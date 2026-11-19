"""
CAN Bus Log Decoder & E2E Safety Verifier.

Parses recorded CAN traces (Vector .asc format via python-can), decodes raw
payloads against a DBC definition (via cantools), and verifies:
- End-to-End (E2E) Alive Counter continuity (detecting dropped/duplicated frames)
- End-to-End (E2E) Checksum integrity (Toyota CAN checksum algorithm)
- Physical signal plausibility (detecting unphysical wheel speed spikes)
- AEB event extraction (tracking EMERGENCY_BRAKING activations across the trace)
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import can
import cantools


@dataclass
class SafetyAnomaly:
    """Represents a single communication or physical plausibility anomaly in a CAN trace."""
    timestamp: float
    anomaly_type: str   # "COUNTER_GAP" | "CHECKSUM_MISMATCH" | "PLAUSIBILITY_SPIKE" | "DECODE_ERROR"
    message_name: str
    frame_id: int
    details: str


@dataclass
class TraceAnalysisReport:
    """Aggregated diagnostic summary from analyzing a CAN bus trace."""
    log_path: str
    total_frames: int
    decoded_frames: int
    unknown_frame_ids: List[int] = field(default_factory=list)
    anomalies: List[SafetyAnomaly] = field(default_factory=list)
    aeb_activations: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        """Returns True if zero E2E or physical plausibility anomalies were found."""
        return len(self.anomalies) == 0


class CANLogAnalyzer:
    """Decodes CAN bus traces and validates E2E safety mechanisms."""

    MAX_WHEEL_ACCEL_KMH_PER_S = 120.0  # Physical plausibility threshold (~3.4g spike limit)

    def __init__(self, dbc_path: str | Path) -> None:
        self.dbc_path = Path(dbc_path)
        self.db = cantools.database.load_file(str(self.dbc_path))

    @staticmethod
    def compute_toyota_checksum(frame_id: int, data: bytes) -> int:
        """
        Computes standard Toyota 8-bit CAN checksum:
        (ID_high + ID_low + DLC + sum(data[0..6])) & 0xFF
        """
        dlc = len(data)
        id_high = (frame_id >> 8) & 0xFF
        id_low = frame_id & 0xFF
        payload_sum = sum(data[:-1])
        return (id_high + id_low + dlc + payload_sum) & 0xFF

    def analyze_asc_log(self, log_path: str | Path) -> TraceAnalysisReport:
        """Reads a Vector .asc CAN log file and runs full decoding and safety checks."""
        path = Path(log_path)
        anomalies: List[SafetyAnomaly] = []
        aeb_activations: List[Dict[str, Any]] = []
        unknown_ids: set[int] = set()

        total_frames = 0
        decoded_frames = 0

        last_counter_by_id: Dict[int, int] = {}
        last_wheel_speed: Optional[tuple[float, float]] = None  # (timestamp, speed_kmh)

        with can.ASCReader(str(path)) as reader:
            for msg in reader:
                total_frames += 1
                frame_id = msg.arbitration_id

                try:
                    dbc_msg = self.db.get_message_by_frame_id(frame_id)
                except KeyError:
                    unknown_ids.add(frame_id)
                    continue

                try:
                    decoded = dbc_msg.decode(bytes(msg.data), decode_choices=True)
                    decoded_frames += 1
                except Exception as exc:
                    anomalies.append(
                        SafetyAnomaly(
                            timestamp=msg.timestamp,
                            anomaly_type="DECODE_ERROR",
                            message_name=dbc_msg.name,
                            frame_id=frame_id,
                            details=f"Failed to decode payload: {exc}",
                        )
                    )
                    continue

                # 1. Verify E2E Checksum (if CHECKSUM signal exists in message)
                if "CHECKSUM" in decoded and len(msg.data) == 8:
                    expected_crc = self.compute_toyota_checksum(frame_id, bytes(msg.data))
                    actual_crc = int(decoded["CHECKSUM"])
                    if actual_crc != expected_crc:
                        anomalies.append(
                            SafetyAnomaly(
                                timestamp=msg.timestamp,
                                anomaly_type="CHECKSUM_MISMATCH",
                                message_name=dbc_msg.name,
                                frame_id=frame_id,
                                details=(
                                    f"Expected CRC 0x{expected_crc:02X}, "
                                    f"received 0x{actual_crc:02X}."
                                ),
                            )
                        )

                # 2. Verify E2E Alive Counter continuity
                if "COUNTER" in decoded:
                    counter_sig = dbc_msg.get_signal_by_name("COUNTER")
                    modulus = 1 << counter_sig.length  # 16 for 4-bit, 256 for 8-bit
                    current_cnt = int(decoded["COUNTER"])

                    if frame_id in last_counter_by_id:
                        expected_cnt = (last_counter_by_id[frame_id] + 1) % modulus
                        if current_cnt != expected_cnt:
                            anomalies.append(
                                SafetyAnomaly(
                                    timestamp=msg.timestamp,
                                    anomaly_type="COUNTER_GAP",
                                    message_name=dbc_msg.name,
                                    frame_id=frame_id,
                                    details=(
                                        f"Alive counter discontinuity: expected {expected_cnt}, "
                                        f"got {current_cnt} (mod {modulus})."
                                    ),
                                )
                            )
                    last_counter_by_id[frame_id] = current_cnt

                # 3. Physical plausibility check on WHEEL_SPEEDS
                if dbc_msg.name == "WHEEL_SPEEDS" and "WHEEL_SPEED_FL" in decoded:
                    speed_fl = float(decoded["WHEEL_SPEED_FL"])
                    if last_wheel_speed is not None:
                        prev_t, prev_v = last_wheel_speed
                        dt = msg.timestamp - prev_t
                        if dt > 0:
                            accel_rate = abs(speed_fl - prev_v) / dt
                            if accel_rate > self.MAX_WHEEL_ACCEL_KMH_PER_S:
                                anomalies.append(
                                    SafetyAnomaly(
                                        timestamp=msg.timestamp,
                                        anomaly_type="PLAUSIBILITY_SPIKE",
                                        message_name=dbc_msg.name,
                                        frame_id=frame_id,
                                        details=(
                                            f"Unphysical wheel speed jump: {prev_v:.1f} -> "
                                            f"{speed_fl:.1f} km/h in {dt*1000:.0f} ms."
                                        ),
                                    )
                                )
                    last_wheel_speed = (msg.timestamp, speed_fl)

                # 4. Extract AEB Emergency Braking events
                if dbc_msg.name == "AEB_STATUS":
                    state_val = str(decoded.get("AEB_STATE", ""))
                    if state_val == "EMERGENCY_BRAKING":
                        aeb_activations.append(
                            {
                                "timestamp": round(msg.timestamp, 3),
                                "ttc": round(float(decoded.get("TARGET_TTC", 0.0)), 2),
                                "prefill": bool(decoded.get("PREFILL_ACTIVE", 0)),
                            }
                        )

        return TraceAnalysisReport(
            log_path=str(path),
            total_frames=total_frames,
            decoded_frames=decoded_frames,
            unknown_frame_ids=sorted(unknown_ids),
            anomalies=anomalies,
            aeb_activations=aeb_activations,
        )


