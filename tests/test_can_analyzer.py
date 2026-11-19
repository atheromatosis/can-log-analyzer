"""
Verification Suite for DBC Static Auditor & CAN Bus Log Analyzer.

Covers:
- REQ-DBC-01: Valid DBC structure & E2E coverage verification
- REQ-DBC-02: Motorola (Big-Endian) & Intel (Little-Endian) bit-overlap detection
- REQ-DBC-03: Frame DLC boundary overflow detection (> 64 bits)
- REQ-LOG-01: End-to-End (E2E) Alive Counter discontinuity detection
- REQ-LOG-02: End-to-End (E2E) Toyota Checksum mismatch detection
- REQ-LOG-03: Physical plausibility verification (wheel speed spike detection)
- REQ-LOG-04: AEB_STATUS event extraction & state decoding
"""

from pathlib import Path
import pytest
from src.dbc_auditor import DBCAuditor
from src.log_analyzer import CANLogAnalyzer

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DBC_PATH = PROJECT_ROOT / "data" / "toyota_prius.dbc"
LOG_PATH = PROJECT_ROOT / "data" / "sample_drive.asc"


class TestDBCAuditor:
    """Static verification tests for Vector DBC database definitions."""

    def test_valid_vehicle_dbc_passes_audit(self) -> None:
        """REQ-DBC-01: Production DBC passes audit with zero critical errors and detects E2E messages."""
        auditor = DBCAuditor(DBC_PATH)
        report = auditor.run_audit()

        assert report.is_valid is True
        assert report.total_messages == 4
        assert report.total_signals == 21
        assert set(report.e2e_protected_messages) == {
            "STEER_ANGLE_SENSOR",
            "ACC_CONTROL",
            "AEB_STATUS",
        }

    def test_detects_motorola_bit_overlap(self, tmp_path: Path) -> None:
        """REQ-DBC-02: Detects overlapping Motorola Big-Endian signals inside a single frame."""
        corrupt_dbc = tmp_path / "overlap.dbc"
        corrupt_dbc.write_text(
            'VERSION ""\n'
            "NS_ :\nBS_:\nBU_: ECU_A\n"
            "BO_ 100 TEST_OVERLAP: 8 ECU_A\n"
            ' SG_ SIG_A : 7|12@0+ (1,0) [0|4095] "km/h" Vector__XXX\n'
            ' SG_ SIG_B : 15|8@0+ (1,0) [0|255] "km/h" Vector__XXX\n',
            encoding="utf-8",
        )

        auditor = DBCAuditor(corrupt_dbc)
        report = auditor.run_audit()

        assert report.is_valid is False
        assert any("Bit collision" in f.description for f in report.findings)

    def test_detects_dlc_boundary_overflow(self, tmp_path: Path) -> None:
        """REQ-DBC-03: Detects signal bit layout exceeding the declared frame DLC size."""
        overflow_dbc = tmp_path / "overflow.dbc"
        overflow_dbc.write_text(
            'VERSION ""\n'
            "NS_ :\nBS_:\nBU_: ECU_A\n"
            "BO_ 200 TEST_OVERFLOW: 4 ECU_A\n"
            ' SG_ WIDE_SIG : 24|16@1+ (1,0) [0|65535] "rpm" Vector__XXX\n',
            encoding="utf-8",
        )

        auditor = DBCAuditor(overflow_dbc)
        report = auditor.run_audit()

        assert report.is_valid is False
        assert any("exceeds frame DLC boundary" in f.description for f in report.findings)


class TestCANLogAnalyzer:
    """Closed-loop trace decoding and E2E safety verification tests."""

    @pytest.fixture(scope="class")
    def trace_report(self):
        analyzer = CANLogAnalyzer(DBC_PATH)
        return analyzer.analyze_asc_log(LOG_PATH)

    def test_decodes_all_trace_frames(self, trace_report) -> None:
        """Verifies all 80 recorded frames in sample_drive.asc decode cleanly against DBC."""
        assert trace_report.total_frames == 80
        assert trace_report.decoded_frames == 80
        assert trace_report.unknown_frame_ids == []

    def test_detects_alive_counter_gap(self, trace_report) -> None:
        """REQ-LOG-01: Identifies dropped frame via Alive Counter discontinuity."""
        counter_anomalies = [
            a for a in trace_report.anomalies if a.anomaly_type == "COUNTER_GAP"
        ]
        assert len(counter_anomalies) == 2
        assert counter_anomalies[0].message_name == "AEB_STATUS"

    def test_detects_checksum_mismatch(self, trace_report) -> None:
        """REQ-LOG-02: Identifies corrupted payload via Toyota 8-bit checksum mismatch."""
        crc_anomalies = [
            a for a in trace_report.anomalies if a.anomaly_type == "CHECKSUM_MISMATCH"
        ]
        assert len(crc_anomalies) == 1
        assert crc_anomalies[0].message_name == "AEB_STATUS"

    def test_detects_wheel_speed_plausibility_spike(self, trace_report) -> None:
        """REQ-LOG-03: Flags unphysical wheel speed jump (50 -> 215 km/h in 50 ms)."""
        spike_anomalies = [
            a for a in trace_report.anomalies if a.anomaly_type == "PLAUSIBILITY_SPIKE"
        ]
        assert len(spike_anomalies) == 2
        assert spike_anomalies[0].message_name == "WHEEL_SPEEDS"

    def test_extracts_aeb_emergency_braking_events(self, trace_report) -> None:
        """REQ-LOG-04: Extracts EMERGENCY_BRAKING state transitions and pre-fill status."""
        assert len(trace_report.aeb_activations) > 0
        first_event = trace_report.aeb_activations[0]
        assert first_event["ttc"] <= 1.5
        assert first_event["prefill"] is True
