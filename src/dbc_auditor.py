"""
Static DBC Database Auditor for Automotive CAN Networks.

Validates DBC definitions against common integration defects:
- Signal bit-layout overlaps (Motorola Big-Endian & Intel Little-Endian)
- Frame payload boundary overflows (> DLC * 8 bits)
- Missing physical units on non-flag/non-E2E signals
- E2E protection coverage (presence of COUNTER and CHECKSUM signals)
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set
import cantools


@dataclass
class AuditFinding:
    """Represents a single static validation issue or warning in a DBC file."""
    severity: str       # "ERROR" | "WARNING"
    message_name: str
    frame_id: int
    description: str


@dataclass
class AuditReport:
    """Aggregated result of a DBC file static audit."""
    dbc_path: str
    total_messages: int
    total_signals: int
    e2e_protected_messages: List[str] = field(default_factory=list)
    findings: List[AuditFinding] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        """Returns True if no critical ERROR findings were detected."""
        return not any(f.severity == "ERROR" for f in self.findings)


class DBCAuditor:
    """Static analyzer for Vector CAN Database (.dbc) files."""

    E2E_EXEMPT_NAMES = {"COUNTER", "CHECKSUM", "CRC", "ALIVE"}

    def __init__(self, dbc_path: str | Path) -> None:
        self.dbc_path = Path(dbc_path)
        self.db = cantools.database.load_file(str(self.dbc_path), strict=False)

    @staticmethod
    def _compute_signal_bit_indices(signal: cantools.database.can.Signal) -> Set[int]:
        """
        Calculates the exact set of bit positions [0..63] occupied by a signal,
        supporting both Intel (little_endian) and Motorola (big_endian) layouts.
        """
        occupied_bits: Set[int] = set()
        bit_pos = signal.start

        for _ in range(signal.length):
            occupied_bits.add(bit_pos)
            if signal.byte_order == "little_endian":
                bit_pos += 1
            else:
                # Motorola / Big-Endian bit numbering within 8-bit bytes
                if bit_pos % 8 == 0:
                    bit_pos += 15
                else:
                    bit_pos -= 1

        return occupied_bits

    def run_audit(self) -> AuditReport:
        """Executes all static checks across every message in the DBC database."""
        findings: List[AuditFinding] = []
        e2e_messages: List[str] = []
        total_signals = 0

        for msg in self.db.messages:
            total_signals += len(msg.signals)
            max_bits = msg.length * 8
            bit_owner_map: Dict[int, str] = {}
            signal_names = {sig.name.upper() for sig in msg.signals}

            # 1. Check E2E Protection (COUNTER + CHECKSUM presence)
            has_counter = any("COUNTER" in name or "ALIVE" in name for name in signal_names)
            has_checksum = any("CHECKSUM" in name or "CRC" in name for name in signal_names)
            if has_counter and has_checksum:
                e2e_messages.append(msg.name)

            # 2. Check bit layout, overlaps, DLC bounds, and metadata
            for sig in msg.signals:
                occupied = self._compute_signal_bit_indices(sig)

                # Out-of-bounds check
                if any(b < 0 or b >= max_bits for b in occupied):
                    findings.append(
                        AuditFinding(
                            severity="ERROR",
                            message_name=msg.name,
                            frame_id=msg.frame_id,
                            description=(
                                f"Signal '{sig.name}' exceeds frame DLC boundary "
                                f"({msg.length} bytes / {max_bits} bits)."
                            ),
                        )
                    )

                # Bit-overlap collision check
                for bit in occupied:
                    if bit in bit_owner_map:
                        other_sig = bit_owner_map[bit]
                        findings.append(
                            AuditFinding(
                                severity="ERROR",
                                message_name=msg.name,
                                frame_id=msg.frame_id,
                                description=(
                                    f"Bit collision at bit {bit} between "
                                    f"'{other_sig}' and '{sig.name}'."
                                ),
                            )
                        )
                    else:
                        bit_owner_map[bit] = sig.name

                # Missing physical unit warning for multi-bit non-E2E signals
                is_e2e_or_flag = (
                    sig.length == 1
                    or sig.choices is not None
                    or any(tag in sig.name.upper() for tag in self.E2E_EXEMPT_NAMES)
                )
                if not is_e2e_or_flag and not sig.unit:
                    findings.append(
                        AuditFinding(
                            severity="WARNING",
                            message_name=msg.name,
                            frame_id=msg.frame_id,
                            description=f"Signal '{sig.name}' has no physical unit defined.",
                        )
                    )

        return AuditReport(
            dbc_path=str(self.dbc_path),
            total_messages=len(self.db.messages),
            total_signals=total_signals,
            e2e_protected_messages=e2e_messages,
            findings=findings,
        )
