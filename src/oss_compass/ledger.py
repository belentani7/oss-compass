"""Append-only, locally verifiable PVC-U decision ledger.

The ledger detects altered, reordered, removed or injected entries after a
trusted head hash has been recorded elsewhere. It is not a consensus database
or a substitute for durable remote storage.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from .crypto import canonical_json
from .pvcu import ConfirmationReceipt, ValidationEnvelope

GENESIS_HASH = "0" * 64
MAX_LEDGER_LINE_BYTES = 1_048_576


def _receipt_data(receipt: ConfirmationReceipt) -> dict[str, Any]:
    return {
        "envelope_id": receipt.envelope_id,
        "quorum": receipt.quorum,
        "accepted": receipt.accepted,
        "accepted_nodes": list(receipt.accepted_nodes),
        "confirmations": [asdict(item) for item in receipt.confirmations],
    }


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class LedgerEntry:
    sequence: int
    created_at: float
    envelope_id: str
    envelope_hash: str
    receipt_hash: str
    accepted: bool
    previous_hash: str
    entry_hash: str

    def unsigned(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "created_at": self.created_at,
            "envelope_id": self.envelope_id,
            "envelope_hash": self.envelope_hash,
            "receipt_hash": self.receipt_hash,
            "accepted": self.accepted,
            "previous_hash": self.previous_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LedgerVerification:
    valid: bool
    entry_count: int
    head_hash: str
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"errors": list(self.errors)}


class ValidationLedger:
    """An in-memory hash chain that can be exported as newline-delimited JSON."""

    def __init__(self, entries: Iterable[LedgerEntry] = ()) -> None:
        self._entries = list(entries)

    @property
    def entries(self) -> tuple[LedgerEntry, ...]:
        return tuple(self._entries)

    @property
    def head_hash(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS_HASH

    def append(self, envelope: ValidationEnvelope, receipt: ConfirmationReceipt, *, created_at: float | None = None) -> LedgerEntry:
        if envelope.envelope_id != receipt.envelope_id:
            raise ValueError("receipt envelope_id does not match the envelope")
        verification = self.verify()
        if not verification.valid:
            raise ValueError("cannot append to an invalid ledger")
        unsigned = {
            "sequence": len(self._entries) + 1,
            "created_at": time.time() if created_at is None else created_at,
            "envelope_id": envelope.envelope_id,
            "envelope_hash": _sha256(envelope.to_dict()),
            "receipt_hash": _sha256(_receipt_data(receipt)),
            "accepted": receipt.accepted,
            "previous_hash": self.head_hash,
        }
        entry = LedgerEntry(**unsigned, entry_hash=_sha256(unsigned))
        self._entries.append(entry)
        return entry

    def verify(self, *, expected_head_hash: str | None = None) -> LedgerVerification:
        errors: list[str] = []
        previous_hash = GENESIS_HASH
        for expected_sequence, entry in enumerate(self._entries, start=1):
            if entry.sequence != expected_sequence:
                errors.append(f"sequence mismatch at entry {expected_sequence}")
            if entry.previous_hash != previous_hash:
                errors.append(f"previous hash mismatch at entry {expected_sequence}")
            if entry.entry_hash != _sha256(entry.unsigned()):
                errors.append(f"entry hash mismatch at entry {expected_sequence}")
            previous_hash = entry.entry_hash
        if expected_head_hash is not None and previous_hash != expected_head_hash:
            errors.append("head hash does not match expected value")
        return LedgerVerification(not errors, len(self._entries), previous_hash, tuple(errors))

    def to_ndjson(self) -> str:
        return "".join(json.dumps(entry.to_dict(), sort_keys=True, separators=(",", ":")) + "\n" for entry in self._entries)

    def append_to(self, path: Path) -> None:
        verification = self.verify()
        if not verification.valid:
            raise ValueError("cannot export an invalid ledger")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            for entry in self._entries:
                handle.write(json.dumps(entry.to_dict(), sort_keys=True, separators=(",", ":")) + "\n")

    @classmethod
    def from_ndjson(cls, path: Path) -> "ValidationLedger":
        entries: list[LedgerEntry] = []
        with path.open("rb") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                if len(raw_line) > MAX_LEDGER_LINE_BYTES:
                    raise ValueError(f"ledger line {line_number} exceeds {MAX_LEDGER_LINE_BYTES} bytes")
                if not raw_line.strip():
                    continue
                try:
                    value = json.loads(raw_line)
                    entries.append(LedgerEntry(**value))
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ValueError(f"invalid ledger entry on line {line_number}") from exc
        return cls(entries)
