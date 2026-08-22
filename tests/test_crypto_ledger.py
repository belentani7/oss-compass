from __future__ import annotations

import json

import pytest

from oss_compass import (
    ConfirmationReceipt,
    NodeConfirmation,
    ValidationLedger,
    generate_keypair,
    key_fingerprint,
    sign_payload,
    validate,
    verify_payload,
)
from oss_compass.ledger import GENESIS_HASH
from oss_compass.pvcu import required_fields


def envelope_and_receipt() -> tuple[object, ConfirmationReceipt]:
    envelope = validate({"id": "change-1"}, subject="change-1", rules=[required_fields("id")])
    receipt = ConfirmationReceipt(
        envelope.envelope_id,
        (
            NodeConfirmation("node-a", envelope.envelope_id, True, "signature-a", "verified"),
            NodeConfirmation("node-b", envelope.envelope_id, True, "signature-b", "verified"),
            NodeConfirmation("node-c", envelope.envelope_id, False, "signature-c", "rejected"),
        ),
    )
    return envelope, receipt


def test_ed25519_signature_is_bound_to_canonical_payload() -> None:
    private_key, public_key = generate_keypair()
    payload = {"subject": "alpha", "sequence": 1}
    signature = sign_payload(private_key, payload)

    assert verify_payload(public_key, payload, signature)
    assert not verify_payload(public_key, {"subject": "alpha", "sequence": 2}, signature)
    assert len(key_fingerprint(public_key)) == 16


def test_ledger_detects_tampering_and_reordering(tmp_path) -> None:
    envelope, receipt = envelope_and_receipt()
    ledger = ValidationLedger()
    first = ledger.append(envelope, receipt, created_at=1.0)
    second = ledger.append(envelope, receipt, created_at=2.0)

    assert ledger.verify(expected_head_hash=second.entry_hash).valid
    assert first.previous_hash == GENESIS_HASH

    path = tmp_path / "ledger.ndjson"
    path.write_text(ledger.to_ndjson(), encoding="utf-8")
    loaded = ValidationLedger.from_ndjson(path)
    assert loaded.verify(expected_head_hash=second.entry_hash).valid

    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows.reverse()
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    assert not ValidationLedger.from_ndjson(path).verify().valid


def test_ledger_rejects_invalid_entry_format(tmp_path) -> None:
    path = tmp_path / "invalid.ndjson"
    path.write_text('{"sequence":"not-an-int"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="invalid ledger entry"):
        ValidationLedger.from_ndjson(path)
