from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Iterable


@dataclass(frozen=True)
class ValidationResult:
    code: str
    passed: bool
    message: str
    sphere: str


@dataclass(frozen=True)
class ValidationEnvelope:
    subject: str
    profile: str
    payload_hash: str
    results: tuple[ValidationResult, ...]
    created_at: float
    envelope_id: str = field(init=False)

    def __post_init__(self) -> None:
        canonical = json.dumps({
            "subject": self.subject,
            "profile": self.profile,
            "payload_hash": self.payload_hash,
            "results": [asdict(item) for item in self.results],
            "created_at": self.created_at,
        }, sort_keys=True, separators=(",", ":"))
        object.__setattr__(self, "envelope_id", hashlib.sha256(canonical.encode()).hexdigest())

    @property
    def passed(self) -> bool:
        return all(item.passed for item in self.results)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["results"] = [asdict(item) for item in self.results]
        return data


@dataclass(frozen=True)
class NodeConfirmation:
    node_id: str
    envelope_id: str
    accepted: bool
    signature: str
    reason: str = ""


@dataclass(frozen=True)
class ConfirmationReceipt:
    envelope_id: str
    confirmations: tuple[NodeConfirmation, ...]
    quorum: int = 2

    @property
    def accepted(self) -> bool:
        return sum(item.accepted for item in self.confirmations) >= self.quorum

    @property
    def accepted_nodes(self) -> tuple[str, ...]:
        return tuple(item.node_id for item in self.confirmations if item.accepted)


Rule = Callable[[Any], ValidationResult]


def sha256_payload(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def validate(payload: Any, *, subject: str, profile: str = "default", rules: Iterable[Rule] = ()) -> ValidationEnvelope:
    results = tuple(rule(payload) for rule in rules)
    return ValidationEnvelope(subject, profile, sha256_payload(payload), results, time.time())


def required_fields(*fields: str) -> Rule:
    def check(payload: Any) -> ValidationResult:
        passed = isinstance(payload, dict) and all(field in payload for field in fields)
        missing = [field for field in fields if not isinstance(payload, dict) or field not in payload]
        return ValidationResult("PVC-101" if passed else "PVC-201", passed, "required fields present" if passed else f"missing fields: {', '.join(missing)}", "1")
    return check


def confirm_three_nodes(envelope: ValidationEnvelope, nodes: dict[str, bool], *, quorum: int = 2) -> ConfirmationReceipt:
    """Confirm an envelope with independent node decisions; defaults to a 2-of-3 quorum."""
    if len(nodes) != 3:
        raise ValueError("exactly three nodes are required")
    if not 1 <= quorum <= 3:
        raise ValueError("quorum must be between 1 and 3")
    confirmations = tuple(
        NodeConfirmation(node_id, envelope.envelope_id, accepted, hashlib.sha256(f"{node_id}:{envelope.envelope_id}:{accepted}".encode()).hexdigest(), "" if accepted else "node rejected envelope")
        for node_id, accepted in sorted(nodes.items())
    )
    return ConfirmationReceipt(envelope.envelope_id, confirmations, quorum)
