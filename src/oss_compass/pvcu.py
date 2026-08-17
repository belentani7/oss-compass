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


AUDIT_LEVELS = ("integrity", "policy", "risk")


@dataclass(frozen=True)
class LevelAudit:
    level: str
    passed: bool
    score: int
    evidence: str = ""


@dataclass(frozen=True)
class NodeAudit:
    node_id: str
    levels: tuple[LevelAudit, ...]

    @property
    def passed(self) -> bool:
        return len(self.levels) == 3 and all(level.passed for level in self.levels)

    @property
    def score(self) -> float:
        return round(sum(level.score for level in self.levels) / 3, 2)


@dataclass(frozen=True)
class ChangeAudit:
    change_id: str
    change_hash: str
    nodes: tuple[NodeAudit, ...]
    quorum: int = 2

    @property
    def approved_nodes(self) -> tuple[str, ...]:
        return tuple(node.node_id for node in self.nodes if node.passed)

    @property
    def accepted(self) -> bool:
        return len(self.approved_nodes) >= self.quorum and self.score == 10.0

    @property
    def score(self) -> float:
        """Global score: nine checks (3 nodes x 3 levels), normalized to 0-10."""
        checks = [level.passed for node in self.nodes for level in node.levels]
        return round(sum(checks) / 9 * 10, 2) if len(checks) == 9 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_id": self.change_id,
            "change_hash": self.change_hash,
            "quorum": self.quorum,
            "score": self.score,
            "accepted": self.accepted,
            "approved_nodes": list(self.approved_nodes),
            "nodes": [
                {"node_id": node.node_id, "score": node.score, "passed": node.passed,
                 "levels": [asdict(level) for level in node.levels]}
                for node in self.nodes
            ],
        }


def audit_change(change_id: str, change: Any, node_levels: dict[str, dict[str, bool]], *, quorum: int = 2) -> ChangeAudit:
    """Audit one change across exactly 3 nodes and exactly 3 levels.

    A change is 10/10 only when all nine node-level checks pass. It is accepted
    only when the configured quorum (2 by default) also approves all levels.
    """
    if len(node_levels) != 3:
        raise ValueError("exactly three nodes are required per change")
    if set(node_levels) != {"node-a", "node-b", "node-c"}:
        raise ValueError("nodes must be node-a, node-b and node-c")
    if quorum != 2:
        raise ValueError("the 3-node audit requires a 2-of-3 quorum")
    audits = []
    change_hash = sha256_payload({"change_id": change_id, "change": change})
    for node_id in sorted(node_levels):
        levels = node_levels[node_id]
        if set(levels) != set(AUDIT_LEVELS):
            raise ValueError("every node must report integrity, policy and risk")
        audits.append(NodeAudit(node_id, tuple(
            LevelAudit(level, bool(levels[level]), 10 if levels[level] else 0,
                       "verified" if levels[level] else "failed")
            for level in AUDIT_LEVELS
        )))
    return ChangeAudit(change_id, change_hash, tuple(audits), quorum)


@dataclass(frozen=True)
class LineAudit:
    line_number: int
    content_hash: str
    node_audits: tuple[NodeAudit, ...]

    @property
    def score(self) -> float:
        checks = [level.passed for node in self.node_audits for level in node.levels]
        return round(sum(checks) / 9 * 10, 2) if len(checks) == 9 else 0.0

    @property
    def passed(self) -> bool:
        return self.score == 10.0 and all(node.passed for node in self.node_audits)


@dataclass(frozen=True)
class StrictCodeAudit:
    change_id: str
    lines: tuple[LineAudit, ...]

    @property
    def score(self) -> float:
        if not self.lines:
            return 0.0
        return round(sum(line.score for line in self.lines) / len(self.lines), 2)

    @property
    def passed(self) -> bool:
        """Hard gate: one failed line rejects the complete code change."""
        return bool(self.lines) and self.score == 10.0 and all(line.passed for line in self.lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_id": self.change_id,
            "score": self.score,
            "passed": self.passed,
            "line_count": len(self.lines),
            "lines": [
                {
                    "line_number": line.line_number,
                    "content_hash": line.content_hash,
                    "score": line.score,
                    "passed": line.passed,
                    "nodes": [
                        {"node_id": node.node_id, "score": node.score, "passed": node.passed,
                         "levels": [asdict(level) for level in node.levels]}
                        for node in line.node_audits
                    ],
                }
                for line in self.lines
            ],
        }


def audit_code_lines(change_id: str, lines: Iterable[str], node_levels: dict[str, dict[int, dict[str, bool]]]) -> StrictCodeAudit:
    """Apply a strict 10/10 gate to every changed line.

    `node_levels` maps each of the three nodes to line number -> three booleans.
    All three nodes and all three levels must pass for every line; otherwise the
    complete change is rejected. This is intentionally stricter than quorum.
    """
    if set(node_levels) != {"node-a", "node-b", "node-c"}:
        raise ValueError("exactly node-a, node-b and node-c are required")
    materialized = tuple(lines)
    if not materialized:
        raise ValueError("at least one changed line is required")
    line_audits = []
    for line_number, content in enumerate(materialized, start=1):
        audits = []
        for node_id in ("node-a", "node-b", "node-c"):
            levels = node_levels[node_id].get(line_number)
            if levels is None or set(levels) != set(AUDIT_LEVELS):
                raise ValueError(f"missing three-level audit for line {line_number} on {node_id}")
            audits.append(NodeAudit(node_id, tuple(
                LevelAudit(level, bool(levels[level]), 10 if levels[level] else 0,
                           "verified" if levels[level] else "failed")
                for level in AUDIT_LEVELS
            )))
        line_audits.append(LineAudit(line_number, sha256_payload(content), tuple(audits)))
    return StrictCodeAudit(change_id, tuple(line_audits))
