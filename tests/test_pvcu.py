import pytest

from oss_compass import confirm_three_nodes, required_fields, validate


def test_envelope_is_deterministic_for_same_timestamp():
    first = validate({"name": "demo"}, subject="demo", rules=[required_fields("name")])
    second = validate({"name": "demo"}, subject="demo", rules=[required_fields("name")])
    assert first.payload_hash == second.payload_hash
    assert first.results[0].passed


def test_three_nodes_accept_with_two_votes():
    envelope = validate({"name": "demo"}, subject="demo", rules=[required_fields("name")])
    receipt = confirm_three_nodes(envelope, {"node-a": True, "node-b": True, "node-c": False})
    assert receipt.accepted
    assert receipt.accepted_nodes == ("node-a", "node-b")


def test_three_nodes_reject_with_one_vote():
    envelope = validate({"name": "demo"}, subject="demo")
    receipt = confirm_three_nodes(envelope, {"node-a": True, "node-b": False, "node-c": False})
    assert not receipt.accepted


def test_requires_exactly_three_nodes():
    envelope = validate({}, subject="demo")
    with pytest.raises(ValueError):
        confirm_three_nodes(envelope, {"node-a": True, "node-b": True})


from oss_compass import audit_change


def _all_levels(value: bool = True):
    return {"integrity": value, "policy": value, "risk": value}


def test_change_audit_is_ten_out_of_ten_when_all_nine_checks_pass():
    audit = audit_change(
        "change-001",
        {"action": "deploy"},
        {"node-a": _all_levels(), "node-b": _all_levels(), "node-c": _all_levels()},
    )
    assert audit.score == 10.0
    assert audit.accepted
    assert audit.approved_nodes == ("node-a", "node-b", "node-c")


def test_change_audit_rejects_when_one_level_fails():
    node_c = _all_levels()
    node_c["risk"] = False
    audit = audit_change(
        "change-002",
        {"action": "delete"},
        {"node-a": _all_levels(), "node-b": _all_levels(), "node-c": node_c},
    )
    assert audit.score < 10.0
    assert not audit.accepted


def test_change_audit_requires_three_nodes_and_three_levels():
    with pytest.raises(ValueError):
        audit_change("change-003", {}, {"node-a": _all_levels(), "node-b": _all_levels()})
    with pytest.raises(ValueError):
        audit_change("change-004", {}, {"node-a": {"integrity": True}, "node-b": _all_levels(), "node-c": _all_levels()})


from oss_compass import audit_code_lines


def _line_matrix(lines, value=True):
    return {node: {number: _all_levels(value) for number in range(1, lines + 1)} for node in ("node-a", "node-b", "node-c")}


def test_every_line_must_reach_ten_out_of_ten():
    audit = audit_code_lines("change-005", ["x = 1", "y = 2"], _line_matrix(2))
    assert audit.score == 10.0
    assert audit.passed
    assert all(line.score == 10.0 for line in audit.lines)


def test_one_failed_line_blocks_the_whole_change():
    matrix = _line_matrix(3)
    matrix["node-b"][2]["risk"] = False
    audit = audit_code_lines("change-006", ["x = 1", "dangerous()", "return x"], matrix)
    assert audit.lines[1].score < 10.0
    assert audit.score < 10.0
    assert not audit.passed
