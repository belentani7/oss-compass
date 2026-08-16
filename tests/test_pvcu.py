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
