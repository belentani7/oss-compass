import pytest

from oss_compass import NodeConfig, NodeServer, confirm_over_network, required_fields, validate


def start_nodes(reject_node=None):
    servers = []
    configs = []
    for node_id in ("node-a", "node-b", "node-c"):
        def validator(envelope, node_id=node_id):
            if node_id == reject_node:
                return False, "fixture rejection"
            return True, "fixture accepted"
        server = NodeServer(NodeConfig(node_id, "127.0.0.1", 0, f"secret-{node_id}"), validator)
        configs.append(server.start())
        servers.append(server)
    return servers, tuple(configs)


def envelope():
    return validate({"name": "network-change"}, subject="network-change", rules=[required_fields("name")])


def test_three_real_http_nodes_accept_with_quorum():
    servers, configs = start_nodes()
    try:
        receipt = confirm_over_network(envelope(), configs)
        assert receipt.accepted
        assert receipt.accepted_nodes == ("node-a", "node-b", "node-c")
        assert all(item.signature for item in receipt.confirmations)
    finally:
        for server in servers:
            server.stop()


def test_one_rejecting_node_still_allows_two_of_three():
    servers, configs = start_nodes(reject_node="node-c")
    try:
        receipt = confirm_over_network(envelope(), configs)
        assert receipt.accepted
        assert receipt.accepted_nodes == ("node-a", "node-b")
        assert receipt.confirmations[2].reason == "fixture rejection"
    finally:
        for server in servers:
            server.stop()


def test_unavailable_node_is_recorded_and_cannot_break_quorum():
    servers, configs = start_nodes()
    try:
        servers[2].stop()
        receipt = confirm_over_network(envelope(), configs, timeout=0.2)
        assert receipt.accepted
        assert receipt.confirmations[2].accepted is False
        assert "node unavailable" in receipt.confirmations[2].reason
    finally:
        for server in servers[:2]:
            server.stop()


def test_wrong_secret_rejects_one_node_but_does_not_forge_its_vote():
    servers, configs = start_nodes()
    try:
        tampered = configs[:2] + (NodeConfig("node-c", configs[2].host, configs[2].port, "wrong-secret"),)
        receipt = confirm_over_network(envelope(), tampered)
        assert receipt.accepted
        assert receipt.confirmations[2].accepted is False
        assert "node unavailable" in receipt.confirmations[2].reason
    finally:
        for server in servers:
            server.stop()


def test_network_requires_exactly_three_named_nodes():
    with pytest.raises(ValueError):
        confirm_over_network(envelope(), (NodeConfig("node-a", "127.0.0.1", 1, "a"),))


def test_node_rejects_replayed_nonce():
    import time
    from oss_compass.network import sign

    server = NodeServer(NodeConfig("node-a", "127.0.0.1", 0, "secret-node-a"))
    try:
        request_body = {
            "node_id": "node-a",
            "envelope": envelope().to_dict(),
            "nonce": "fixed-fixture-nonce",
            "timestamp": time.time(),
        }
        request_body["signature"] = sign("secret-node-a", request_body)
        assert server._handle(request_body)["accepted"] is True
        with pytest.raises(ValueError, match="replayed"):
            server._handle(request_body)
    finally:
        server.stop()
