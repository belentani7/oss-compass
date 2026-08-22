from __future__ import annotations

import time

import pytest

from oss_compass import (
    CoordinatorIdentity,
    Ed25519NodeServer,
    SignedNodeConfig,
    confirm_over_ed25519_network,
    generate_keypair,
    sign_payload,
    validate,
)
from oss_compass.pvcu import required_fields
from oss_compass.secure_network import PROTOCOL_VERSION


def test_ed25519_network_reaches_quorum_and_reports_rejection() -> None:
    coordinator_private, coordinator_public = generate_keypair()
    coordinator = CoordinatorIdentity("coordinator-main", coordinator_private)
    servers = []
    try:
        for node_id, accepted in (("node-a", True), ("node-b", True), ("node-c", False)):
            node_private, _node_public = generate_keypair()
            server = Ed25519NodeServer(
                SignedNodeConfig(node_id, "127.0.0.1", 0, node_private, {coordinator.coordinator_id: coordinator_public}),
                validator=lambda _envelope, approved=accepted: (approved, "approved" if approved else "risk policy rejected"),
            )
            server.start()
            servers.append(server)
        envelope = validate({"id": "change-1"}, subject="change-1", rules=[required_fields("id")])
        receipt = confirm_over_ed25519_network(envelope, coordinator, tuple(server.endpoint() for server in servers))

        assert receipt.accepted
        assert receipt.accepted_nodes == ("node-a", "node-b")
        assert "risk policy rejected" in receipt.confirmations[2].reason
    finally:
        for server in servers:
            server.stop()


def test_untrusted_coordinator_is_rejected_without_confirming() -> None:
    trusted_private, trusted_public = generate_keypair()
    untrusted_private, _untrusted_public = generate_keypair()
    servers = []
    try:
        for node_id in ("node-a", "node-b", "node-c"):
            server_private, _server_public = generate_keypair()
            server = Ed25519NodeServer(
                SignedNodeConfig(node_id, "127.0.0.1", 0, server_private, {"trusted": trusted_public}),
            )
            server.start()
            servers.append(server)
        envelope = validate({"id": "change-1"}, subject="change-1", rules=[required_fields("id")])
        receipt = confirm_over_ed25519_network(
            envelope,
            CoordinatorIdentity("untrusted", untrusted_private),
            tuple(server.endpoint() for server in servers),
        )
        assert not receipt.accepted
        assert all("node unavailable" in item.reason for item in receipt.confirmations)
    finally:
        for server in servers:
            server.stop()


def test_node_rejects_a_replayed_signed_request() -> None:
    coordinator_private, coordinator_public = generate_keypair()
    node_private, _node_public = generate_keypair()
    server = Ed25519NodeServer(
        SignedNodeConfig("node-a", "127.0.0.1", 0, node_private, {"coordinator": coordinator_public}),
    )
    try:
        envelope = validate({"id": "change-1"}, subject="change-1", rules=[required_fields("id")]).to_dict()
        unsigned = {
            "protocol": PROTOCOL_VERSION,
            "node_id": "node-a",
            "coordinator_id": "coordinator",
            "envelope": envelope,
            "nonce": "replay-me-once",
            "timestamp": time.time(),
        }
        request_body = dict(unsigned, signature=sign_payload(coordinator_private, unsigned))
        assert server._handle(request_body)["accepted"]
        with pytest.raises(ValueError, match="replayed confirmation request"):
            server._handle(request_body)
    finally:
        server.stop()


def test_node_request_size_limit_fails_closed() -> None:
    coordinator_private, coordinator_public = generate_keypair()
    coordinator = CoordinatorIdentity("coordinator", coordinator_private)
    servers = []
    try:
        for node_id in ("node-a", "node-b", "node-c"):
            node_private, _node_public = generate_keypair()
            server = Ed25519NodeServer(
                SignedNodeConfig(node_id, "127.0.0.1", 0, node_private, {"coordinator": coordinator_public}),
                max_request_bytes=1,
            )
            server.start()
            servers.append(server)
        envelope = validate({"id": "change-1"}, subject="change-1", rules=[required_fields("id")])
        receipt = confirm_over_ed25519_network(envelope, coordinator, tuple(server.endpoint() for server in servers))
        assert not receipt.accepted
        assert all("node unavailable" in item.reason for item in receipt.confirmations)
    finally:
        for server in servers:
            server.stop()
