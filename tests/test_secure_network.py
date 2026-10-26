from __future__ import annotations

import http.client
import json
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


def test_nonce_capacity_does_not_reopen_replay_window() -> None:
    """Capacity exhaustion must reject new requests, never forget live nonces."""
    coordinator_private, coordinator_public = generate_keypair()
    node_private, _node_public = generate_keypair()
    server = Ed25519NodeServer(
        SignedNodeConfig("node-a", "127.0.0.1", 0, node_private, {"coordinator": coordinator_public}),
        max_seen_nonces=2,
    )
    try:
        envelope = validate({"id": "change-1"}, subject="change-1", rules=[required_fields("id")]).to_dict()

        def signed_request(nonce: str, timestamp: float) -> dict:
            unsigned = {
                "protocol": PROTOCOL_VERSION,
                "node_id": "node-a",
                "coordinator_id": "coordinator",
                "envelope": envelope,
                "nonce": nonce,
                "timestamp": timestamp,
            }
            return dict(unsigned, signature=sign_payload(coordinator_private, unsigned))

        now = time.time()
        first = signed_request("nonce-one", now - 30)
        second = signed_request("nonce-two", now)
        third = signed_request("nonce-three", now)
        assert server._handle(first)["accepted"]
        assert server._handle(second)["accepted"]
        # A third signed request must fail closed instead of evicting nonce-one.
        with pytest.raises(ValueError, match="capacity"):
            server._handle(third)
        assert len(server._seen_nonces) == 2
        with pytest.raises(ValueError, match="replayed"):
            server._handle(first)

        # Expired evidence may be reclaimed without losing the other nonce.
        server._seen_nonces["nonce-one"] = time.time() - server.max_clock_skew - 1
        assert server._handle(third)["accepted"]
        assert "nonce-one" not in server._seen_nonces
        assert "nonce-two" in server._seen_nonces
        assert len(server._seen_nonces) == 2
    finally:
        server.stop()


@pytest.mark.parametrize("bad_timestamp", [float("nan"), float("inf"), float("-inf")])
def test_signed_nonfinite_timestamp_is_rejected_before_nonce_cache(bad_timestamp: float) -> None:
    coordinator_private, coordinator_public = generate_keypair()
    node_private, _ = generate_keypair()
    server = Ed25519NodeServer(SignedNodeConfig(
        "node-a", "127.0.0.1", 0, node_private, {"coordinator": coordinator_public},
    ))
    try:
        unsigned = {
            "protocol": PROTOCOL_VERSION,
            "node_id": "node-a",
            "coordinator_id": "coordinator",
            "envelope": {"envelope_id": "e", "payload_hash": "h", "results": [{"passed": True}]},
            "nonce": "nonfinite-timestamp",
            "timestamp": bad_timestamp,
        }
        with pytest.raises(ValueError, match="stale"):
            server._handle(dict(unsigned, signature=sign_payload(coordinator_private, unsigned)))
        assert not server._seen_nonces
    finally:
        server.stop()


def test_malformed_authenticated_v2_fields_do_not_consume_replay_memory() -> None:
    coordinator_private, coordinator_public = generate_keypair()
    node_private, _ = generate_keypair()
    server = Ed25519NodeServer(SignedNodeConfig(
        "node-a", "127.0.0.1", 0, node_private, {"coordinator": coordinator_public},
    ))
    try:
        base = {
            "protocol": PROTOCOL_VERSION,
            "node_id": "node-a",
            "coordinator_id": "coordinator",
            "envelope": {"envelope_id": "e", "payload_hash": "h", "results": [{"passed": True}]},
            "nonce": "malformed-field-nonce",
            "timestamp": time.time(),
        }
        for override in (
            {"coordinator_id": ["coordinator"]},
            {"nonce": ["malformed-field-nonce"]},
            {"envelope": []},
            {"timestamp": "not-a-timestamp"},
        ):
            unsigned = dict(base, **override)
            with pytest.raises(ValueError):
                server._handle(dict(unsigned, signature=sign_payload(coordinator_private, unsigned)))
        with pytest.raises(ValueError, match="fields"):
            server._handle(None)
        signed = dict(base, signature=sign_payload(coordinator_private, base))
        with pytest.raises(ValueError, match="signature"):
            server._handle(dict(signed, signature=None))
        assert not server._seen_nonces
    finally:
        server.stop()


def test_v2_http_malformed_json_returns_400_without_leaking_error_details() -> None:
    _, coordinator_public = generate_keypair()
    node_private, _ = generate_keypair()
    server = Ed25519NodeServer(SignedNodeConfig(
        "node-a", "127.0.0.1", 0, node_private, {"coordinator": coordinator_public},
    ))
    server.start()
    try:
        untrusted = {
            "protocol": PROTOCOL_VERSION,
            "node_id": "node-a",
            "coordinator_id": "untrusted",
            "envelope": {},
            "nonce": "http-malformed-nonce",
            "timestamp": time.time(),
            "signature": "invalid",
        }
        for raw in (b"null", json.dumps(untrusted).encode("utf-8")):
            client = http.client.HTTPConnection(server.config.host, server.config.port, timeout=3)
            try:
                client.request("POST", "/v2/confirm", body=raw, headers={"Content-Type": "application/json"})
                response = client.getresponse()
                body = response.read().decode("utf-8")
                assert response.status == 400
                assert "untrusted coordinator" not in body
                assert "TypeError" not in body
            finally:
                client.close()
    finally:
        server.stop()


def test_v2_default_validator_handles_nonobject_result_entries() -> None:
    coordinator_private, coordinator_public = generate_keypair()
    node_private, _ = generate_keypair()
    server = Ed25519NodeServer(SignedNodeConfig(
        "node-a", "127.0.0.1", 0, node_private, {"coordinator": coordinator_public},
    ))
    try:
        unsigned = {
            "protocol": PROTOCOL_VERSION,
            "node_id": "node-a",
            "coordinator_id": "coordinator",
            "envelope": {"envelope_id": "e", "payload_hash": "h", "results": ["not-a-result"]},
            "nonce": "malformed-results",
            "timestamp": time.time(),
        }
        response = server._handle(dict(unsigned, signature=sign_payload(coordinator_private, unsigned)))
        assert response["accepted"] is False
    finally:
        server.stop()
