"""Tests for quorum node request authentication, nonce handling and limits."""

import http.client
import json
import time

import pytest

from oss_compass.network import (
    MAX_CONFIRMATION_BYTES, NodeConfig, NodeServer, sign,
)


def request_body(server, *, nonce="fixed-unique-nonce-01", timestamp=None):
    body = {
        "node_id": server.config.node_id,
        "envelope": {"envelope_id": "fixture", "payload_hash": "hash", "results": [{"passed": True}]},
        "nonce": nonce,
        "timestamp": time.time() if timestamp is None else timestamp,
    }
    body["signature"] = sign(server.config.secret, body)
    return body


def test_forged_requests_do_not_consume_replay_memory():
    server = NodeServer(NodeConfig("node-a", "127.0.0.1", 0, "test-key"))
    try:
        invalid = request_body(server)
        invalid["signature"] = "0" * 64
        with pytest.raises(ValueError, match="signature"):
            server._handle(invalid)
        assert server._seen_nonces == {}
        assert server._handle(request_body(server))["accepted"] is True
    finally:
        server.stop()


def test_replay_is_rejected_and_expired_nonces_are_pruned():
    server = NodeServer(NodeConfig("node-a", "127.0.0.1", 0, "test-key"))
    try:
        body = request_body(server)
        server._handle(body)
        with pytest.raises(ValueError, match="replayed"):
            server._handle(body)
        server._seen_nonces["old-nonce"] = time.time() - 1000
        server._handle(request_body(server, nonce="second-fixed-nonce"))
        assert "old-nonce" not in server._seen_nonces
    finally:
        server.stop()


def test_nonfinite_timestamp_rejected_even_with_matching_signature():
    server = NodeServer(NodeConfig("node-a", "127.0.0.1", 0, "test-key"))
    try:
        body = request_body(server, timestamp=float("nan"))
        with pytest.raises(ValueError, match="stale"):
            server._handle(body)
    finally:
        server.stop()



def test_malformed_body_is_rejected_before_signature_or_nonce_processing():
    server = NodeServer(NodeConfig("node-a", "127.0.0.1", 0, "test-key"))
    try:
        for invalid in [None, 3, [], "text", {"node_id": server.config.node_id}]:
            with pytest.raises(ValueError):
                server._handle(invalid)
        body = request_body(server)
        body["envelope"] = "not-an-object"
        body["signature"] = sign(server.config.secret, {
            key: body[key] for key in ("node_id", "envelope", "nonce", "timestamp")
        })
        with pytest.raises(ValueError, match="envelope"):
            server._handle(body)
        assert server._seen_nonces == {}
    finally:
        server.stop()


def test_http_malformed_payload_does_not_reflect_untrusted_exception():
    server = NodeServer(NodeConfig("node-a", "127.0.0.1", 0, "test-key"))
    config = server.start()
    try:
        client = http.client.HTTPConnection(config.host, config.port, timeout=3)
        client.request("POST", "/confirm", body=b"{invalid marker do-not-echo}",
                       headers={"Content-Type": "application/json"})
        response = client.getresponse()
        data = response.read().decode("utf-8")
        assert response.status == 400
        assert "do-not-echo" not in data
        assert "JSONDecodeError" not in data
        client.close()
    finally:
        server.stop()

def test_http_handler_rejects_oversized_confirmation_before_reading():
    server = NodeServer(NodeConfig("node-a", "127.0.0.1", 0, "test-key"))
    config = server.start()
    try:
        conn = http.client.HTTPConnection(config.host, config.port, timeout=3)
        conn.request("POST", "/confirm", body=b"{}", headers={
            "Content-Length": str(MAX_CONFIRMATION_BYTES + 1),
            "Content-Type": "application/json",
        })
        response = conn.getresponse()
        assert response.status == 413
        response.read()
        conn.close()
    finally:
        server.stop()


def test_nonce_cache_fails_closed_at_capacity_and_reclaims_expired_entries(monkeypatch):
    # Use a tiny configured limit so the failure mode can be exercised cheaply.
    monkeypatch.setattr("oss_compass.network.MAX_RECENT_NONCES", 2)
    server = NodeServer(NodeConfig("node-a", "127.0.0.1", 0, "test-key"))
    try:
        first = request_body(server, nonce="first-unique-nonce-01")
        second = request_body(server, nonce="second-unique-nonce-02")
        third = request_body(server, nonce="third-unique-nonce-03")
        assert server._handle(first)["accepted"] is True
        assert server._handle(second)["accepted"] is True

        # Authenticated bursts cannot grow memory by displacing live replay evidence.
        with pytest.raises(ValueError, match="capacity"):
            server._handle(third)
        assert len(server._seen_nonces) == 2
        with pytest.raises(ValueError, match="replayed"):
            server._handle(first)

        # Expired records are reclaimed before admission, without weakening replay.
        server._seen_nonces[first["nonce"]] = time.time() - 1000
        assert server._handle(third)["accepted"] is True
        assert first["nonce"] not in server._seen_nonces
        assert len(server._seen_nonces) == 2
    finally:
        server.stop()
