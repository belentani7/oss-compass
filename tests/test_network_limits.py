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
