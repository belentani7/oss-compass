"""PVC-U v2 confirmation over HTTP with Ed25519 signatures and bounded replay protection.

This transport authenticates the coordinator and node responses. Deployments
must still provide TLS, independent machines, secure key storage and a key
rotation process; this module intentionally does not pretend to provide them.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Mapping
from urllib import request

from .crypto import canonical_json, key_fingerprint, public_key_for, sign_payload, verify_payload
from .pvcu import ConfirmationReceipt, NodeConfirmation, ValidationEnvelope

MAX_REQUEST_BYTES = 131_072
PROTOCOL_VERSION = "pvcu-ed25519-v2"


@dataclass(frozen=True)
class CoordinatorIdentity:
    coordinator_id: str
    private_key: str

    @property
    def public_key(self) -> str:
        return public_key_for(self.private_key)


@dataclass(frozen=True)
class SignedNodeConfig:
    node_id: str
    host: str
    port: int
    private_key: str
    trusted_coordinators: Mapping[str, str]


@dataclass(frozen=True)
class SignedNodeEndpoint:
    node_id: str
    host: str
    port: int
    public_key: str


class Ed25519NodeServer:
    """Independent HTTP node with coordinator allow-list and expiring nonce cache."""

    def __init__(
        self,
        config: SignedNodeConfig,
        validator: Callable[[dict[str, Any]], tuple[bool, str]] | None = None,
        *,
        max_clock_skew: int = 60,
        max_request_bytes: int = MAX_REQUEST_BYTES,
        max_seen_nonces: int = 10_000,
    ) -> None:
        if not config.node_id or not config.trusted_coordinators:
            raise ValueError("a node_id and at least one trusted coordinator are required")
        self.config = config
        self.validator = validator or self._default_validator
        self.max_clock_skew = max_clock_skew
        self.max_request_bytes = max_request_bytes
        self.max_seen_nonces = max_seen_nonces
        self._seen_nonces: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                if self.path != "/v2/confirm":
                    self.send_error(404)
                    return
                try:
                    raw_length = self.headers.get("Content-Length")
                    if raw_length is None:
                        raise ValueError("content length is required")
                    length = int(raw_length)
                    if not 0 < length <= parent.max_request_bytes:
                        raise ValueError("request body size is not allowed")
                    body = json.loads(self.rfile.read(length).decode("utf-8"))
                    response = parent._handle(body)
                    encoded = canonical_json(response)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(encoded)))
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    self.wfile.write(encoded)
                except (ValueError, json.JSONDecodeError) as exc:
                    self.send_error(400, str(exc))

            def log_message(self, *_args: Any) -> None:
                return

        self._server = ThreadingHTTPServer((config.host, config.port), Handler)
        self.config = SignedNodeConfig(config.node_id, config.host, self._server.server_port, config.private_key, config.trusted_coordinators)
        self._thread: threading.Thread | None = None

    @staticmethod
    def _default_validator(envelope: dict[str, Any]) -> tuple[bool, str]:
        results = envelope.get("results", [])
        valid = bool(envelope.get("envelope_id")) and bool(envelope.get("payload_hash")) and bool(results) and all(item.get("passed") is True for item in results)
        return valid, "envelope verified" if valid else "envelope validation failed"

    def _remember_nonce(self, nonce: str, timestamp: float) -> None:
        now = time.time()
        with self._lock:
            while self._seen_nonces:
                oldest, observed_at = next(iter(self._seen_nonces.items()))
                if now - observed_at <= self.max_clock_skew and len(self._seen_nonces) < self.max_seen_nonces:
                    break
                self._seen_nonces.pop(oldest)
            if nonce in self._seen_nonces:
                raise ValueError("replayed confirmation request")
            self._seen_nonces[nonce] = timestamp

    def _handle(self, body: dict[str, Any]) -> dict[str, Any]:
        required = {"protocol", "node_id", "coordinator_id", "envelope", "nonce", "timestamp", "signature"}
        if set(body) != required or body["protocol"] != PROTOCOL_VERSION:
            raise ValueError("invalid confirmation request fields")
        if body["node_id"] != self.config.node_id:
            raise ValueError("wrong node destination")
        try:
            timestamp = float(body["timestamp"])
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid request timestamp") from exc
        if abs(time.time() - timestamp) > self.max_clock_skew:
            raise ValueError("stale confirmation request")
        coordinator_id = body["coordinator_id"]
        coordinator_key = self.config.trusted_coordinators.get(coordinator_id)
        if coordinator_key is None:
            raise ValueError("untrusted coordinator")
        unsigned = {key: body[key] for key in required - {"signature"}}
        if not verify_payload(coordinator_key, unsigned, body["signature"]):
            raise ValueError("invalid request signature")
        self._remember_nonce(str(body["nonce"]), timestamp)
        accepted, reason = self.validator(body["envelope"])
        response = {
            "protocol": PROTOCOL_VERSION,
            "node_id": self.config.node_id,
            "node_key_fingerprint": key_fingerprint(public_key_for(self.config.private_key)),
            "envelope_id": body["envelope"].get("envelope_id", ""),
            "accepted": accepted,
            "reason": reason,
            "nonce": body["nonce"],
            "timestamp": time.time(),
        }
        response["signature"] = sign_payload(self.config.private_key, response)
        return response

    def endpoint(self) -> SignedNodeEndpoint:
        return SignedNodeEndpoint(self.config.node_id, self.config.host, self.config.port, public_key_for(self.config.private_key))

    def start(self) -> SignedNodeEndpoint:
        self._thread = threading.Thread(target=self._server.serve_forever, name=f"pvcu-v2-{self.config.node_id}", daemon=True)
        self._thread.start()
        return self.endpoint()

    def stop(self) -> None:
        if self._thread:
            self._server.shutdown()
            self._thread.join(timeout=2)
        self._server.server_close()


def _request(endpoint: SignedNodeEndpoint, coordinator: CoordinatorIdentity, envelope: dict[str, Any], timeout: float) -> NodeConfirmation:
    unsigned = {
        "protocol": PROTOCOL_VERSION,
        "node_id": endpoint.node_id,
        "coordinator_id": coordinator.coordinator_id,
        "envelope": envelope,
        "nonce": secrets.token_urlsafe(24),
        "timestamp": time.time(),
    }
    body = dict(unsigned, signature=sign_payload(coordinator.private_key, unsigned))
    req = request.Request(
        f"http://{endpoint.host}:{endpoint.port}/v2/confirm",
        data=canonical_json(body),
        headers={"Content-Type": "application/json", "Content-Length": str(len(canonical_json(body)))},
        method="POST",
    )
    with request.urlopen(req, timeout=timeout) as response:
        if response.headers.get_content_type() != "application/json":
            raise ValueError("node did not return JSON")
        response_body = response.read(MAX_REQUEST_BYTES + 1)
    if len(response_body) > MAX_REQUEST_BYTES:
        raise ValueError("node response exceeds size limit")
    result = json.loads(response_body.decode("utf-8"))
    signature = result.pop("signature", "")
    expected = {"protocol", "node_id", "node_key_fingerprint", "envelope_id", "accepted", "reason", "nonce", "timestamp"}
    if set(result) != expected or result["protocol"] != PROTOCOL_VERSION:
        raise ValueError("invalid node response fields")
    if result["node_id"] != endpoint.node_id or result["envelope_id"] != envelope.get("envelope_id") or result["nonce"] != unsigned["nonce"]:
        raise ValueError("node response does not match request")
    if result["node_key_fingerprint"] != key_fingerprint(endpoint.public_key):
        raise ValueError("node response key fingerprint does not match endpoint")
    if not verify_payload(endpoint.public_key, result, signature):
        raise ValueError("invalid node response signature")
    return NodeConfirmation(endpoint.node_id, envelope["envelope_id"], bool(result["accepted"]), signature, str(result["reason"]))


def confirm_over_ed25519_network(
    envelope: ValidationEnvelope,
    coordinator: CoordinatorIdentity,
    nodes: tuple[SignedNodeEndpoint, ...],
    *,
    quorum: int = 2,
    timeout: float = 2.0,
) -> ConfirmationReceipt:
    """Confirm an envelope through exactly three Ed25519-authenticated nodes."""
    required_nodes = {"node-a", "node-b", "node-c"}
    if len(nodes) != 3 or {node.node_id for node in nodes} != required_nodes:
        raise ValueError("exactly node-a, node-b and node-c are required")
    if quorum != 2:
        raise ValueError("the network protocol requires a 2-of-3 quorum")
    confirmations: dict[str, NodeConfirmation] = {}
    envelope_dict = envelope.to_dict()
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(_request, node, coordinator, envelope_dict, timeout): node for node in nodes}
        for future in as_completed(futures):
            node = futures[future]
            try:
                confirmations[node.node_id] = future.result()
            except Exception as exc:
                confirmations[node.node_id] = NodeConfirmation(node.node_id, envelope.envelope_id, False, "", f"node unavailable: {exc}")
    ordered = tuple(confirmations[node_id] for node_id in ("node-a", "node-b", "node-c"))
    return ConfirmationReceipt(envelope.envelope_id, ordered, quorum)
