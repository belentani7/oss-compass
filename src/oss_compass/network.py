from __future__ import annotations

import hmac
import hashlib
import json
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib import request

from .pvcu import ConfirmationReceipt, NodeConfirmation, ValidationEnvelope


@dataclass(frozen=True)
class NodeConfig:
    node_id: str
    host: str
    port: int
    secret: str


class NodeServer:
    """A real network node that verifies signed confirmation requests."""

    def __init__(self, config: NodeConfig, validator: Callable[[dict[str, Any]], tuple[bool, str]] | None = None, *, max_clock_skew: int = 60) -> None:
        self.config = config
        self.validator = validator or self._default_validator
        self.max_clock_skew = max_clock_skew
        self._seen_nonces: set[str] = set()
        self._lock = threading.Lock()
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                if self.path != "/confirm":
                    self.send_error(404)
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    body = json.loads(self.rfile.read(length).decode("utf-8"))
                    response = parent._handle(body)
                    encoded = json.dumps(response, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(encoded)))
                    self.end_headers()
                    self.wfile.write(encoded)
                except Exception as exc:  # the node must return a signed rejection, not crash
                    self.send_error(400, str(exc))

            def log_message(self, *_args: Any) -> None:
                return

        self._server = ThreadingHTTPServer((config.host, config.port), Handler)
        self.config = NodeConfig(config.node_id, config.host, self._server.server_port, config.secret)
        self._thread: threading.Thread | None = None

    @staticmethod
    def _default_validator(envelope: dict[str, Any]) -> tuple[bool, str]:
        results = envelope.get("results", [])
        valid = bool(envelope.get("envelope_id")) and bool(envelope.get("payload_hash")) and bool(results) and all(item.get("passed") is True for item in results)
        return (valid, "envelope verified" if valid else "envelope validation failed")

    def _handle(self, body: dict[str, Any]) -> dict[str, Any]:
        required = {"node_id", "envelope", "nonce", "timestamp", "signature"}
        if set(body) != required:
            raise ValueError("invalid confirmation request fields")
        if body["node_id"] != self.config.node_id:
            raise ValueError("wrong node destination")
        if abs(time.time() - float(body["timestamp"])) > self.max_clock_skew:
            raise ValueError("stale confirmation request")
        with self._lock:
            if body["nonce"] in self._seen_nonces:
                raise ValueError("replayed confirmation request")
            self._seen_nonces.add(body["nonce"])
        unsigned = {key: body[key] for key in ("node_id", "envelope", "nonce", "timestamp")}
        if not hmac.compare_digest(body["signature"], sign(self.config.secret, unsigned)):
            raise ValueError("invalid request signature")
        accepted, reason = self.validator(body["envelope"])
        response = {"node_id": self.config.node_id, "envelope_id": body["envelope"].get("envelope_id", ""), "accepted": accepted, "reason": reason, "nonce": body["nonce"], "timestamp": time.time()}
        response["signature"] = sign(self.config.secret, response)
        return response

    def start(self) -> NodeConfig:
        self._thread = threading.Thread(target=self._server.serve_forever, name=f"pvcu-{self.config.node_id}", daemon=True)
        self._thread.start()
        return self.config

    def stop(self) -> None:
        if self._thread:
            self._server.shutdown()
            self._thread.join(timeout=2)
        self._server.server_close()


def canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign(secret: str, value: dict[str, Any]) -> str:
    return hmac.new(secret.encode("utf-8"), canonical(value), hashlib.sha256).hexdigest()


def _request(config: NodeConfig, envelope: dict[str, Any], timeout: float) -> NodeConfirmation:
    unsigned = {"node_id": config.node_id, "envelope": envelope, "nonce": secrets.token_urlsafe(18), "timestamp": time.time()}
    body = dict(unsigned, signature=sign(config.secret, unsigned))
    req = request.Request(f"http://{config.host}:{config.port}/confirm", data=canonical(body), headers={"Content-Type": "application/json"}, method="POST")
    with request.urlopen(req, timeout=timeout) as response:
        result = json.loads(response.read().decode("utf-8"))
    response_signature = result.pop("signature", "")
    if result.get("node_id") != config.node_id or result.get("envelope_id") != envelope.get("envelope_id") or result.get("nonce") != unsigned["nonce"] or not hmac.compare_digest(response_signature, sign(config.secret, result)):
        raise ValueError("invalid node response signature")
    return NodeConfirmation(config.node_id, envelope["envelope_id"], bool(result["accepted"]), response_signature, str(result.get("reason", "")))


def confirm_over_network(envelope: ValidationEnvelope, nodes: tuple[NodeConfig, ...], *, quorum: int = 2, timeout: float = 2.0) -> ConfirmationReceipt:
    """Send one signed request to exactly three network nodes and apply 2-of-3 quorum."""
    if len(nodes) != 3 or {node.node_id for node in nodes} != {"node-a", "node-b", "node-c"}:
        raise ValueError("exactly node-a, node-b and node-c are required")
    if quorum != 2:
        raise ValueError("the network protocol requires a 2-of-3 quorum")
    envelope_dict = envelope.to_dict()
    confirmations: dict[str, NodeConfirmation] = {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(_request, node, envelope_dict, timeout): node for node in nodes}
        for future in as_completed(futures):
            node = futures[future]
            try:
                confirmations[node.node_id] = future.result()
            except Exception as exc:
                confirmations[node.node_id] = NodeConfirmation(node.node_id, envelope.envelope_id, False, "", f"node unavailable: {exc}")
    ordered = tuple(confirmations[node_id] for node_id in ("node-a", "node-b", "node-c"))
    return ConfirmationReceipt(envelope.envelope_id, ordered, quorum)
