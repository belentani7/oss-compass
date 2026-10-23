# OSS COMPASS — PROJECT MASTER PROMPT

## Source of truth and identity
This repository is **OSS Compass**, a Python 3.10+ implementation of the PVC-U validation protocol. It is NOT a generic project-auditing dashboard or a replacement for other Belentani products. The implemented domain is validated envelopes, deterministic rules, 2-of-3 confirmations, Ed25519 trust, anti-replay protections and a tamper-evident ledger. Start from the current source, tests and README; do not replace this architecture with a template or invent capabilities.

## Maximum useful product vision
Deliver a reusable, security-conscious library and CLI that allows integrators to (1) bind evidence to a canonical payload, (2) apply versioned validation rules, (3) request genuinely independent, authenticated confirmations, (4) verify quorum and reasoned rejection, (5) persist and independently verify an audit trail against externally anchored checkpoints, and (6) integrate with CI or runtime policy gates using machine-readable output.

## Engineering roadmap (implement, don't merely describe)
1. **Integrity foundation:** typed validation errors; strict envelope/receipt invariants; bounded canonical payload sizes; stable serialization; malformed-input and fuzz tests; incremental ledger persistence with duplicate/divergent-history detection. Keep HMAC v1 compatibility separate from signed v2.
2. **Policy evaluation:** composable and versioned rule packs, explicit fail-closed behavior, deterministic evaluation, provenance and explainable results, no hidden LLM verdicts.
3. **Independent confirmation:** cryptographic key rotation/revocation, coordinator and node identity constraints, bounded nonce persistence across restarts, timeouts, retries, TLS requirements and health/readiness checks. Prove independence; never label three in-process boolean votes 'distributed'.
4. **Audit transport and operations:** crash-safe transactional persistence, cross-process writer locking, external checkpoint anchoring, export/import verification, backup and recovery drills, structured events, metrics without secret leakage.
5. **Developer product:** typed API, examples, CLI policy/ledger workflows, CI adapters, documentation in ES/EN and migration guides, accessible integration examples, packaging and release checks.
6. **Assurance:** threat modeling, dependency security, property-based and adversarial tests, continuous integration, reproducible performance/load benchmarks, cross-platform behavior and integration tests with actual separated processes.

## Non-negotiable implementation rules
- Work in this repository and preserve project history, licenses, names, public APIs and migration paths. Do not create a new repository.
- Prefer source-code changes, tests and verified user flows over speculative plans.
- Never expose private keys, credentials, real customer payloads or secrets in test fixtures, logs or issues.
- Never claim Byzantine fault tolerance, production immutability, authenticated transport, deployment readiness or verified CI without evidence.
- Hash-chain verification alone cannot detect truncation without a trusted external head hash. An append-only format is not atomic or multi-writer safe without a durable lock and crash-safe transaction.
- Open reviewable PRs with precise changed files and test evidence. Do not merge, deploy or publish without passing quality gates and approval for potentially destructive changes.

## Reusable implementation instruction
Read the current README, pyproject, src/oss_compass, tests, current main HEAD and existing PRs. Pick the highest-impact missing behavior not under active development. Implement a small coherent vertical slice with failing regression tests first where possible. Run pytest and integration checks in a clean environment if execution is available; otherwise label tests **not executed** and inspect CI without treating runner failures as passing. Open or update one PR; record SHA, remaining blockers and the next substantive slice; continue to a different pending historical repository in future scheduled executions rather than cycling here without a blocker.
