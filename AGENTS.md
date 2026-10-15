# Repository Guidelines — Belentani / NOIACORE

> Universal contributor guide. Read before opening any issue, PR, or coding.

## Mission

Part of the **Belentani / NOIACORE** ecosystem: open education, creative
technology, applied AI. Every repo must serve a clear purpose visible in
the README.

## Project Structure

```
canonical-name/            # one canonical repo per product
├── apps/                  # Next.js / SvelteKit frontend apps
│   └── web/
├── packages/              # shared libraries
│   ├── ui/                # design system (@belentani/ui)
│   └── config/            # TS/ESLint/Vite shared configs
├── services/              # FastAPI + Pydantic backend services
│   └── api/
├── docs/                  # Starlight / Docusaurus
├── .github/
│   ├── workflows/ci.yml   # comprehensive gates
│   └── ISSUE_TEMPLATE/
├── AGENTS.md              # this file
├── CLAUDE.md              # Claude Code optimizations
├── package.json           # pnpm workspaces root
├── pyproject.toml         # uv workspace (Python)
└── turbo.json             # Turborepo
```

## Build, Test, Dev Commands

```bash
pnpm install --frozen-lockfile          # install all
pnpm -F web dev                         # start frontend dev server
pnpm -F web build                       # production build
pnpm -F web test                        # unit tests
pnpm -F web typecheck                   # tsc --noEmit
pnpm -F web lint                        # eslint + format:check
pnpm quality:gates                      # typecheck + lint + test + build
uv sync                                 # install Python deps
uv run pytest                           # Python tests
uv run python -m fastapi --dir services/api dev  # backend dev
```

## Coding Standards

- **TypeScript**: Strict mode (`strict: true`), `tsc --noEmit` must pass
- **Python**: FastAPI + Pydantic V2, type hints mandatory, `ruff check` clean
- **Formatting**: Prettier (TS/JS), Ruff format (Python)
- **Commits**: Conventional Commits (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`)
- **Branches**: `main` is protected. Feature branches: `feat/issue-number-short-description`
- **PRs**: Must link an issue, have CI green, 1 review, <400 diff lines (split if larger)

## Non-negotiable Rules

1. **NO PII** in code, logs, commits, or AI prompts — anonymize everything
2. **NO secrets** — `.env.example` only; real env vars via GitHub Secrets
3. **NO `|| true`** in CI workflows — failures must block merge
4. **License** = MIT in LICENSE + MIT badge in README
5. **Tests** = required for any logic; coverage gate: 80% critical, 60% overall
6. **CI** must be green on `main` before any merge
7. **No `db:push --accept-data-loss`**, `db:reset`, or destructive migration scripts
8. **GDPR/AES-256** claims must be demonstrable in code, not asserted in README
9. **Rate limiting + Zod/Pydantic validation** mandatory for every API endpoint
10. **`prefers-reduced-motion`** respected in all frontend animations

## Security

- **GitHub Advanced Security**: CodeQL + Dependabot + Secret Scanning enabled
- **Gitleaks**: `.gitleaks.toml` in repo root; CI scans full history
- **Dependabot**: auto-PRs for security updates; group non-breaking deps
- **SBOM**: `cyclonedx` or `syft` in release workflow
- **Privacy**: data minimization, consent logging, 30-day retention max

## Frontend Standards

- **Design system**: `@belentani/ui` package with shared tokens
- **Palette**: Green-positive (`#00FF94`, `#39D98A`, `#A7F36C`) on dark surfaces
- **Animations**: GSAP + Framer Motion; respect `prefers-reduced-motion`
- **3D**: R3F + Drei + postprocessing for creative hubs; fallback to HTML/CSS
- **a11y**: axe-core 0 violations, WCAG 2.2 AA minimum
- **Lighthouse**: 95+ on Performance, Best Practices, SEO; Accessibility 100

## Backend Standards (Python)

- **FastAPI** for all APIs (async, OpenAPI autodocs)
- **Pydantic V2** for input validation
- **SQLModel/SQLAlchemy** only for persistence (not in-memory scripts)
- **uv** for environment + dependency management (not pip/poetry)
- **pytest** + **pytest-cov** for tests
- **Ruff** for lint + format (unify in one tool)
- **OpenTelemetry** + structured logging (no PII in logs)
- **Rate limiting**: `slowapi` with in-memory Redis or `fastapi-limiter`
- **MCP SDK**: `mcp[cli]` for tool servers; document tools with `.well-known/`

## Agent-Specific Instructions

- This file is read by **OpenAI Codex**, **Claude Code**, **Cursor**, and
  **Google Jules** (agents.md standard).
- **No cloning repos** — use GitHub API via `gh` CLI for all repo operations.
- Verify file existence before reading/writing via API.
- Respect `permission.edit.deny` patterns for `**/01_LEGAL/**` and `**/.env*`
- Frontend tokens live in `packages/ui/src/tokens.css`
- Python: Ruff + Black + mypy strict; all public functions type-annotated
- Use MCP servers: `belentani-audit`, `reference-repos` when available
