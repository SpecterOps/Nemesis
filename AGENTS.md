# Repository Guidelines

## Project Structure & Module Organization
Nemesis is organized as a multi-service monorepo:
- `projects/`: deployable services (for example `web_api`, `file_enrichment`, `frontend`, `agents`), each typically with its own `pyproject.toml` and `tests/`.
- `libs/`: shared Python libraries (`common`, `file_linking`, `nemesis_dpapi`, `file_enrichment_modules`).
- `infra/`: Docker, Dapr, Traefik, and observability configuration.
- `tools/`: repo-level developer scripts (`install_dev_env.sh`, `lint.sh`, `test.sh`, `nemesis-ctl.sh`).
- `docs/`: MkDocs content and generated API documentation assets.

## Build, Test, and Development Commands
- `cp env.example .env`: create local configuration.
- `./tools/install_dev_env.sh`: install/sync Python deps (`uv sync --frozen`) across `libs/*` and `projects/*`.
- `./tools/nemesis-ctl.sh start dev --build`: build and run the local development stack.
- `./tools/nemesis-ctl.sh start prod --monitoring --jupyter`: run the production profile locally with optional services.
- `./tools/lint.sh`: run `ruff check --fix` and `ruff format` for the repository.
- `./tools/test.sh`: run `uv run pytest tests/ -x -q` in each Python package that has a `tests/` directory.
- Frontend only: `cd projects/frontend && npm run dev` (or `npm run build`, `npm run preview`).

## Codex Skills
- Repo-local Codex skills live under `.codex/skills/`.
- Use `$enrichment-module-builder <file type description>` to run the guided module workflow for new modules.
- Use `$managing-packages <task>` when adding, upgrading, removing, or syncing Python dependencies.
- For broader repo context and command reminders, reference `.codex/references/project-context.md`.

## Coding Style & Naming Conventions
- Python version target is 3.13 (`>=3.13,<3.14` in project manifests).
- Follow root Ruff config: 4-space indentation, 120-char line length, double quotes, and sorted imports.
- Naming: Python modules/functions `snake_case`, classes `PascalCase`, constants `UPPER_SNAKE_CASE`.
- In frontend code, keep component filenames `PascalCase` under `projects/frontend/src/components`.

## Testing Guidelines
- Primary framework is `pytest` (with `pytest-asyncio` used across many packages).
- Place tests in `<module>/tests/` and use `test_*.py` naming; benchmark modules may use `bench_*.py` where configured.
- No global coverage threshold is currently enforced; add regression tests for bug fixes and changed behavior.

## Commit & Pull Request Guidelines
- Match existing commit style: short, imperative subjects like `fix docs`, `bump deps`, `linting, lint+test scripts`; optional issue/PR refs (for example `(#100)`).
- PRs should include: purpose, affected modules/services, test evidence (script output or targeted runs), and any `.env`/compose impact.
- Include screenshots for UI changes in `projects/frontend` and link related issues/docs updates.

## Security & Configuration Tips
- Do not commit secrets; keep `.env` local and derive it from `env.example`.
- Never read or open `.env*` files from agent workflows; use `env.example` for variable shape/reference.
- When changing runtime topology, update related `compose*.yaml` and `infra/*` files in the same PR.
