---
name: addressing-dependabot
description: Addresses GitHub Dependabot security alerts by listing open alerts, identifying affected projects, upgrading vulnerable dependencies, running verification, and committing fixes. Use when the user wants to fix Dependabot alerts, upgrade vulnerable packages, or address security vulnerabilities found by Dependabot.
---

# Addressing Dependabot Security Alerts

Guide remediation of Dependabot alerts for this monorepo.

**CRITICAL: At each approval gate (Steps 2 and 6), you MUST use the `AskUserQuestion` tool before proceeding.**

## Overview

1. Fetch Open Alerts
2. Present Alerts for Selection [GATE]
3. Analyze Affected Projects
4. Update Dependencies
5. Run Verification (lint + tests, retry on failure)
6. Review and Commit [GATE]

---

## Step 1: Fetch Open Alerts

Detect the repo dynamically, then fetch alerts:

```bash
REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner)
gh api "repos/${REPO}/dependabot/alerts?state=open&per_page=100" \
  --jq '.[] | {number, package: .dependency.package.name, ecosystem: .dependency.package.ecosystem, manifest: .dependency.manifest_path, severity: .security_advisory.severity, summary: .security_advisory.summary, fixed_in: .security_vulnerability.first_patched_version.identifier, cve: .security_advisory.cve_id}'
```

If the user provided a severity filter, keep only alerts at or above that level (critical > high > medium > low).

If the user provided a specific alert number:

```bash
REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner)
gh api "repos/${REPO}/dependabot/alerts/{number}" \
  --jq '{number, package: .dependency.package.name, ecosystem: .dependency.package.ecosystem, manifest: .dependency.manifest_path, severity: .security_advisory.severity, summary: .security_advisory.summary, fixed_in: .security_vulnerability.first_patched_version.identifier, cve: .security_advisory.cve_id, description: .security_advisory.description}'
```

If no open alerts exist, inform the user and stop.

---

## Step 2: Present Alerts for Selection [GATE 1]

Present alerts grouped by severity using this template:

```
## Open Dependabot Security Alerts

### Critical
| # | Package | Ecosystem | Project | Summary | Fix Version |
|---|---------|-----------|---------|---------|-------------|

### High
...

### Medium / Low
...

Total: {count} open alerts
```

Derive the "Project" column by stripping the filename from the alert's `manifest` path (e.g. `projects/web_api/uv.lock` → `projects/web_api`).

**STOP: Use `AskUserQuestion` to ask which alerts to address. Options: specific numbers, a severity level ("all critical"), or "all".**

Skip this gate if the user already specified an alert number as an argument.

---

## Step 3: Analyze Affected Projects

For each selected alert, determine the ecosystem and update strategy.

### Python (pip) alerts

The manifest path points to a `uv.lock` file. The project directory is its parent.

Check if the package is a **direct dependency**:

```bash
grep -i "{package}" {project_dir}/pyproject.toml
```

- **Direct dependency found** → update with `uv add` in Step 4
- **Not found (transitive)** → update with `uv sync --upgrade-package` in Step 4

Also scan all projects for the same package — Dependabot may only flag one manifest, but others may be affected:

```bash
grep -rli "{package}" projects/*/pyproject.toml libs/*/pyproject.toml 2>/dev/null
```

### npm alerts

The manifest is `projects/frontend/package-lock.json`. Check `projects/frontend/package.json` for the package to determine direct vs transitive.

### Rust (cargo) alerts

The manifest is `projects/noseyparker_scanner/Cargo.lock`. Provide guidance only — NoseyParker builds from an upstream project, so Cargo dependency updates may require upstream changes or a container rebuild.

### Python project paths reference

```
projects/web_api/
projects/file_enrichment/
projects/document_conversion/
projects/cli/
projects/alerting/
projects/housekeeping/
projects/agents/
libs/common/
libs/file_enrichment_modules/
libs/chromium/
libs/file_linking/
libs/nemesis_dpapi/
```

Frontend: `projects/frontend/`

---

## Step 4: Update Dependencies

### Python — Direct dependency

```bash
cd {project_dir} && uv add "{package}>={fixed_version}"
```

Or for latest:

```bash
cd {project_dir} && uv add {package}@latest
```

Update ALL projects where this package is a direct dependency, not just the one flagged.

### Python — Transitive dependency

```bash
cd {project_dir} && uv sync --upgrade-package {package}
```

If that doesn't resolve to the fixed version, try upgrading the parent dependency. As a last resort, pin the minimum version:

```toml
# In pyproject.toml under [tool.uv]
constraint-dependencies = ["{package}>={fixed_version}"]
```

### npm — Direct dependency

```bash
cd projects/frontend && npm update {package}
```

If `npm update` doesn't resolve to the fixed version:

```bash
cd projects/frontend && npm install {package}@latest
```

### npm — Transitive dependency

Add an override in `projects/frontend/package.json` (existing pattern — see `lodash` override):

```json
"overrides": {
  "{package}": ">={fixed_version}"
}
```

Then `npm install`.

### Rust

Provide instructions:

```bash
cd projects/noseyparker_scanner && cargo update {package}
```

Note that the NoseyParker container may need rebuilding: `docker compose -f compose.base.yaml build noseyparker`

---

## Step 5: Run Verification

### Lint

```bash
cd /home/itadmin/code/Nemesis && uv run ruff check . --fix && uv run ruff format .
```

### Tests

Run tests for each affected Python project:

```bash
cd {project_dir} && uv run pytest tests/ -x -q
```

For frontend changes:

```bash
cd projects/frontend && npm run build
```

### Feedback loop

If lint or tests fail:
1. Investigate whether the failure is caused by the dependency update
2. If related: fix the issue (version pinning, code adjustment) and re-run
3. If pre-existing: note it and proceed

### Verification checklist

```
- [ ] uv sync / npm install succeeded
- [ ] Ruff lint passes
- [ ] Tests pass for all affected projects
- [ ] No unintended lock file changes (review git diff briefly)
```

---

## Step 6: Review and Commit [GATE 2]

Present a summary using this template:

```
## Dependabot Alert Fix Summary

### Alerts Addressed
| # | Package | Severity | CVE | Status |
|---|---------|----------|-----|--------|

### Files Changed
{git diff --name-only output}

### Verification Results
- Lint: PASS/FAIL
- Tests: PASS/FAIL (per project)

### Proposed Commit Message
fix: upgrade {packages} to address {CVEs} (Dependabot #{numbers})
```

**STOP: Use `AskUserQuestion` to get approval before committing.**

Commit only the relevant files (typically `pyproject.toml` + `uv.lock` for Python, `package.json` + `package-lock.json` for npm). Alerts auto-close once the fix reaches the default branch.

---

## Troubleshooting

### gh CLI not authenticated

```bash
gh auth status
```

### Package version conflict

If `uv add` fails due to version constraints, relax bounds in `pyproject.toml`. For example, change `>=1.0,<2.0` to `>=1.5,<3.0`.

### Transitive dependency stuck on old version

If the parent dependency pins an old version, check for a newer parent release. If none exists, use `constraint-dependencies` in `[tool.uv]` to force the minimum version.

### npm transitive dependency

Use the `"overrides"` field in `package.json` (same pattern as the existing `lodash` override).

### Dismissing an alert without fixing

```bash
REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner)
gh api --method PATCH "repos/${REPO}/dependabot/alerts/{number}" \
  -f state=dismissed -f dismissed_reason="tolerable_risk"
```

Valid reasons: `fix_started`, `inaccurate`, `no_bandwidth`, `not_used`, `tolerable_risk`.
