---
name: addressing-dependabot
description: Addresses GitHub Dependabot security alerts by listing open alerts, identifying affected Python/uv, frontend npm, and Titus Go projects, upgrading vulnerable dependencies, running verification, and committing fixes. Use when the user wants to fix Dependabot alerts, upgrade vulnerable packages, or address security vulnerabilities found by Dependabot.
---

# Addressing Dependabot Security Alerts

Guide remediation of Dependabot alerts for this monorepo.

**CRITICAL: At each approval gate (Steps 2 and 6), ask for explicit user approval before proceeding. Use `request_user_input` when available; otherwise ask a direct concise question in chat and wait for an explicit approval response.**

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

**STOP: Ask which alerts to address. Options: specific numbers, a severity level ("all critical"), or "all". Use `request_user_input` when available; otherwise ask a direct concise question in chat and wait for an explicit approval response.**

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

The manifest is `projects/frontend/package-lock.json`. Check `projects/frontend/package.json` for the package to determine direct vs transitive:

```bash
grep -i "\"{package}\"" projects/frontend/package.json
```

- **Direct dependency/devDependency found** → update the dependency spec in `package.json`, then run `npm install`
- **Override already exists** → update the override minimum too, otherwise `npm install {package}@...` may fail with `EOVERRIDE`
- **Transitive only** → add or update an `overrides` entry in `package.json`, then run `npm install`

After npm updates, verify the actually installed version from `package-lock.json` or `npm ls {package}`. Some vulnerable version strings may remain as a parent package's requested dependency, but the resolved `node_modules/{package}` entry must be fixed-or-newer.

### Go (go) alerts

The manifest is usually `projects/titus_scanner/go.mod` or `projects/titus_scanner/go.sum`. Check whether the package is direct or indirect:

```bash
grep -n "{package}" projects/titus_scanner/go.mod projects/titus_scanner/go.sum
```

Use the fixed version from Dependabot when possible. Go module tags need a leading `v`, so fixed version `5.9.2` becomes `v5.9.2`. If `go` is not on PATH, use `/usr/local/go/bin/go`.

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
cd projects/frontend && npm install "{package}@>={fixed_version}"
```

If the package is in `devDependencies`, keep it there:

```bash
cd projects/frontend && npm install --save-dev "{package}@>={fixed_version}"
```

If an existing override for the same package conflicts with the direct dependency, edit `projects/frontend/package.json` so both the dependency/devDependency spec and the override allow `>={fixed_version}`, then run `npm install`.

### npm — Transitive dependency

Add an override in `projects/frontend/package.json` (existing pattern — see `lodash` override):

```json
"overrides": {
  "{package}": ">={fixed_version}"
}
```

Then `npm install`.

Verify resolution:

```bash
cd projects/frontend && npm ls {package}
```

### Go

```bash
cd projects/titus_scanner && go get {package}@v{fixed_version} && go mod tidy
```

If multiple Go alerts affect the same project, upgrade them together:

```bash
cd projects/titus_scanner && go get {package1}@v{fixed_version1} {package2}@v{fixed_version2} && go mod tidy
```

Verify resolution:

```bash
cd projects/titus_scanner && go list -m {package}
```

Note that the Titus container may need rebuilding: `docker compose build titus-scanner`

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
cd projects/frontend && npm run build && npm audit --audit-level=low
```

For Titus Go changes:

```bash
cd projects/titus_scanner && go test ./...
```

### Feedback loop

If lint or tests fail:
1. Investigate whether the failure is caused by the dependency update
2. If related: fix the issue (version pinning, code adjustment) and re-run
3. If pre-existing: note it and proceed

### Verification checklist

```
- [ ] uv sync / npm install / go get + go mod tidy succeeded
- [ ] Ruff lint passes
- [ ] npm build and audit pass for frontend changes
- [ ] Go tests pass for Titus changes
- [ ] Tests pass for all affected Python projects
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

**STOP: Ask for approval before committing. Use `request_user_input` when available; otherwise ask a direct concise question in chat and wait for an explicit approval response.**

Commit only the relevant files:

- Python: `pyproject.toml` + `uv.lock`
- npm: `projects/frontend/package.json` + `projects/frontend/package-lock.json`
- Go: `projects/titus_scanner/go.mod` + `projects/titus_scanner/go.sum`

Alerts auto-close once the fix reaches the default branch.

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

### npm direct dependency conflicts with override

If `npm install {package}@...` fails with `EOVERRIDE`, update the existing override and the direct dependency spec in `package.json` to the fixed range, then run plain `npm install`.

### go command not found

Use `/usr/local/go/bin/go` in place of `go`.

### Go fixed version format

Dependabot may show `fixed_in` without a leading `v` (for example `5.9.2`). Use `v5.9.2` in `go get`.

### Dismissing an alert without fixing

```bash
REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner)
gh api --method PATCH "repos/${REPO}/dependabot/alerts/{number}" \
  -f state=dismissed -f dismissed_reason="tolerable_risk"
```

Valid reasons: `fix_started`, `inaccurate`, `no_bandwidth`, `not_used`, `tolerable_risk`.
