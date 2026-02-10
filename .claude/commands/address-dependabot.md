# /address-dependabot

Address GitHub Dependabot security alerts by upgrading vulnerable dependencies.

## Usage

```
/address-dependabot
/address-dependabot critical
/address-dependabot 683
```

## Arguments

- **No arguments**: Lists all open alerts sorted by severity for selection
- **Severity filter** (`critical`, `high`, `medium`, `low`): Lists alerts at or above that severity
- **Alert number**: Jumps directly to addressing a specific alert

## What This Command Does

1. **Fetch Alerts** - Lists open Dependabot alerts from GitHub via `gh` CLI
2. **Select Alerts** - Presents alerts grouped by severity for you to choose (approval gate)
3. **Analyze Impact** - Identifies affected projects and whether deps are direct or transitive
4. **Update Dependencies** - Upgrades via `uv` (Python) or `npm` (JavaScript)
5. **Verify** - Runs linting and tests to confirm nothing breaks
6. **Commit** - Reviews changes and commits with your approval (approval gate)

## Approval Gates

1. **Alert Selection** - Choose which alerts to address
2. **Pre-Commit Review** - Review changes before committing

## Requirements

- `gh` CLI authenticated with repo access
- `uv` for Python dependency management
- `npm` for frontend dependency management

## Reference

Full skill: `.claude/skills/addressing-dependabot.md`
