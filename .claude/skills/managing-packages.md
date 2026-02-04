---
name: managing-packages
description: Manages Python package dependencies. Use when adding, upgrading, removing, or syncing Python/pypi packages in projects or libs.
---

# Managing Packages with uv

## Commands

All commands must be run from the specific project/library directory.

### Add a package

```bash
cd /home/itadmin/code/Nemesis/{path} && uv add {package}
```

### Add dev dependency

```bash
cd /home/itadmin/code/Nemesis/{path} && uv add --dev {package}
```

### Upgrade a package

```bash
cd /home/itadmin/code/Nemesis/{path} && uv add {package}@latest
```

### Remove a package

```bash
cd /home/itadmin/code/Nemesis/{path} && uv remove {package}
```

### Sync dependencies

```bash
cd /home/itadmin/code/Nemesis/{path} && uv sync
```

## Project paths

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

## Notes

- Always use `uv`, never `pip`
- Commit both `pyproject.toml` and `uv.lock`
- Use `uv run` to execute commands in the project's environment