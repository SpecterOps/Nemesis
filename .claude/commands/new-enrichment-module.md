# /new-enrichment-module

Create a new Nemesis enrichment module with guided assistance.

## Usage

```
/new-enrichment-module <description of file type to support>
```

## Examples

```
/new-enrichment-module Windows Prefetch files (.pf)
/new-enrichment-module SSH private keys (RSA, ECDSA, Ed25519)
/new-enrichment-module AWS credentials files
/new-enrichment-module macOS Keychain database files
/new-enrichment-module KeePass database files (.kdbx)
```

## What This Command Does

This command uses the enrichment-module-builder skill to guide you through:

1. **Problem Analysis** - Understanding what data to extract
2. **Library Research** - Finding the best parsing library (with your approval)
3. **Sample Files** - Obtaining test files (with your approval)
4. **Detection Strategy** - Determining how to identify target files
5. **Implementation** - Creating the module code
6. **Testing** - Verifying the module works

## Human Approval Gates

The process includes two gates where your approval is required:

1. **Library Selection** - Review and approve the recommended parsing library
2. **Sample File** - Review and approve the source of test files

## Requirements

- The Nemesis repository should be your current working directory
- Python 3.12+ with uv installed
- For integration testing: Docker and docker-compose

## Output

A complete enrichment module including:
- `analyzer.py` with the module implementation
- `pyproject.toml` (if custom dependencies needed)
- `rules.yar` (if YARA detection needed)
- Unit tests using the test harness

## Reference

See the full skill documentation at:
`.claude/skills/enrichment-module-builder.md`

See the development guide at:
`libs/file_enrichment_modules/DEVELOPMENT_GUIDE.md`
