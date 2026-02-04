# Enrichment Module Development Guide

This guide covers how to create new enrichment modules for Nemesis. Enrichment modules analyze files and extract security-relevant information like credentials, hashes, metadata, and indicators of compromise.

There are two ways to build a new module:

- **Manual:** Follow the sections below to understand the module structure, implement the protocol, and wire up testing yourself. Best for learning how things work under the hood.
- **Claude Code skill (easy mode):** Run the `/new-enrichment-module` skill in Claude Code to get a guided, interactive workflow that handles scaffolding, library selection, implementation, and testing. Jump to [Quick Start with Claude Code](#quick-start-with-claude-code) to get started.

## Table of Contents

1. [Module Structure](#module-structure)
2. [Protocol Interface](#protocol-interface)
3. [Detection Patterns](#detection-patterns)
4. [Output Types](#output-types)
5. [Finding Categories & Severity](#finding-categories--severity)
6. [Common Patterns](#common-patterns)
7. [Testing](#testing)
8. [Quick Start with Claude Code](#quick-start-with-claude-code)
9. [Reference Modules](#reference-modules)

---

## Module Structure

Each enrichment module lives in its own directory under `libs/file_enrichment_modules/file_enrichment_modules/`:

```
libs/file_enrichment_modules/file_enrichment_modules/{module_name}/
├── analyzer.py          # Required: Main module code with create_enrichment_module()
├── pyproject.toml       # Optional: Module-specific dependencies
└── rules.yar            # Optional: YARA rules for detection
```

### Required: analyzer.py

The `analyzer.py` file must export a `create_enrichment_module()` factory function:

```python
from common.models import EnrichmentResult
from file_enrichment_modules.module_loader import EnrichmentModule

class MyAnalyzer(EnrichmentModule):
    name: str = "my_analyzer"
    dependencies: list[str] = []

    def __init__(self):
        from common.storage import StorageMinio
        self.storage = StorageMinio()
        self.asyncpg_pool = None  # Injected at runtime
        self.workflows = ["default"]

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        # Return True if this module should analyze this file
        ...

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        # Analyze the file and return results
        ...

def create_enrichment_module() -> EnrichmentModule:
    return MyAnalyzer()
```

### Optional: pyproject.toml

If your module needs dependencies not in the base `file_enrichment_modules`, create a `pyproject.toml`:

```toml
[project]
name = "my_module"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "some-library>=1.0.0",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

Dependencies are automatically installed when the module loads.

---

## Protocol Interface

All modules must implement the `EnrichmentModule` protocol:

```python
from typing import Protocol
import asyncpg
from common.models import EnrichmentResult

class EnrichmentModule(Protocol):
    name: str                           # Unique module identifier
    dependencies: list[str]             # Other modules this depends on
    asyncpg_pool: asyncpg.Pool | None   # Database pool (injected at runtime)

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should process the given file.

        Args:
            object_id: UUID of the file in the database
            file_path: Optional local path to the file (for performance)

        Returns:
            True if the module should process this file
        """
        ...

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process the file and return enrichment results.

        Args:
            object_id: UUID of the file in the database
            file_path: Optional local path to the file

        Returns:
            EnrichmentResult with findings/transforms, or None on failure
        """
        ...
```

> **Important:** In addition to the protocol fields above, modules must set `self.workflows = ["default"]` in their `__init__` method. The workflow engine filters modules by this attribute — without it, your module will load but never execute.

---

## Detection Patterns

Choose the appropriate detection pattern based on your target file type:

### 1. Magic Type / MIME Type Matching

Best for: Files with distinctive magic signatures (PE, ELF, PDF, SQLite, etc.)

```python
async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
    file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

    # Check magic type
    return "PE32" in file_enriched.magic_type

    # Or check MIME type
    return file_enriched.mime_type == "application/x-sqlite3"
```

**Example modules:** `container` (uses `is_container()` helper), `sqlite`

### 2. File Extension Matching

Best for: Files identified by extension (`.keytab`, `.pem`, `.lnk`)

```python
async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
    file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

    # Check extension
    return file_enriched.extension and file_enriched.extension.lower() in [".keytab", ".kt"]
```

**Example modules:** `keytab` (extension OR YARA), `lnk`

### 3. Filename Matching

Best for: Configuration files with specific names (`.git-credentials`, `web.config`)

```python
async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
    file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

    # Check filename + plaintext
    return file_enriched.is_plaintext and file_enriched.file_name.lower() in [
        ".git-credentials",
        ".gitcredentials"
    ]
```

**Example modules:** `gitcredentials`, `filezilla`

### 4. YARA Rule Matching

Best for: Files with distinctive binary signatures or content patterns

```python
import yara_x

class MyAnalyzer(EnrichmentModule):
    def __init__(self):
        self.yara_rule = yara_x.compile("""
rule target_file {
    strings:
        $header = { 05 02 }  // Magic bytes
    condition:
        $header at 0
}
        """)

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

        # Read bytes for YARA scan
        num_bytes = min(file_enriched.size, 1000)
        if file_path:
            with open(file_path, "rb") as f:
                file_bytes = f.read(num_bytes)
        else:
            file_bytes = self.storage.download_bytes(object_id, length=num_bytes)

        return len(self.yara_rule.scan(file_bytes).matching_rules) > 0
```

**Example modules:** `pe`, `keytab`, `dpapi_blob`

### 5. Combined Detection

For higher confidence, combine multiple detection methods:

```python
async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
    file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

    # Method 1: Extension check (fast)
    if file_enriched.file_name.lower().endswith(".keytab"):
        return True

    # Method 2: YARA verification (slower but more accurate)
    file_bytes = self.storage.download_bytes(object_id, length=1000)
    return len(self.yara_rule.scan(file_bytes).matching_rules) > 0
```

**Example modules:** `chromium_cookies` (magic + YARA + filename), `office_doc` (extension OR magic)

### 6. Process All Files

For scanners that should run on everything:

```python
async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
    return True  # Run on all files
```

**Example modules:** `yara` (scans all files with custom rules)

---

## Output Types

### EnrichmentResult Structure

```python
from common.models import EnrichmentResult, Finding, Transform

result = EnrichmentResult(
    module_name=self.name,
    results={"parsed_data": {...}},      # Raw parsed data (stored in DB)
    findings=[...],                       # Security findings
    transforms=[...],                     # Derived files
    dependencies=self.dependencies,       # Module dependencies
)
```

### 1. Results (Raw Data)

Store parsed data that doesn't fit findings/transforms:

```python
result.results = {
    "headers": {...},
    "sections": [...],
    "imports": [...],
}
```

### 2. Findings

Security-relevant discoveries with severity ratings:

```python
from common.models import Finding, FindingCategory, FindingOrigin, FileObject

# Create display data (shown in UI)
summary_markdown = "# Credentials Found\n\n* Username: admin\n* Password: ..."
display_data = FileObject(
    type="finding_summary",
    metadata={"summary": summary_markdown}
)

finding = Finding(
    category=FindingCategory.CREDENTIAL,
    finding_name="git_credentials_detected",
    origin_type=FindingOrigin.ENRICHMENT_MODULE,
    origin_name=self.name,
    object_id=file_enriched.object_id,
    severity=7,
    raw_data={"credentials": [...]},  # Structured data
    data=[display_data],               # Display objects
)

result.findings.append(finding)
```

### 3. Transforms

Derived files uploaded to storage:

```python
from common.models import Transform
import tempfile

# Create a report/derived file
with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp:
    tmp.write("# Analysis Report\n...")
    tmp.flush()
    transform_id = self.storage.upload_file(tmp.name)

transform = Transform(
    type="analysis_report",
    object_id=str(transform_id),
    metadata={
        "file_name": f"{file_enriched.file_name}_analysis.md",
        "display_type_in_dashboard": "markdown",  # or "monaco", "hex"
        "default_display": True,                   # Show by default
        "offer_as_download": False,                # Allow download
    },
)

result.transforms.append(transform)
```

---

## Finding Categories & Severity

### Categories

```python
from common.models import FindingCategory

FindingCategory.CREDENTIAL       # Usernames, passwords, tokens, API keys
FindingCategory.EXTRACTED_HASH   # Password hashes, encryption keys
FindingCategory.EXTRACTED_DATA   # Parsed configuration, metadata
FindingCategory.VULNERABILITY    # Security misconfigurations, weaknesses
FindingCategory.YARA_MATCH       # YARA rule matches
FindingCategory.PII              # Personal identifiable information
FindingCategory.MISC             # Other security findings
FindingCategory.INFORMATIONAL    # Low-priority info
```

### Severity Scale (0-10)

| Severity | Use For | Examples |
|----------|---------|----------|
| 9-10 | Critical credentials, active exploits | Domain admin creds, cleartext passwords |
| 7-8 | High-value credentials, keys | Kerberos keytabs, API tokens, SSH keys |
| 5-6 | Medium findings | YARA matches, password hashes |
| 3-4 | Low findings | Metadata disclosure, expired certs |
| 1-2 | Informational | Debug info, version strings |

---

## Common Patterns

### Getting File Metadata

```python
from common.state_helpers import get_file_enriched_async

async def process(self, object_id: str, file_path: str | None = None):
    file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

    # Available fields:
    # file_enriched.file_name      - Original filename
    # file_enriched.extension      - File extension
    # file_enriched.size           - File size in bytes
    # file_enriched.magic_type     - Magic file type
    # file_enriched.mime_type      - MIME type
    # file_enriched.is_plaintext   - True if text file
    # file_enriched.is_container   - True if archive
    # file_enriched.hashes         - Dict with md5, sha1, sha256
    # file_enriched.path           - Original path on source system
```

### Reading File Contents

```python
# Option 1: Use provided file_path (preferred for performance)
if file_path:
    with open(file_path, "rb") as f:
        content = f.read()
else:
    # Option 2: Download from storage
    with self.storage.download(object_id) as temp_file:
        with open(temp_file.name, "rb") as f:
            content = f.read()

# Option 3: Read specific bytes (for detection)
header_bytes = self.storage.download_bytes(object_id, length=1000)
```

### Standard Process Pattern

```python
async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
    try:
        file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

        if file_path:
            return self._analyze_file(file_path, file_enriched)
        else:
            with self.storage.download(object_id) as temp_file:
                return self._analyze_file(temp_file.name, file_enriched)

    except Exception:
        logger.exception(message="Error in process()", object_id=object_id)
        return None

def _analyze_file(self, file_path: str, file_enriched) -> EnrichmentResult | None:
    """Actual analysis logic (sync method)."""
    result = EnrichmentResult(module_name=self.name)
    # ... analysis code ...
    return result
```

---

## Testing

### Standalone Testing with Test Harness

Use the test harness to test modules without running Nemesis:

```python
import pytest
from tests.harness import ModuleTestHarness, FileEnrichedFactory
from file_enrichment_modules.my_module.analyzer import MyAnalyzer

@pytest.mark.asyncio
async def test_should_process_target_file():
    harness = ModuleTestHarness()

    # Register a test file
    harness.register_file(
        object_id="test-uuid",
        local_path="/path/to/test/file",
        file_enriched=FileEnrichedFactory.create_pe_file(object_id="test-uuid"),
    )

    # Test the module
    async with harness.create_module(MyAnalyzer) as module:
        assert await module.should_process("test-uuid") is True

@pytest.mark.asyncio
async def test_process_extracts_data():
    harness = ModuleTestHarness()
    harness.register_file(
        object_id="test-uuid",
        local_path="/path/to/test/file",
        file_enriched=FileEnrichedFactory.create_pe_file(object_id="test-uuid"),
    )

    async with harness.create_module(MyAnalyzer) as module:
        result = await module.process("test-uuid")

        assert result is not None
        assert result.module_name == "my_analyzer"
        assert len(result.findings) > 0
```

### Run Tests

```bash
cd libs/file_enrichment_modules
uv run pytest tests/test_my_module.py -v
```

### Integration Testing

For full integration testing with Nemesis running:

```bash
# Start dev environment
./tools/nemesis-ctl.sh start dev

# Submit test file
cd projects/cli
uv run python -m nemesis_cli.main submit --file /path/to/sample

# Check results in Hasura or via SQL
```

---

## Quick Start with Claude Code

If you have [Claude Code](https://docs.anthropic.com/en/docs/claude-code) available or another coding AI agent, the `/new-enrichment-module` skill provides a guided workflow that handles design, implementation, and testing.

### Usage

Launch Claude Code from the Nemesis project root and run:

```
/new-enrichment-module <description of file type to support>
```

Examples:

```
/new-enrichment-module Windows Prefetch files (.pf)
/new-enrichment-module SSH private keys (RSA, ECDSA, Ed25519)
/new-enrichment-module macOS Keychain database files
/new-enrichment-module KeePass database files (.kdbx)
```

### What the Skill Does

The skill walks through 8 steps, pausing at review gates for your input:

| Step | What Happens | Review Gate? |
|------|-------------|:------------:|
| 1. Problem Analysis | Gathers requirements about target file types and data to extract | |
| 2. Output Mode | Choose Findings, Parsing-Only, or Hybrid mode | Yes |
| 3. Library Research | Searches for and evaluates parsing libraries | Yes |
| 4. Sample File | Obtain or generate a test file | Yes |
| 5. Detection Strategy | Builds `should_process()` using magic types, extensions, YARA, etc. | |
| 6. Implementation | Creates `analyzer.py`, `pyproject.toml`, and `rules.yar` as needed | |
| 7. Standalone Tests | Writes and runs unit tests using the test harness | |
| 8. Integration Test | Submits the test file to a running Nemesis instance and verifies results | Yes |

The review gates let you steer library choices, output format, and test file selection before the skill commits to an approach.

### Prerequisites

For the full workflow including integration testing (step 8), start Nemesis in development mode first:

```bash
./tools/nemesis-ctl.sh start dev
```

The skill can still scaffold and unit-test a module without Nemesis running, but the final integration test requires a live instance.

### Output

When complete, the skill produces a ready-to-use module at `libs/file_enrichment_modules/file_enrichment_modules/{module_name}/` with:

- `analyzer.py` — Full module implementation with `should_process()` and `process()`
- `pyproject.toml` — Created if the module needs dependencies beyond the base package
- `rules.yar` — Created if the detection strategy uses YARA rules
- Unit tests in `tests/` using the test harness

---

## Reference Modules

These modules demonstrate the major patterns:

| Module | Detection | Output | Key Feature |
|--------|-----------|--------|-------------|
| `pe` | Magic + YARA | Findings + Transforms | Complex parsing with lief |
| `yara` | All files | Findings | YARA rule management |
| `chromium_cookies` | Magic + YARA + filename | Findings + Transforms | SQLite + DPAPI |
| `gitcredentials` | Filename + plaintext | Findings | Simple text parsing |
| `group_policy_preferences` | YARA + plaintext | Findings | XML + crypto |
| `container` | `is_container()` helper | Transforms | Archive handling |
| `keytab` | Extension OR YARA | Findings | Binary struct parsing |
| `office_doc` | Extension OR magic | Findings + Transforms | Multi-format handling |

Browse these at: `libs/file_enrichment_modules/file_enrichment_modules/`
