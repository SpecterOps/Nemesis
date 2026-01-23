# Enrichment Module Builder Skill

This skill guides the creation of new Nemesis enrichment modules from start to finish.

**CRITICAL: At each user approval gate (Steps 2, 3, 4, and 8), you MUST use the `AskUserQuestion` tool to prompt for approval before proceeding to the next step. Do NOT continue past a gate until the user has explicitly approved.**

## Overview

Enrichment modules analyze files and extract security-relevant information like credentials, hashes, metadata, and indicators of compromise. This skill walks through the complete process:

1. Problem Analysis
2. Module Output Mode (with user approval gate)
3. Library Research (with user approval gate)
4. Sample File Acquisition (with user approval gate)
5. Detection Strategy
6. Module Implementation
7. Standalone Testing
8. Integration Testing (with user approval gate) - **REQUIRED**

## Reference Documentation

Before starting, review:
- **Development Guide:** `libs/file_enrichment_modules/DEVELOPMENT_GUIDE.md`
- **Test Harness:** `libs/file_enrichment_modules/tests/harness/`

## Reference Modules

Use these 8 modules as implementation references - they cover all major patterns:

| Module | Detection Pattern | Key Feature |
|--------|------------------|-------------|
| `pe` | Magic + YARA | Complex parsing with lief |
| `yara` | All files | YARA rule management |
| `chromium_cookies` | Magic + YARA + filename | Database + DPAPI |
| `gitcredentials` | Filename + plaintext | Simple text parsing |
| `group_policy_preferences` | YARA + plaintext | XML + crypto |
| `container` | is_container() | Archive handling |
| `keytab` | Extension OR YARA | Binary struct parsing |
| `office_doc` | Extension OR magic | Multi-format handling |

Paths: `libs/file_enrichment_modules/file_enrichment_modules/{module_name}/`

---

## Step 1: Problem Analysis

Gather requirements from the user:

1. **Target file type/format:** What files should this module process?
2. **Data to extract:** What information should be extracted?
   - Credentials (usernames, passwords, tokens)
   - Hashes (password hashes, encryption keys)
   - Metadata (configuration, version info)
   - Security indicators
3. **Finding categories:** Which apply?
   - CREDENTIAL, EXTRACTED_HASH, EXTRACTED_DATA, VULNERABILITY, YARA_MATCH, PII, MISC, INFORMATIONAL
4. **Severity level:** 0-10 based on security impact

**Questions to ask:**
- What file types/extensions/names identify target files?
- What specific data fields need extraction?
- Are there multiple variants of this file format?
- Should the module produce transforms (derived files) in addition to findings?

---

## Step 2: Module Output Mode [GATE 1]

Determine what the module should produce as output:

### Output Mode Options

1. **Findings Mode:** The module extracts security-relevant data and generates findings
   - Use when: Extracting credentials, hashes, vulnerabilities, or other actionable security data
   - Output: Findings with categories (CREDENTIAL, EXTRACTED_HASH, etc.) and severity levels
   - Example modules: `chromium_cookies`, `gitcredentials`, `group_policy_preferences`

2. **Parsing-Only Mode:** The module parses the file and stores structured data without generating findings
   - Use when: Extracting metadata, configuration, or informational data for display/search
   - Output: Structured results stored in the database, no findings generated
   - Example modules: `pe` (extracts PE metadata), `office_doc` (extracts document metadata)

3. **Hybrid Mode:** The module parses data AND generates findings for specific conditions
   - Use when: Most data is informational, but certain patterns warrant findings
   - Output: Structured results plus conditional findings
   - Example: Parse all PE metadata, but generate finding only if unsigned or suspicious

### Present to User

**Format your recommendation:**

```
## Module Output Mode for {file_type} Module

Based on the data to be extracted, I recommend:

### Recommended: {Findings Mode | Parsing-Only Mode | Hybrid Mode}

**Rationale:** {why this mode fits the use case}

### What this means:
- {description of what will be produced}
- {how data will be stored/displayed}
- {whether alerts will be generated}

### Alternative consideration:
{brief note on why other modes might or might not apply}

**Do you approve this output mode, or would you prefer a different approach?**
```

**STOP: Use `AskUserQuestion` tool with the three output mode options (Findings Mode, Parsing-Only Mode, Hybrid Mode) to get user approval before proceeding to Step 3.**

---

## Step 3: Library Research [GATE 2]

Search for parsing libraries before implementation:

### Research Steps

1. **Search PyPI** for relevant parsing libraries:
   - Search terms: "{file_format} parser python", "{file_format} python library"
   - Evaluate: popularity (downloads), maintenance status, API quality

2. **Search GitHub** for reference implementations:
   - Look for existing parsers, security tools, CTF write-ups
   - Check for format documentation

3. **Evaluate options:**
   - Does the library handle the specific format variant?
   - Is it actively maintained?
   - Does it have security-relevant features?
   - What's the API complexity?

### Present to User

**Format your recommendation:**

```
## Library Recommendation for {file_type} Module

### Recommended: {library_name}
- **PyPI:** https://pypi.org/project/{library_name}/
- **GitHub:** {github_url}
- **Why:** {reasons - API quality, maintenance, features}
- **Downloads:** {monthly_downloads}

### Alternatives Considered:
1. {alt_library_1} - {why_not_chosen}
2. {alt_library_2} - {why_not_chosen}

### Manual Parsing
If no good library exists, we can implement manual parsing using:
- struct module for binary formats
- xml.etree for XML
- Regular expressions for text patterns

**Do you approve this library choice, or would you prefer an alternative?**
```

**STOP: Use `AskUserQuestion` tool to present the recommended library and alternatives to get user approval before proceeding to Step 4.**

---

## Step 4: Sample File Acquisition [GATE 3]

Obtain test files for development and testing:

### Search Locations

1. **Public GitHub repos:** Search for sample files (<100MB)
   - Query: `"{file_extension}" OR "{file_type} sample"`
   - Look in security research repos, CTF repos, test fixtures

2. **Sample file repositories:**
   - file-examples.com
   - filesamples.com
   - Sample files in related tool repos

3. **Generate synthetic files:**
   - If no public samples exist, create test files
   - Document the generation method

### Present to User

**Format your recommendation:**

```
## Sample File for {file_type} Module

### Source: {source_description}
- **URL/Location:** {url_or_path}
- **File:** {filename}
- **Size:** {size}
- **Why suitable:** {reasons}

### Alternative sources if needed:
1. {alt_source_1}
2. {alt_source_2}

### Synthetic generation (if no public samples):
{description of how to create test file}

**Do you approve this sample file source, or do you have an alternative?**
```

**STOP: Use `AskUserQuestion` tool to present the sample file options to get user approval before proceeding to Step 5.**

---

## Step 5: Detection Strategy

Determine how `should_process()` will identify target files:

### Analyze the Sample File

1. **Check magic type:** Run `file` command on sample
2. **Check MIME type:** What MIME type does Nemesis assign?
3. **Identify binary signatures:** Look for distinctive headers/magic bytes
4. **Check filenames/extensions:** Are there standard naming conventions?

### Choose Detection Method

Based on analysis, select from:

1. **Magic/MIME type:** For files with distinctive signatures
2. **File extension:** For convention-based identification
3. **Filename:** For config files with specific names
4. **YARA rule:** For binary patterns
5. **Combined:** For higher confidence

### Generate YARA Rule (if needed)

If the file has distinctive binary signatures:

```yara
rule {file_type}_file {
    meta:
        description = "Detects {file_type} files"

    strings:
        $header = { XX XX XX XX }  // Magic bytes

    condition:
        $header at 0
}
```

---

## Step 6: Module Implementation

Create the module structure:

### 1. Create Directory

```bash
mkdir -p libs/file_enrichment_modules/file_enrichment_modules/{module_name}
```

### 2. Create analyzer.py

Use this template, adapting based on the reference module that matches your pattern:

```python
# enrichment_modules/{module_name}/analyzer.py
from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)


class {ModuleName}Analyzer(EnrichmentModule):
    name: str = "{module_name}_analyzer"
    dependencies: list[str] = []

    def __init__(self):
        self.storage = StorageMinio()
        self.asyncpg_pool = None
        self.workflows = ["default"]

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should process the file."""
        file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

        # TODO: Implement detection logic
        return False

    def _analyze_file(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze the file and extract data."""
        result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        try:
            # TODO: Implement parsing logic

            # Create findings if relevant data found
            # Create transforms for derived files

            return result

        except Exception:
            logger.exception(message=f"Error analyzing {file_enriched.file_name}")
            return None

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process the file."""
        try:
            file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

            if file_path:
                return self._analyze_file(file_path, file_enriched)
            else:
                with self.storage.download(object_id) as temp_file:
                    return self._analyze_file(temp_file.name, file_enriched)

        except Exception:
            logger.exception(message="Error in process()")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return {ModuleName}Analyzer()
```

### 3. Create pyproject.toml (if custom deps needed)

```toml
[project]
name = "{module_name}"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "{library_name}>=X.Y.Z",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

### 4. Create YARA rules (if using YARA detection)

Create `rules.yar` with detection rules.

---

## Step 7: Standalone Testing

Create and run tests using the test harness:

### Create Test File

```python
# tests/test_{module_name}.py
import pytest
from tests.harness import ModuleTestHarness, FileEnrichedFactory
from file_enrichment_modules.{module_name}.analyzer import {ModuleName}Analyzer


class Test{ModuleName}Analyzer:
    """Tests for {ModuleName}Analyzer."""

    @pytest.mark.asyncio
    async def test_should_process_target_file(self):
        """Test that should_process returns True for target files."""
        harness = ModuleTestHarness()

        harness.register_file(
            object_id="test-uuid",
            local_path="/path/to/sample/file",
            file_enriched=FileEnrichedFactory.create(
                object_id="test-uuid",
                file_name="sample.ext",
                magic_type="expected magic type",
                # ... other fields
            ),
        )

        async with harness.create_module({ModuleName}Analyzer) as module:
            result = await module.should_process("test-uuid")
            assert result is True

    @pytest.mark.asyncio
    async def test_should_not_process_unrelated_file(self):
        """Test that should_process returns False for unrelated files."""
        harness = ModuleTestHarness()

        harness.register_file(
            object_id="test-uuid",
            local_path="/path/to/unrelated/file",
            file_enriched=FileEnrichedFactory.create_plaintext_file(
                object_id="test-uuid",
                file_name="readme.txt",
            ),
        )

        async with harness.create_module({ModuleName}Analyzer) as module:
            result = await module.should_process("test-uuid")
            assert result is False

    @pytest.mark.asyncio
    async def test_process_extracts_expected_data(self):
        """Test that process extracts the expected data."""
        harness = ModuleTestHarness()

        harness.register_file(
            object_id="test-uuid",
            local_path="/path/to/sample/file",
            file_enriched=FileEnrichedFactory.create(...),
        )

        async with harness.create_module({ModuleName}Analyzer) as module:
            result = await module.process("test-uuid")

            assert result is not None
            assert result.module_name == "{module_name}_analyzer"
            # Assert on findings
            # Assert on transforms
            # Assert on results
```

### Run Tests

```bash
cd libs/file_enrichment_modules
uv run pytest tests/test_{module_name}.py -v
```

### Verification Checklist

- [ ] `should_process()` returns True for target files
- [ ] `should_process()` returns False for non-target files
- [ ] `process()` extracts expected data
- [ ] Findings have correct categories and severity
- [ ] Transforms are created properly (if applicable)
- [ ] Error handling works correctly

---

## Step 8: Integration Testing [GATE 4]

**This step is REQUIRED.** You MUST execute the E2E integration test, not just print instructions.

### Ask User to Confirm Nemesis is Running

Before proceeding, ask the user to confirm their Nemesis instance is ready:

```
## Integration Testing Ready Check

The module implementation and unit tests are complete. Now we need to run end-to-end integration testing against a live Nemesis instance.

**Please confirm:**
1. Is Nemesis dev environment running? (Start with: `./tools/nemesis-ctl.sh start dev`)
2. What is the Nemesis host? (default: `localhost:7443`)

Once confirmed, I will:
1. Verify the Nemesis instance is healthy
2. Submit a test file to the running instance
3. Wait for enrichment processing to complete
4. Query the database to verify results
5. Report the E2E test outcome

**Reply with the host (or press enter for localhost:7443) to proceed with integration testing.**
```

**STOP: Use `AskUserQuestion` tool to confirm Nemesis is running and get the host before proceeding with E2E testing.**

### Execute E2E Testing

Once the user confirms Nemesis is running, execute these steps IN ORDER:

#### 1. Verify Nemesis Health

Run a health check against the provided host:

```bash
curl -k -s "https://{host}/api/health" | head -20
```

If the health check fails, inform the user and ask them to verify Nemesis is running.

#### 2. Check Module is Loaded

Verify the new module appears in the file-enrichment container logs:

```bash
docker compose logs file-enrichment 2>&1 | grep -i "{module_name}" | tail -10
```

Look for successful module loading. If not found, check for import errors.

#### 3. Submit Test File

Use the test fixture file created during standalone testing. Execute the submission:

```bash
./tools/submit.sh {path_to_test_fixture_file} \
    -h {host} \
    -u n -p n \
    -j test-project \
    --debug
```

Capture the `object_id` from the submission output - you will need it to verify results.

#### 4. Wait for Processing

Wait for enrichment to complete (poll every 5 seconds, up to 60 seconds):

```bash
# Check enrichment status
docker exec -i $(docker compose ps -q postgres) psql -U postgres -d nemesis -c \
    "SELECT module_name, status, created_at FROM enrichments WHERE object_id = '{object_id}' ORDER BY created_at DESC;"
```

#### 5. Verify Results

Query the database to confirm the module produced expected output:

```bash
# Check enrichment record exists
docker exec -i $(docker compose ps -q postgres) psql -U postgres -d nemesis -c \
    "SELECT module_name, status FROM enrichments WHERE module_name = '{module_name}_analyzer' ORDER BY created_at DESC LIMIT 1;"

# Check findings were created (if applicable)
docker exec -i $(docker compose ps -q postgres) psql -U postgres -d nemesis -c \
    "SELECT id, category, severity, value FROM findings WHERE origin_name = '{module_name}_analyzer' ORDER BY created_at DESC LIMIT 10;"
```

#### 6. Report Results

After executing the above steps, report the E2E test outcome to the user:

```
## E2E Integration Test Results

### Status: {PASS | FAIL}

### Verification Steps:
- [ ] Nemesis health check: {PASS/FAIL}
- [ ] Module loaded in file-enrichment: {PASS/FAIL}
- [ ] File submission successful: {PASS/FAIL}
- [ ] Enrichment record created: {PASS/FAIL}
- [ ] Findings created (if applicable): {PASS/FAIL - count: N}
- [ ] No errors in logs: {PASS/FAIL}

### Details:
{Summary of what was found, any errors encountered}

### Object ID: {object_id}
```

If any step fails, provide troubleshooting guidance and offer to re-run after the user fixes the issue.

---

## Completion Checklist

Before considering the module complete, ALL items must be checked:

- [ ] **Code:** analyzer.py implements EnrichmentModule protocol
- [ ] **Detection:** should_process() correctly identifies target files
- [ ] **Extraction:** process() extracts relevant security data
- [ ] **Findings:** Correct categories and severity levels
- [ ] **Tests:** Standalone tests pass
- [ ] **Dependencies:** pyproject.toml created if needed
- [ ] **YARA:** rules.yar created if using YARA detection
- [ ] **Integration (REQUIRED):** E2E test executed against running Nemesis instance and PASSED

**IMPORTANT:** Do NOT mark the module as complete until Step 8 E2E integration testing has been executed and passed.

---

## Troubleshooting

### Module Not Loading

1. Check for syntax errors in analyzer.py
2. Verify `create_enrichment_module()` function exists
3. Check container logs for import errors

### Detection Not Working

1. Verify file_enriched fields match expectations
2. Test YARA rules separately with yara-x
3. Add debug logging to should_process()

### Parsing Errors

1. Check library compatibility with file format variant
2. Add defensive error handling
3. Test with multiple sample files

### Tests Failing

1. Verify test file path is correct
2. Check FileEnrichedFactory fields match module expectations
3. Ensure harness is properly registering files
