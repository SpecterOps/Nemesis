#!/usr/bin/env python3
"""
End-to-end integration test for enrichment modules with a running Nemesis instance.

This script:
1. Verifies Nemesis is running and healthy
2. Submits a test file via the CLI
3. Waits for enrichment processing to complete
4. Queries the database to verify results
5. Reports success or failure

Usage:
    # From the Nemesis root directory with Nemesis running:
    cd libs/file_enrichment_modules
    uv run python tests/integration/run_e2e_test.py --module gitcredentials --sample-file /path/to/sample

    # Or use the built-in test file generator:
    uv run python tests/integration/run_e2e_test.py --module gitcredentials --generate-sample
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

# Configuration
DEFAULT_API_HOST = "localhost:7443"
DEFAULT_USERNAME = "n"
DEFAULT_PASSWORD = "n"
DEFAULT_PROJECT = "e2e-test"
MAX_WAIT_SECONDS = 120
POLL_INTERVAL_SECONDS = 5


def check_nemesis_health(host: str, username: str, password: str) -> bool:
    """Check if Nemesis API is healthy."""
    try:
        url = f"https://{host}/api/health"
        response = httpx.get(url, auth=(username, password), verify=False, timeout=10)
        return response.status_code == 200
    except Exception as e:
        print(f"Health check failed: {e}")
        return False


def generate_sample_file(module_name: str, output_dir: str) -> str | None:
    """Generate a sample file for testing a specific module."""
    generators = {
        "gitcredentials": _generate_git_credentials,
        "container": _generate_zip_file,
        "keytab": _generate_keytab_file,
    }

    generator = generators.get(module_name)
    if not generator:
        print(f"No sample generator for module: {module_name}")
        print(f"Available generators: {list(generators.keys())}")
        return None

    return generator(output_dir)


def _generate_git_credentials(output_dir: str) -> str:
    """Generate a sample .git-credentials file."""
    path = os.path.join(output_dir, ".git-credentials")
    with open(path, "w") as f:
        f.write("https://testuser:e2e_test_token_12345@github.com\n")
        f.write("https://anotheruser:another_secret_token@gitlab.com/repo\n")
    return path


def _generate_zip_file(output_dir: str) -> str:
    """Generate a sample ZIP file."""
    import zipfile

    path = os.path.join(output_dir, "test_archive.zip")
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("readme.txt", "This is a test file for e2e testing.")
        zf.writestr("subdir/nested.txt", "Nested file content.")
    return path


def _generate_keytab_file(output_dir: str) -> str:
    """Generate a minimal keytab file with magic bytes."""
    path = os.path.join(output_dir, "test.keytab")
    with open(path, "wb") as f:
        # Keytab magic bytes (version 0x502)
        f.write(b"\x05\x02")
        # Minimal entry structure (will fail parsing but trigger detection)
        f.write(b"\x00" * 50)
    return path


def submit_file(
    file_path: str,
    host: str,
    username: str,
    password: str,
    project: str,
) -> str | None:
    """Submit a file to Nemesis using tools/submit.sh and return the object_id."""
    # Get the Nemesis root directory
    nemesis_root = Path(__file__).parent.parent.parent.parent.parent
    submit_script = nemesis_root / "tools" / "submit.sh"

    if not submit_script.exists():
        print(f"Submit script not found: {submit_script}")
        return None

    # Build the submit command using tools/submit.sh
    # tools/submit.sh runs the CLI via Docker with proper volume mounting
    cmd = [
        str(submit_script),
        file_path,
        "-h", host,
        "-u", username,
        "-p", password,
        "-j", project,
        "-a", "e2e-test-agent",
        "--debug",
    ]

    print(f"Submitting file: {file_path}")
    print(f"Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            cwd=str(nemesis_root),
            capture_output=True,
            text=True,
            timeout=120,  # Docker pull might take time on first run
        )

        print(f"STDOUT: {result.stdout}")
        if result.stderr:
            print(f"STDERR: {result.stderr}")

        if result.returncode != 0:
            print(f"Submit failed with return code: {result.returncode}")
            return None

        # Try to extract object_id from output
        # The CLI should print something like "Submitted: <object_id>"
        for line in result.stdout.split("\n") + result.stderr.split("\n"):
            if "object_id" in line.lower() or "submitted" in line.lower():
                # Try to find a UUID pattern
                uuid_pattern = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
                match = re.search(uuid_pattern, line, re.IGNORECASE)
                if match:
                    return match.group(0)

        # If we can't find the object_id, the file was still submitted
        # We'll need to query for it
        return "submitted"

    except subprocess.TimeoutExpired:
        print("Submit command timed out")
        return None
    except Exception as e:
        print(f"Submit failed: {e}")
        return None


def wait_for_enrichment(
    host: str,
    username: str,
    password: str,
    project: str,
    module_name: str,
    max_wait: int = MAX_WAIT_SECONDS,
) -> dict | None:
    """Wait for enrichment to complete and return the result."""
    print(f"Waiting for enrichment by module '{module_name}' (max {max_wait}s)...")

    # Query Hasura for enrichment results
    hasura_url = f"https://{host}/v1/graphql"

    # Map module names to their analyzer names
    module_to_analyzer = {
        "gitcredentials": "git_credentials_parser",
        "container": "container_analyzer",
        "keytab": "keytab_analyzer",
        "pe": "pe_analyzer",
        "yara": "yara_scanner",
    }

    analyzer_name = module_to_analyzer.get(module_name, f"{module_name}_analyzer")

    query = """
    query GetEnrichment($module_name: String!, $project: String!) {
        enrichments(
            where: {
                module_name: {_eq: $module_name},
                file: {project: {_eq: $project}}
            },
            order_by: {created_at: desc},
            limit: 1
        ) {
            id
            object_id
            module_name
            created_at
            results
        }
        findings(
            where: {
                origin_name: {_eq: $module_name},
                file: {project: {_eq: $project}}
            },
            order_by: {created_at: desc},
            limit: 10
        ) {
            id
            object_id
            category
            finding_name
            severity
            raw_data
            created_at
        }
    }
    """

    start_time = time.time()
    while time.time() - start_time < max_wait:
        try:
            response = httpx.post(
                hasura_url,
                json={
                    "query": query,
                    "variables": {
                        "module_name": analyzer_name,
                        "project": project,
                    },
                },
                auth=(username, password),
                verify=False,
                timeout=10,
            )

            if response.status_code == 200:
                data = response.json()
                if "data" in data:
                    enrichments = data["data"].get("enrichments", [])
                    findings = data["data"].get("findings", [])

                    if enrichments or findings:
                        return {
                            "enrichments": enrichments,
                            "findings": findings,
                        }

            print(f"  No results yet, waiting {POLL_INTERVAL_SECONDS}s...")
            time.sleep(POLL_INTERVAL_SECONDS)

        except Exception as e:
            print(f"  Query error: {e}, retrying...")
            time.sleep(POLL_INTERVAL_SECONDS)

    print("Timeout waiting for enrichment results")
    return None


def verify_results(results: dict, module_name: str) -> bool:
    """Verify the enrichment results are as expected."""
    enrichments = results.get("enrichments", [])
    findings = results.get("findings", [])

    print("\n" + "=" * 60)
    print("ENRICHMENT RESULTS")
    print("=" * 60)

    if enrichments:
        print(f"\nEnrichments found: {len(enrichments)}")
        for e in enrichments:
            print(f"  - Module: {e.get('module_name')}")
            print(f"    Object ID: {e.get('object_id')}")
            print(f"    Created: {e.get('created_at')}")
    else:
        print("\nNo enrichments found")

    if findings:
        print(f"\nFindings found: {len(findings)}")
        for f in findings:
            print(f"  - Name: {f.get('finding_name')}")
            print(f"    Category: {f.get('category')}")
            print(f"    Severity: {f.get('severity')}")
            print(f"    Object ID: {f.get('object_id')}")
    else:
        print("\nNo findings found")

    print("=" * 60)

    # Verify based on module
    if module_name == "gitcredentials":
        # Should have at least one credential finding
        cred_findings = [f for f in findings if f.get("category") == "credential"]
        if cred_findings:
            print("\n[PASS] Git credentials finding detected")
            return True
        else:
            print("\n[FAIL] No credential findings found")
            return False

    elif module_name == "container":
        # Should have an enrichment result
        if enrichments:
            print("\n[PASS] Container enrichment completed")
            return True
        else:
            print("\n[FAIL] No container enrichment found")
            return False

    elif module_name == "keytab":
        # Should have findings or at least an enrichment
        if findings or enrichments:
            print("\n[PASS] Keytab analysis completed")
            return True
        else:
            print("\n[FAIL] No keytab results found")
            return False

    # Default: just check if we got any results
    if enrichments or findings:
        print(f"\n[PASS] Module '{module_name}' produced results")
        return True
    else:
        print(f"\n[FAIL] Module '{module_name}' produced no results")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="End-to-end integration test for enrichment modules"
    )
    parser.add_argument(
        "--module",
        required=True,
        help="Module name to test (e.g., gitcredentials, container, keytab)",
    )
    parser.add_argument(
        "--sample-file",
        help="Path to sample file to submit",
    )
    parser.add_argument(
        "--generate-sample",
        action="store_true",
        help="Generate a sample file for the specified module",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_API_HOST,
        help=f"Nemesis API host:port (default: {DEFAULT_API_HOST})",
    )
    parser.add_argument(
        "--username",
        default=DEFAULT_USERNAME,
        help=f"API username (default: {DEFAULT_USERNAME})",
    )
    parser.add_argument(
        "--password",
        default=DEFAULT_PASSWORD,
        help=f"API password (default: {DEFAULT_PASSWORD})",
    )
    parser.add_argument(
        "--project",
        default=DEFAULT_PROJECT,
        help=f"Project name (default: {DEFAULT_PROJECT})",
    )
    parser.add_argument(
        "--max-wait",
        type=int,
        default=MAX_WAIT_SECONDS,
        help=f"Maximum seconds to wait for enrichment (default: {MAX_WAIT_SECONDS})",
    )
    parser.add_argument(
        "--skip-health-check",
        action="store_true",
        help="Skip the Nemesis health check",
    )

    args = parser.parse_args()

    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print("=" * 60)
    print("NEMESIS E2E ENRICHMENT MODULE TEST")
    print("=" * 60)
    print(f"Module: {args.module}")
    print(f"Host: {args.host}")
    print(f"Project: {args.project}")
    print()

    # Step 1: Health check
    if not args.skip_health_check:
        print("Step 1: Checking Nemesis health...")
        if not check_nemesis_health(args.host, args.username, args.password):
            print("[FAIL] Nemesis is not healthy or not running")
            print("Make sure Nemesis is running: ./tools/nemesis-ctl.sh start dev")
            sys.exit(1)
        print("[OK] Nemesis is healthy")
    else:
        print("Step 1: Skipping health check")

    # Step 2: Get or generate sample file
    print("\nStep 2: Preparing sample file...")
    sample_file = args.sample_file
    temp_dir = None

    if args.generate_sample or not sample_file:
        temp_dir = tempfile.mkdtemp(prefix="nemesis_e2e_")
        sample_file = generate_sample_file(args.module, temp_dir)
        if not sample_file:
            print("[FAIL] Could not generate sample file")
            sys.exit(1)
        print(f"[OK] Generated sample file: {sample_file}")
    else:
        if not os.path.exists(sample_file):
            print(f"[FAIL] Sample file not found: {sample_file}")
            sys.exit(1)
        print(f"[OK] Using sample file: {sample_file}")

    # Step 3: Submit file
    print("\nStep 3: Submitting file to Nemesis...")
    object_id = submit_file(
        sample_file,
        args.host,
        args.username,
        args.password,
        args.project,
    )
    if not object_id:
        print("[FAIL] File submission failed")
        sys.exit(1)
    print(f"[OK] File submitted (object_id: {object_id})")

    # Step 4: Wait for enrichment
    print(f"\nStep 4: Waiting for enrichment (max {args.max_wait}s)...")
    results = wait_for_enrichment(
        args.host,
        args.username,
        args.password,
        args.project,
        args.module,
        args.max_wait,
    )
    if not results:
        print("[FAIL] No enrichment results found within timeout")
        sys.exit(1)

    # Step 5: Verify results
    print("\nStep 5: Verifying results...")
    if verify_results(results, args.module):
        print("\n" + "=" * 60)
        print("[SUCCESS] E2E test passed!")
        print("=" * 60)
        sys.exit(0)
    else:
        print("\n" + "=" * 60)
        print("[FAILURE] E2E test failed!")
        print("=" * 60)
        sys.exit(1)


if __name__ == "__main__":
    main()
