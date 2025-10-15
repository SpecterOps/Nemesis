import asyncio
import base64
import json
import re
import time
import uuid
from datetime import datetime
from typing import Any

import psycopg
from common.helpers import sanitize_for_jsonb
from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin

logger = get_logger(__name__)


def is_jwt_expired(jwt_token: str) -> tuple[bool, dict[str, Any]]:
    """
    Decode a JWT token and check if it's expired.

    Args:
        jwt_token (str): The JWT token to check

    Returns:
        Tuple[bool, Dict[str, Any]]: A tuple containing:
            - Boolean indicating if the token is expired (True) or valid (False)
            - Dictionary containing the decoded payload
    """
    # Split the token into header, payload, and signature
    try:
        header_b64, payload_b64, signature = jwt_token.split(".")
    except Exception as e:
        logger.exception(e, message="Invalid JWT format. Expected three parts separated by dots.", jwt_token=jwt_token)
        return False, {}

    # Decode the payload
    # JWT uses base64url encoding, so we need to add padding
    payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
    # Replace URL-safe characters
    payload_b64 = payload_b64.replace("-", "+").replace("_", "/")

    try:
        payload_json = base64.b64decode(payload_b64).decode("utf-8")
        payload = json.loads(payload_json)
    except Exception as e:
        logger.exception(e, message="Error decoding JWT payload", jwt_token=jwt_token)
        return True, {}

    # Check if token is expired
    current_time = int(time.time())

    try:
        # Check for "exp" claim
        if "exp" not in payload:
            # If no expiration time is specified, token doesn't expire
            return False, payload

        return current_time > int(payload["exp"]), payload
    except Exception as e:
        logger.exception(e, message="Error processing jwt_token", jwt_token=jwt_token)
        return True, payload


def format_commit_date(commit_date_str):
    """
    Convert git commit date from Unix timestamp format to human-readable format.

    Args:
        commit_date_str (str): Commit date in format "timestamp timezone" (e.g., "1753487005 -0700")

    Returns:
        str: Human-readable date string, or original value if conversion fails
    """
    try:
        # Parse the timestamp and timezone using regex
        match = re.match(r"^(\d+)\s*([-+]\d{4})$", commit_date_str.strip())
        if not match:
            return commit_date_str

        timestamp_str, tz_offset = match.groups()
        timestamp = int(timestamp_str)

        # Convert Unix timestamp to datetime object
        dt = datetime.fromtimestamp(timestamp)

        # Format as human-readable string
        formatted_date = dt.strftime("%Y-%m-%d %H:%M:%S")

        # Add timezone offset to the formatted string
        return f"{formatted_date} {tz_offset}"

    except (ValueError, OSError, OverflowError):
        # Return original value if any conversion fails
        return commit_date_str


def create_finding_summary(match_info):
    """
    Creates a markdown summary of a single NoseyParker finding.

    Args:
        match_info (MatchInfo): The match information from NoseyParker

    Returns:
        str: A markdown formatted summary of the finding
    """
    # Generate a finding ID (using a UUID)
    finding_id = str(uuid.uuid4())

    summary = f"# {match_info.rule_name}\n\n"
    summary += "### Metadata\n"
    summary += f"* **Finding ID**: {finding_id}\n"
    summary += f"* **Rule Type**: {match_info.rule_type}\n"

    # Add file path if available
    if match_info.file_path:
        summary += f"* **File Path**: `{match_info.file_path}`\n"

    # Add git commit information if available
    if match_info.git_commit:
        summary += f"* **Git Commit**: `{match_info.git_commit.commit_id}`\n"
        summary += f"* **Author**: {match_info.git_commit.author} ({match_info.git_commit.author_email})\n"

        # Format the commit date with fallback
        formatted_date = format_commit_date(match_info.git_commit.commit_date)
        summary += f"* **Commit Date**: {formatted_date}\n"

        summary += f"* **Commit Message**: {match_info.git_commit.message[:100]}{'...' if len(match_info.git_commit.message) > 100 else ''}\n"

    summary += "\n"

    summary += "### Detected Match\n\n"
    summary += f"**Location**: Line {match_info.location.line}, Column {match_info.location.column}\n\n"
    summary += "**Match**:\n"
    summary += "```\n"
    summary += f"{match_info.matched_content}\n"
    summary += "```\n"
    summary += "**Context**:\n"
    summary += "```\n"
    summary += f"{match_info.snippet}\n"
    summary += "```\n"

    # Check if this is a JWT
    if match_info.rule_type == "jwt" or "jwt" in match_info.rule_name.lower():
        jwt_token = match_info.matched_content.strip()
        is_expired, payload = is_jwt_expired(jwt_token)

        # Add JWT expiration status and decoded payload to the summary
        summary += "\n### JWT Analysis\n\n"
        summary += f"**Expired**: {is_expired}\n\n"
        summary += "**Decoded Payload**:\n"
        summary += "```\n"
        summary += json.dumps(payload, indent=2)
        summary += "\n```\n"

    return summary


async def store_noseyparker_results(
    object_id: str, matches: list, scan_stats=None, postgres_connection_string: str = None
):
    """
    Store Nosey Parker results in the database, including creating findings.

    Args:
        object_id (str): The object ID of the file that was scanned
        matches (List[MatchInfo]): List of match information from Nosey Parker
        scan_stats (dict, optional): Statistics about the scan
        postgres_connection_string (str, optional): Database connection string
    """
    try:
        try:
            with psycopg.connect(postgres_connection_string) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE workflows
                        SET enrichments_success = array_append(enrichments_failure, %s)
                        WHERE object_id = %s
                        """,
                        ("noseyparker", object_id),
                    )
                    conn.commit()
        except Exception as db_error:
            logger.error(f"Failed to update noseyparker enrichment success in database: {str(db_error)}")

        if not matches:
            logger.debug("No matches found, nothing to store", object_id=object_id)
            return

        # Create an enrichment result to store
        enrichment_result = EnrichmentResult(module_name="noseyparker")
        enrichment_result.results = {
            "matches": [sanitize_for_jsonb(match.dict() if hasattr(match, "dict") else match) for match in matches],
            "stats": sanitize_for_jsonb(
                scan_stats.dict() if scan_stats and hasattr(scan_stats, "dict") else scan_stats
            ),
        }

        # Create findings for each match
        findings_list = []
        for match in matches:
            # Generate summary for the finding (create_finding_summary should also be updated as shown above)
            summary_markdown = create_finding_summary(match)

            # Create display data
            display_data = FileObject(
                type="finding_summary",
                metadata={"summary": sanitize_for_jsonb(summary_markdown)},  # Sanitize the summary too
            )

            # Create the finding with sanitized raw_data
            finding = Finding(
                category=FindingCategory.CREDENTIAL,
                finding_name=f"noseyparker_{match.rule_type if hasattr(match, 'rule_type') else 'match'}",
                origin_type=FindingOrigin.ENRICHMENT_MODULE,
                origin_name="noseyparker",
                object_id=object_id,
                severity=7,
                raw_data=sanitize_for_jsonb({"match": match.dict() if hasattr(match, "dict") else match}),
                data=[display_data],
            )

            findings_list.append(finding)

        # Add findings to enrichment result
        enrichment_result.findings = findings_list

        def store_in_db():
            with psycopg.connect(postgres_connection_string) as conn:
                with conn.cursor() as cur:
                    # Store main enrichment result
                    results_escaped = json.dumps(sanitize_for_jsonb(enrichment_result.model_dump(mode="json")))
                    cur.execute(
                        """
                        INSERT INTO enrichments (object_id, module_name, result_data)
                        VALUES (%s, %s, %s)
                        """,
                        (object_id, "noseyparker", results_escaped),
                    )

                    # Store any findings
                    for finding in findings_list:
                        # Convert each FileObject to a JSON string
                        data_as_strings = []
                        for obj in finding.data:
                            # Convert the model to a dict first
                            if hasattr(obj, "model_dump"):
                                obj_dict = obj.model_dump()
                            else:
                                obj_dict = obj
                            sanitized_obj = sanitize_for_jsonb(obj_dict)
                            data_as_strings.append(json.dumps(sanitized_obj))

                        cur.execute(
                            """
                            INSERT INTO findings (
                                finding_name, category, severity, object_id,
                                origin_type, origin_name, raw_data, data
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                finding.finding_name,
                                finding.category,
                                finding.severity,
                                object_id,
                                finding.origin_type,
                                finding.origin_name,
                                json.dumps(sanitize_for_jsonb(finding.raw_data)),
                                json.dumps(data_as_strings),  # Store as array of JSON strings
                            ),
                        )

                conn.commit()

        # Run database operations in thread
        await asyncio.to_thread(store_in_db)

        logger.info("Successfully stored NoseyParker results", object_id=object_id, match_count=len(matches))

        return enrichment_result

    except Exception as e:
        logger.exception(e, message="Error storing NoseyParker results", object_id=object_id)
        return None
