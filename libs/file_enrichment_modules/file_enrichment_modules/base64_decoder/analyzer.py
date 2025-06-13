# enrichment_modules/base64_decoder/analyzer.py
import base64
import json
import re
import tempfile
from typing import List, Dict, Any, Tuple

import structlog
from common.models import EnrichmentResult, File, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched
from common.helpers import is_plaintext
from common.storage import StorageMinio
from dapr.clients import DaprClient

from file_enrichment_modules.module_loader import EnrichmentModule

logger = structlog.get_logger(module=__name__)


class Base64DecoderAnalyzer(EnrichmentModule):
    def __init__(self, max_extractions: int = 30):
        super().__init__("base64_decoder")
        self.storage = StorageMinio()
        # the workflows this module should automatically run in
        self.workflows = ["default"]
        # Maximum number of base64 extractions to process
        self.max_extractions = max_extractions
        self.size_limit = 5000000  # only check the first 5 megs for base64 strings, for efficiency

        # Multi-tier pattern matching for efficiency
        # Tier 1: Short base64 (8-200 chars) - common for passwords, tokens, etc.
        self.short_base64_pattern = re.compile(r'\b([A-Za-z0-9+/]{8,200}={0,2})\b')

        # Tier 2: Long base64 (200+ chars) - files, certificates, etc.
        # Allow whitespace/newlines within long sequences
        self.long_base64_pattern = re.compile(r'([A-Za-z0-9+/\s]{200,}={0,2})')

    def should_process(self, object_id: str) -> bool:
        """Determine if this module should run on plaintext files."""

        # there are some performance issues, so we're disabling this one for now
        return False

        file_enriched = get_file_enriched(object_id)

        # skip carving if the file is not plaintext, of if it's an extracted strings.txt
        if not file_enriched.is_plaintext or ((file_enriched.file_name.lower() == "strings.txt") and file_enriched.originating_object_id):
            return False

        if file_enriched.size > self.size_limit:
            logger.warning(
                f"[base64_decoder] file {file_enriched.path} ({file_enriched.object_id} / {file_enriched.size} bytes) exceeds the size limit of {self.size_limit} bytes, only analyzing the first {self.size_limit} bytes"
            )

        try:
            num_bytes = file_enriched.size if file_enriched.size < self.size_limit else self.size_limit
            file_bytes = self.storage.download_bytes(file_enriched.object_id, length=num_bytes)
            file_content = file_bytes.decode('utf-8', errors='ignore')

            # Quick check using efficient patterns
            should_run = (self.short_base64_pattern.search(file_content) is not None or
                         self.long_base64_pattern.search(file_content) is not None)

            logger.debug(f"[base64_decoder] should_run: {should_run}")
            return should_run
        except Exception as e:
            logger.exception(f"Error checking file for base64 content: {e}")
            return False

    def _is_likely_base64(self, candidate: str) -> bool:
        """Quick heuristic checks before expensive validation"""
        # Must be proper length (multiple of 4)
        if len(candidate) % 4 != 0:
            return False

        # Check character diversity for shorter strings to avoid false positives
        if len(candidate) < 100:
            has_upper = any(c.isupper() for c in candidate)
            has_lower = any(c.islower() for c in candidate)
            has_digit = any(c.isdigit() for c in candidate)
            has_special = '+' in candidate or '/' in candidate

            # Need at least 2 types of characters for diversity
            char_types = sum([has_upper, has_lower, has_digit, has_special])
            if char_types < 2:
                return False

        # Avoid obvious English words and common patterns
        lower_candidate = candidate.lower()
        if lower_candidate in {'password', 'username', 'admin', 'test', 'example', 'sample', 'default', 'null', 'true', 'false'}:
            return False

        # Avoid repetitive patterns
        if len(set(candidate)) < len(candidate) / 4:  # Too repetitive
            return False

        return True

    def _try_decode_base64(self, encoded_str: str) -> Tuple[bool, bytes]:
        """Attempt to decode a base64 string with validation."""
        try:
            # Clean the string (remove whitespace for long sequences)
            cleaned_str = re.sub(r'\s+', '', encoded_str)

            # Quick validation before decode attempt
            if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', cleaned_str):
                return False, b""

            decoded = base64.b64decode(cleaned_str, validate=True)

            # Must produce some meaningful output
            if len(decoded) == 0:
                return False, b""

            return True, decoded
        except Exception:
            return False, b""

    def _remove_overlaps(self, matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove overlapping matches, keeping longer/better ones"""
        if not matches:
            return matches

        # Sort by start position
        sorted_matches = sorted(matches, key=lambda x: x['start'])
        filtered = [sorted_matches[0]]

        for current in sorted_matches[1:]:
            last = filtered[-1]

            # Check for overlap
            if current['start'] < last['end']:
                # Keep the longer match, or the one with better characteristics
                if (current['length'] > last['length'] or
                    (current['length'] == last['length'] and current.get('has_special_chars', False))):
                    filtered[-1] = current
            else:
                filtered.append(current)

        return filtered

    def _extract_base64_candidates(self, content: str) -> List[Dict[str, Any]]:
        """Extract potential base64 encoded strings from content with efficient filtering."""

        candidates = []
        max_initial_matches = 2 * self.max_extractions

        # Process short patterns first (more common, faster to validate)
        for match in self.short_base64_pattern.finditer(content):
            candidate_str = match.group(1)

            if self._is_likely_base64(candidate_str):
                candidates.append({
                    'value': candidate_str,
                    'start': match.start(1),
                    'end': match.end(1),
                    'length': len(candidate_str),
                    'type': 'short',
                    'has_special_chars': '+' in candidate_str or '/' in candidate_str
                })

            if len(candidates) >= max_initial_matches:
                logger.warning(f"[base64_decoder] Reached initial extraction limit of {max_initial_matches} in short patterns")
                break

        # Process long patterns if we haven't hit the limit
        if len(candidates) < max_initial_matches:
            for match in self.long_base64_pattern.finditer(content):
                candidate_str = re.sub(r'\s+', '', match.group(1))  # Clean whitespace

                if len(candidate_str) >= 200 and self._is_likely_base64(candidate_str):
                    candidates.append({
                        'value': candidate_str,
                        'start': match.start(1),
                        'end': match.end(1),
                        'length': len(candidate_str),
                        'type': 'long',
                        'has_special_chars': '+' in candidate_str or '/' in candidate_str
                    })

                if len(candidates) >= max_initial_matches:
                    logger.warning(f"[base64_decoder] Reached initial extraction limit of {max_initial_matches} including long patterns")
                    break

        # Remove overlapping matches
        candidates = self._remove_overlaps(candidates)

        logger.info(f"[base64_decoder] Extracted {len(candidates)} base64 candidates after filtering (target: up to {max_initial_matches})")
        return candidates

    def process(self, object_id: str) -> EnrichmentResult | None:
        """Process file to find and decode base64 content."""
        try:
            file_enriched = get_file_enriched(object_id)
            enrichment_result = EnrichmentResult(module_name=self.name)

            # Download and read the file content (respect size limit)
            num_bytes = file_enriched.size if file_enriched.size < self.size_limit else self.size_limit
            file_bytes = self.storage.download_bytes(file_enriched.object_id, length=num_bytes)
            file_content = file_bytes.decode('utf-8', errors='ignore')

            # Extract potential base64 candidates with efficient filtering
            base64_candidates = self._extract_base64_candidates(file_content)

            if not base64_candidates:
                logger.info(f"[base64_decoder] No base64 candidates found in {file_enriched.object_id}")
                return None

            logger.info(f"[base64_decoder] Processing {len(base64_candidates)} base64 candidates, targeting up to {self.max_extractions} successful decodes")

            decoded_blobs = []
            modified_content = file_content
            uploaded_files = []

            # Process candidates until we reach max_extractions successful decodes
            successful_decodes = 0
            for candidate_info in base64_candidates:
                # Stop processing if we've reached our successful decode limit
                if successful_decodes >= self.max_extractions:
                    logger.warning(f"[base64_decoder] Reached maximum successful decodes limit ({self.max_extractions}), stopping processing")
                    break

                candidate = candidate_info['value']
                upload_file = False
                success, decoded_bytes = self._try_decode_base64(candidate)

                if not success:
                    continue  # Skip failed decodes, don't count toward limit

                # Count this as a successful decode
                successful_decodes += 1

                bytes_are_plaintext = is_plaintext(decoded_bytes)

                blob_info = {
                    "original_base64": candidate,
                    "decoded_length": len(decoded_bytes),
                    "is_plaintext": bytes_are_plaintext,
                    "candidate_type": candidate_info['type'],
                    "start_position": candidate_info['start'],
                }

                # If decoded text is plaintext and short, replace in content
                if bytes_are_plaintext:
                    try:
                        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                        if len(decoded_str) < 100:
                            replacement = f"[b64dec(val): {decoded_str}]"
                            modified_content = modified_content.replace(candidate, replacement, 1)
                            blob_info["action"] = "replaced_inline"
                            blob_info["replacement"] = replacement
                        else:
                            upload_file = True
                    except Exception as e:
                        logger.error(f"Error decoding b64 content to UTF-8: {e}")

                # If the file was a large plaintext or the decoded bytes have a length of at least 50, upload as separate file
                if upload_file or (not bytes_are_plaintext and len(decoded_bytes) > 50):
                    try:
                        with tempfile.NamedTemporaryFile(mode="wb") as tmp:
                            tmp.write(decoded_bytes)
                            tmp.flush()
                            decoded_object_id = self.storage.upload_file(tmp.name)

                        # Create File message for the decoded content
                        file_message = File(
                            object_id=decoded_object_id,
                            agent_id=file_enriched.agent_id,
                            project=file_enriched.project,
                            timestamp=file_enriched.timestamp,
                            expiration=file_enriched.expiration,
                            path=f"{file_enriched.path}/b64dec",
                            originating_object_id=file_enriched.object_id,
                            nesting_level=(file_enriched.nesting_level or 0) + 1,
                        )

                        # Publish the file message
                        with DaprClient() as dapr_client:
                            data = json.dumps(file_message.model_dump(exclude_unset=True, mode="json"))
                            dapr_client.publish_event(
                                pubsub_name="pubsub",
                                topic_name="file",
                                data=data,
                                data_content_type="application/json",
                            )

                        blob_info["action"] = "uploaded_as_file"
                        blob_info["uploaded_object_id"] = decoded_object_id
                        uploaded_files.append(decoded_object_id)

                        logger.info(
                            f"[base64_decoder] Uploaded decoded content as separate file",
                            uploaded_object_id=decoded_object_id,
                            originating_object_id=file_enriched.object_id,
                            candidate_type=candidate_info['type']
                        )

                    except Exception as e:
                        logger.exception(f"Error uploading decoded content: {e}")
                        blob_info["action"] = "upload_failed"
                        blob_info["error"] = str(e)

                decoded_blobs.append(blob_info)

            # If we made any modifications, upload the modified content
            transforms = []
            if modified_content != file_content:
                try:
                    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as tmp:
                        tmp.write(modified_content)
                        tmp.flush()
                        modified_object_id = self.storage.upload_file(tmp.name)

                    transform = Transform(
                        type="base64_decode_inline",
                        object_id=modified_object_id,
                        metadata={
                            "file_name": f"{file_enriched.file_name}_b64decoded.{file_enriched.extension}",
                            "display_type_in_dashboard": "monaco",
                            "display_title": "Base64 Decoded (Inline Replacements)",
                        },
                    )
                    transforms.append(transform)

                    logger.info(
                        f"[base64_decoder] Created modified file with inline replacements",
                        modified_object_id=modified_object_id,
                        originating_object_id=file_enriched.object_id,
                    )

                except Exception as e:
                    logger.exception(f"Error creating modified file: {e}")

            # Store results with enhanced statistics
            enrichment_result.results = {
                "decoded_blobs": decoded_blobs,
                "total_candidates": len(base64_candidates),
                "successfully_decoded": len(decoded_blobs),
                "uploaded_files": uploaded_files,
                "inline_replacements": sum(1 for blob in decoded_blobs if blob.get("action") == "replaced_inline"),
                "max_extractions_limit": self.max_extractions,
                "candidates_processed": successful_decodes,
                "short_candidates": sum(1 for c in base64_candidates if c['type'] == 'short'),
                "long_candidates": sum(1 for c in base64_candidates if c['type'] == 'long'),
                "file_size_processed": num_bytes,
                "processing_efficiency": {
                    "candidates_found": len(base64_candidates),
                    "successful_decode_rate": len(decoded_blobs) / len(base64_candidates) if base64_candidates else 0,
                    "bytes_processed": num_bytes
                }
            }

            if transforms:
                enrichment_result.transforms = transforms

            return enrichment_result

        except Exception as e:
            logger.exception(e, message="Error in base64_decoder process()", file_object_id=object_id)
            return None


def create_enrichment_module() -> EnrichmentModule:
    return Base64DecoderAnalyzer()