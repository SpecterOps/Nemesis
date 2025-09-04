# src/workflow/file_feature_extractor.py
import math

# from pathlib import Path
import ntpath
import re
import statistics
from collections import Counter
from datetime import datetime

from common.logger import get_logger

# logger = structlog.get_logger(module=__name__)
logger = get_logger(__name__)
# unix epoch for a default
DEFAULT_TIMESTAMP = datetime(1970, 1, 1, 0, 0, 0, tzinfo=datetime.now().astimezone().tzinfo)


class FileFeatureExtractor:
    def __init__(self):
        self.version = "1.0"

        self.api_service_keywords = {
            "api",
            "endpoint",
            "service",
            "server",
            "gateway",
            "proxy",
            "rest",
            "grpc",
            "graphql",
            "webhook",
            "callback",
            "interface",
        }

        self.database_keywords = {
            "database",
            "db",
            "sql",
            "mongo",
            "redis",
            "postgres",
            "mysql",
            "mariadb",
            "oracle",
            "nosql",
            "jdbc",
            "odbc",
            "cursor",
            "query",
            "elasticsearch",
            "dynamodb",
            "cassandra",
        }

        self.config_keywords = {
            "config",
            "settings",
            "conf",
            "properties",
            "env",
            "configuration",
            "parameters",
            "options",
            "prefs",
            "preferences",
            "setup",
            "profile",
            "default",
            "constants",
            "vars",
            "variables",
        }

        self.infrastructure_keywords = {
            "docker",
            "kubernetes",
            "k8s",
            "cluster",
            "node",
            "instance",
            "container",
            "pod",
            "deployment",
            "terraform",
            "ansible",
            "chef",
            "puppet",
            "vagrant",
            "helm",
            "swarm",
            "compose",
            "jenkins",
        }

        self.dev_env_keywords = {
            "dev",
            "development",
            "staging",
            "prod",
            "production",
            "test",
            "debug",
            "log",
            "trace",
            "qa",
            "uat",
            "sandbox",
            "integration",
            "hotfix",
            "build",
            "release",
            "snapshot",
            "beta",
            "alpha",
        }

        self.network_keywords = {
            "dns",
            "dhcp",
            "smtp",
            "http",
            "https",
            "ftp",
            "ssh",
            "sftp",
            "vpn",
            "network",
            "firewall",
            "proxy",
            "tcp",
            "udp",
            "ip",
            "port",
            "ssl",
            "tls",
            "ldap",
            "kerberos",
        }

        self.authentication_keywords = {
            "password",
            "passwd",
            "pwd",
            "auth",
            "authentication",
            "login",
            "credential",
            "credentials",
            "creds",
            "authenticated",
            "authenticator",
            "passphrase",
            "passcode",
            "pin",
        }

        self.key_keywords = {
            "key",
            "keys",
            "apikey",
            "api_key",
            "secret_key",
            "private_key",
            "public_key",
            "keypair",
            "keyring",
            "masterkey",
            "signing_key",
            "encryption_key",
            "decryption_key",
            "ssh_key",
            "gpg_key",
        }

        self.token_keywords = {
            "token",
            "jwt",
            "bearer",
            "oauth",
            "refresh_token",
            "access_token",
            "session_token",
            "id_token",
            "saml",
            "assertion",
            "ticket",
            "authorization_token",
            "temporary_token",
            "nonce",
        }

        self.secret_keywords = {
            "secret",
            "hidden",
            "confidential",
            "private",
            "restricted",
            "sensitive",
            "secure",
            "classified",
            "proprietary",
            "protected",
            "internal",
            "privileged",
            "undisclosed",
        }

        self.certificate_keywords = {
            "certificate",
            "cert",
            "crt",
            "pem",
            "p12",
            "pfx",
            "keystore",
            "truststore",
            "ca_cert",
            "client_cert",
            "server_cert",
            "x509",
            "ssl_cert",
            "root_ca",
            "intermediate_ca",
        }

        self.identity_keywords = {
            "identity",
            "account",
            "user",
            "username",
            "email",
            "userid",
            "uid",
            "admin",
            "root",
            "superuser",
            "administrator",
            "sysadmin",
            "webmaster",
            "manager",
            "owner",
            "moderator",
        }

        self.permission_keywords = {
            "permission",
            "acl",
            "access",
            "role",
            "privilege",
            "grant",
            "authorization",
            "scope",
            "policy",
            "rights",
            "allow",
            "deny",
            "sudo",
            "chmod",
            "umask",
            "group",
            "rbac",
        }

        # Common source code directories
        self.source_code_dirs = {
            "www_root",
            "wwwroot",
            "inetpub",
            "public_html",
            "webroot",
            "src",
            "source",
            "app",
            "application",
            "backend",
            "frontend",
        }

        # Build and output directories
        self.build_output_dirs = {
            "build",
            "dist",
            "target",
            "out",
            "output",
            "bin",
            "obj",
            "release",
            "debug",
            "builds",
            "artifacts",
        }

        # Version control directories
        self.vcs_dirs = {".git", ".svn", ".hg"}

        # Common sensitive filenames
        self.sensitive_filenames = {
            "id_rsa",
            "id_dsa",
            ".htpasswd",
            ".htaccess",
            "authorized_keys",
            "known_hosts",
            ".ssh",
            ".pgp",
            ".gnupg",
            ".env",
            "config.json",
            "secrets.yaml",
            "credentials.xml",
        }

        # File extension categories
        self.backup_extensions = {".bak", ".back", ".backup", ".old"}
        self.source_code_extensions = {
            ".py",
            ".pl",
            ".ps1",
            ".java",
            ".cs",
            ".cpp",
            ".h",
            ".hpp",
            ".js",
            ".ts",
            ".php",
            ".rb",
            ".go",
            ".rs",
            ".swift",
        }
        self.shell_executable_extensions = {".exe", ".appref-ms", ".js", ".sh", ".bat", ".cmd"}
        self.binary_extensions = {".exe", ".dll", ".sys", ".so", ".dylib"}
        self.office_extensions = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".odt", ".ods", ".odp"}
        self.plaintext_extensions = {".txt", ".json", ".xml", ".csv", ".log", ".md", ".rst", ".tex"}
        self.config_extensions = {
            ".yaml",
            ".yml",
            ".ini",
            ".toml",
            ".xml",
            ".cfg",
            ".config",
            ".env",
            ".conf",
            ".properties",
        }

        # Extensions commonly associated with sensitive data
        self.sensitive_extensions = {
            ".key",
            ".pem",
            ".crt",
            ".cer",
            ".p12",
            ".pfx",
            ".jks",
            ".keystore",
            ".pass",
            ".pgp",
            ".asc",
            ".kdbx",
        }

        # Common certificate/key sizes (in bytes)
        self.common_cert_sizes = {
            2048 // 8,  # RSA-2048
            4096 // 8,  # RSA-4096
            256 // 8,  # ECC-256
            384 // 8,  # ECC-384
        }

    def _safe_division(self, numerator, denominator, default=0):
        """Safely perform division, returning default value if denominator is 0"""
        try:
            if denominator == 0:
                return default
            return numerator / denominator
        except (TypeError, ZeroDivisionError):
            return default

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0
        counts = Counter(text)
        text_length = len(text)
        probs = [self._safe_division(count, text_length) for count in counts.values()]
        return -sum(p * math.log2(p) for p in probs if p > 0)

    def _is_power_of_two(self, n: int) -> bool:
        """Check if a number is a power of 2"""
        return n > 0 and (n & (n - 1)) == 0

    def _get_naming_convention(self, name: str) -> str:
        """Identify the naming convention used"""
        if "_" in name:
            return "snake_case"
        elif "-" in name:
            return "kebab-case"
        elif any(c.isupper() for c in name[1:]):
            if name[0].isupper():
                return "PascalCase"
            return "camelCase"
        return "other"

    def _has_date_pattern(self, text: str) -> bool:
        """Check for common date patterns in text"""
        date_patterns = [
            r"\d{4}-\d{2}-\d{2}",  # YYYY-MM-DD
            r"\d{2}-\d{2}-\d{4}",  # DD-MM-YYYY
            r"\d{8}",  # YYYYMMDD
            r"\d{2}\d{2}\d{4}",  # DDMMYYYY
        ]
        return any(re.search(pattern, text) for pattern in date_patterns)

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if not s2:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _is_business_hours(self, dt: datetime) -> bool:
        """Check if time is during business hours (9 AM - 5 PM)"""
        return (
            dt.weekday() < 5  # Monday to Friday
            and 9 <= dt.hour < 17  # 9 AM to 5 PM
        )

    def _is_weekend(self, dt: datetime) -> bool:
        """Check if time is during weekend"""
        return dt.weekday() >= 5

    def _extract_version_pattern(self, name: str, suffix="") -> dict[str, float]:
        """Extract version number patterns from filename.

        Returns:
            Dictionary with the following features:
            - has_simple_version: bool (0/1)
            - has_double_version: bool (0/1)
            - has_semantic_version: bool (0/1)
            - has_dot_version: bool (0/1)
            - simple_version_value: float (-1 if not found)
            - double_version_value: float (-1 if not found)
            - semantic_version_value: float (-1 if not found)
            - dot_version_value: float (-1 if not found)
        """
        patterns = {
            r"v\d+": "simple_version",
            r"v\d+\.\d+": "double_version",
            r"v\d+\.\d+\.\d+": "semantic_version",
            r"\d{1,2}\.\d{1,2}\.\d{1,2}": "dot_version",
        }

        # Initialize all features with default values
        features = {
            f"has_simple_version{suffix}": 0,
            f"has_double_version{suffix}": 0,
            f"has_semantic_version{suffix}": 0,
            f"has_dot_version{suffix}": 0,
            f"simple_version_value{suffix}": -1.0,
            f"double_version_value{suffix}": -1.0,
            f"semantic_version_value{suffix}": -1.0,
            f"dot_version_value{suffix}": -1.0,
        }

        # Update features based on matches
        for pattern, feature_name in patterns.items():
            matches = re.findall(pattern, name, re.IGNORECASE)
            if matches:
                features[f"has_{feature_name}{suffix}"] = 1
                # Extract the numeric part and normalize
                numeric = re.sub(r"[v.]", "", matches[0])
                features[f"{feature_name}{suffix}_value"] = float(numeric) / 1000

        return features

    def _get_size_bucket(self, size: int) -> int:
        """
        Returns size bucket 0-5:
        0: <1KB
        1: 1KB-10KB
        2: 10KB-100KB
        3: 100KB-1MB
        4: 1MB-10MB
        5: >10MB
        """
        if size < 1024:  # 1KB
            return 0
        elif size < 10240:  # 10KB
            return 1
        elif size < 102400:  # 100KB
            return 2
        elif size < 1048576:  # 1MB
            return 3
        elif size < 10485760:  # 10MB
            return 4
        else:
            return 5

    def _is_automated_timestamp(self, dt: datetime) -> bool:
        """Check if timestamp suggests automated creation"""
        return (
            dt.second == 0  # Exact minute
            or (dt.minute == 0 and dt.second == 0)  # Exact hour
            or (dt.hour == 0 and dt.minute == 0 and dt.second == 0)  # Exact day
        )

    def _is_round_number_timestamp(self, dt: datetime) -> bool:
        """Check if timestamp has round numbers"""
        return dt.minute in {0, 15, 30, 45} and dt.second == 0

    def _check_path_patterns(self, filepath: str) -> dict[str, bool]:
        """Returns dict of boolean flags for various path patterns"""
        # Normalize path separators to Windows style for consistent processing
        norm_path = ntpath.normpath(filepath)
        str_path = norm_path.lower()

        # Split path into components
        drive, tail = ntpath.splitdrive(norm_path)
        parts = [p for p in tail.split(ntpath.sep) if p]
        if drive:
            parts.insert(0, drive)

        # Determine if it's a Windows-style path by checking for backslashes or drive
        is_windows = bool(drive) or "\\" in str_path

        patterns = {
            "root_dir": len(parts) == 2 if is_windows else len(parts) == 1,  # File directly in root
            "temp_dir": False,
            "public_user": False,
            "user_dir": False,
            "program_data": False,
            "program_files": False,
            "program_files_x86": False,
            "windows": False,
            "system32": False,
            "windows_temp": False,
            "unix_user": False,
            "etc": False,
            "root_home": False,
            "home_user": False,
        }

        if is_windows:
            patterns.update(
                {
                    "temp_dir": "\\temp\\" in str_path or str_path.endswith("\\temp"),
                    "public_user": "\\users\\public\\" in str_path or str_path.endswith("\\users\\public"),
                    "user_dir": bool(re.search(r"\\users\\[^\\]+\\", str_path)),
                    "program_data": "\\programdata\\" in str_path or str_path.endswith("\\programdata"),
                    "program_files": "\\program files\\" in str_path or str_path.endswith("\\program files"),
                    "program_files_x86": "\\program files (x86)\\" in str_path
                    or str_path.endswith("\\program files (x86)"),
                    "windows": "\\windows\\" in str_path or str_path.endswith("\\windows"),
                    "system32": "\\windows\\system32\\" in str_path or str_path.endswith("\\windows\\system32"),
                    "windows_temp": "\\windows\\temp\\" in str_path or str_path.endswith("\\windows\\temp"),
                }
            )
        else:
            patterns.update(
                {
                    "unix_user": bool(re.search(r"/users/[^/]+/?", str_path)),
                    "etc": "/etc/" in str_path or str_path == "/etc",
                    "root_home": "/root/" in str_path or str_path == "/root",
                    "home_user": bool(re.search(r"/home/[^/]+/?", str_path)),
                }
            )

        return patterns

    def extract_sibling_features(
        self,
        filepath: str,
        size: int,
        sibling_data: dict,
        created_time: str | None = None,
        modified_time: str | None = None,
        accessed_time: str | None = None,
    ) -> dict[str, float]:
        features = {}

        try:
            created_dt = datetime.fromisoformat(created_time) if created_time else DEFAULT_TIMESTAMP
        except (ValueError, TypeError):
            created_dt = DEFAULT_TIMESTAMP

        features.update(
            {
                "sibling_count": sibling_data.get("sibling_count", 0),
                "has_sensitive_siblings": int(sibling_data.get("has_sensitive", False)),
                "is_part_of_batch": int(sibling_data.get("similar_created_count", 0) > 1),
            }
        )

        # Check if file might have been moved (based on creation time difference)
        #   TODO: double check this logic...
        if "avg_sibling_created_time" in sibling_data:
            avg_sibling_created = datetime.fromisoformat(sibling_data["avg_sibling_created_time"])
            features["possible_moved_file"] = int(
                abs((created_dt - avg_sibling_created).total_seconds()) > 86400  # More than 1 day difference
            )
        else:
            features["possible_moved_file"] = -1

        features["_features_version"] = self.version
        return features

    # def extract_population_features(
    #     self,
    #     filepath: str,
    #     size: int,
    #     population_stats: Dict,
    #     created_time: Optional[str] = None,
    #     modified_time: Optional[str] = None,
    #     accessed_time: Optional[str] = None,
    # ) -> Dict[str, float]:

    #     features = {}

    #     file_name = ntpath.basename(filepath)
    #     dir_path = ntpath.dirname(filepath)
    #     dir_path_lower = dir_path.lower()

    #     ext = ntpath.splitext(filepath)[1]
    #     if ext:
    #         ext = ext.lower()
    #     else:
    #         ext = 'no_extension'

    #     # Extension rarity (if population stats available)
    #     if 'extension_counts' in population_stats:
    #         total_files = sum(population_stats['extension_counts'].values())
    #         ext_count = population_stats['extension_counts'].get(ext, 0)
    #         features['extension_rarity'] = 1.0 - (ext_count / total_files) if total_files > 0 else 1.0
    #     else:
    #         features['extension_rarity'] = 0.0

    #     if 'dir_avg_sizes' in population_stats and dir_path_lower in population_stats['dir_avg_sizes']:
    #         dir_avg = population_stats['dir_avg_sizes'][dir_path_lower]
    #         features['size_ratio_to_dir_avg'] = self._safe_division(size, dir_avg, default=-1)
    #     else:
    #         features['size_ratio_to_dir_avg'] = -1

    #     if 'extension_avg_sizes' in population_stats and ext in population_stats['extension_avg_sizes']:
    #         ext_avg = population_stats['extension_avg_sizes'][ext]
    #         features['size_ratio_to_ext_avg'] = self._safe_division(size, ext_avg, default=-1)

    #         if 'extension_size_std' in population_stats and ext in population_stats['extension_size_std']:
    #             ext_std = population_stats['extension_size_std'][ext]
    #             if ext_std > 0:
    #                 z_score = abs(size - ext_avg) / ext_std
    #                 features['extension_size_pattern_match'] = 1.0 / (1.0 + z_score)
    #             else:
    #                 features['extension_size_pattern_match'] = -1
    #         else:
    #             features['extension_size_pattern_match'] = -1
    #     else:
    #         features['size_ratio_to_ext_avg'] = -1
    #         features['extension_size_pattern_match'] = -1

    #     # Directory depth comparison
    #     if 'avg_directory_depth' in population_stats and population_stats['avg_directory_depth'] > 0:
    #         features['relative_directory_depth'] = features['directory_depth'] / population_stats['avg_directory_depth']
    #     else:
    #         features['relative_directory_depth'] = -1

    #     features['_features_version'] = self.version
    #     return features

    def extract_population_features(
        self,
        filepath: str,
        size: int,
        population_stats: dict,
        created_time: str | None = None,
        modified_time: str | None = None,
        accessed_time: str | None = None,
    ) -> dict[str, float]:
        """
        Extract population-based features including time patterns
        """
        features = {}

        # file_name = ntpath.basename(filepath)
        dir_path = ntpath.dirname(filepath)
        dir_path_lower = dir_path.lower()

        ext = ntpath.splitext(filepath)[1]
        if ext:
            ext = ext.lower()
        else:
            ext = "no_extension"

        # Original size and extension features
        if "extension_counts" in population_stats:
            total_files = sum(population_stats["extension_counts"].values())
            ext_count = population_stats["extension_counts"].get(ext, 0)
            features["extension_rarity"] = 1.0 - (ext_count / total_files) if total_files > 0 else 1.0
        else:
            features["extension_rarity"] = 0.0

        if "dir_avg_sizes" in population_stats and dir_path_lower in population_stats["dir_avg_sizes"]:
            dir_avg = population_stats["dir_avg_sizes"][dir_path_lower]
            features["size_ratio_to_dir_avg"] = self._safe_division(size, dir_avg, default=-1)
        else:
            features["size_ratio_to_dir_avg"] = -1

        if "extension_avg_sizes" in population_stats and ext in population_stats["extension_avg_sizes"]:
            ext_avg = population_stats["extension_avg_sizes"][ext]
            features["size_ratio_to_ext_avg"] = self._safe_division(size, ext_avg, default=-1)

            if "extension_size_std" in population_stats and ext in population_stats["extension_size_std"]:
                ext_std = population_stats["extension_size_std"][ext]
                if ext_std > 0:
                    z_score = abs(size - ext_avg) / ext_std
                    features["extension_size_pattern_match"] = 1.0 / (1.0 + z_score)
                else:
                    features["extension_size_pattern_match"] = -1
            else:
                features["extension_size_pattern_match"] = -1
        else:
            features["size_ratio_to_ext_avg"] = -1
            features["extension_size_pattern_match"] = -1

        # Directory depth comparison
        if "avg_directory_depth" in population_stats:
            dir_depth = len(ntpath.normpath(filepath).split(ntpath.sep)) - 1
            features["relative_directory_depth"] = (
                dir_depth / population_stats["avg_directory_depth"]
                if population_stats["avg_directory_depth"] > 0
                else -1
            )
        else:
            features["relative_directory_depth"] = -1

        # New time-based features
        # if all(t is not None for t in [created_time, modified_time, accessed_time]):
        #     try:
        #         created_dt = datetime.fromisoformat(created_time)
        #         modified_dt = datetime.fromisoformat(modified_time)
        #         accessed_dt = datetime.fromisoformat(accessed_time)

        #         # Directory time pattern features
        #         if ('dir_time_patterns' in population_stats and
        #             dir_path_lower in population_stats['dir_time_patterns']):
        #             dir_patterns = population_stats['dir_time_patterns'][dir_path_lower]

        #             # Creation time patterns
        #             features['dir_creation_hour_deviation'] = abs(
        #                 created_dt.hour - dir_patterns['created']['avg_hour']
        #             ) / (dir_patterns['created']['std_hour'] + 1e-6)

        #             features['dir_creation_business_hours_match'] = (
        #                 1.0 if (9 <= created_dt.hour < 17) ==
        #                 (dir_patterns['created']['business_hours_ratio'] > 0.5)
        #                 else 0.0
        #             )

        #             features['dir_creation_weekend_match'] = (
        #                 1.0 if (created_dt.weekday() >= 5) ==
        #                 (dir_patterns['created']['weekend_ratio'] > 0.5)
        #                 else 0.0
        #             )

        #             # Modification time patterns
        #             features['dir_modification_hour_deviation'] = abs(
        #                 modified_dt.hour - dir_patterns['modified']['avg_hour']
        #             ) / (dir_patterns['modified']['std_hour'] + 1e-6)

        #         # Extension time pattern features
        #         if ('extension_time_patterns' in population_stats and
        #             ext in population_stats['extension_time_patterns']):
        #             ext_patterns = population_stats['extension_time_patterns'][ext]

        #             # Lifespan comparison
        #             file_lifespan_days = (modified_dt - created_dt).total_seconds() / 86400
        #             features['ext_lifespan_ratio'] = self._safe_division(
        #                 file_lifespan_days,
        #                 ext_patterns['avg_lifespan_days'],
        #                 default=-1
        #             )

        #             # Access frequency comparison
        #             if (modified_dt - created_dt).days > 0:
        #                 file_access_freq = 1 / (modified_dt - created_dt).days
        #                 features['ext_access_frequency_ratio'] = self._safe_division(
        #                     file_access_freq,
        #                     ext_patterns['access_frequency'],
        #                     default=-1
        #                 )
        #             else:
        #                 features['ext_access_frequency_ratio'] = -1

        #         # Global time pattern features
        #         if 'time_distribution' in population_stats:
        #             time_dist = population_stats['time_distribution']

        #             # Check if creation hour matches global peak hours
        #             peak_created_hours = [h for h, _ in time_dist['peak_activity_hours']['created']]
        #             features['creation_peak_hour_match'] = (
        #                 1.0 if created_dt.hour in peak_created_hours else 0.0
        #             )

        #             # Compare to global business hours pattern
        #             features['business_hours_pattern_match'] = (
        #                 1.0 if (9 <= created_dt.hour < 17) ==
        #                 (time_dist['business_hours_ratio']['created'] > 0.5)
        #                 else 0.0
        #             )

        #             # Check for automated timestamp patterns
        #             features['automated_timestamp_probability'] = (
        #                 1.0 if created_dt.second == 0 else 0.0
        #             )

        #     except (ValueError, TypeError) as e:
        #         # If any time parsing fails, set default values
        #         features.update({
        #             'dir_creation_hour_deviation': -1,
        #             'dir_creation_business_hours_match': -1,
        #             'dir_creation_weekend_match': -1,
        #             'dir_modification_hour_deviation': -1,
        #             'ext_lifespan_ratio': -1,
        #             'ext_access_frequency_ratio': -1,
        #             'creation_peak_hour_match': -1,
        #             'business_hours_pattern_match': -1,
        #             'automated_timestamp_probability': -1
        #         })

        features["_features_version"] = self.version
        return features

    def extract_indivdiual_features(
        self,
        filepath: str,
        size: int,
        created_time: str | None = None,
        modified_time: str | None = None,
        accessed_time: str | None = None,
    ) -> dict[str, float]:
        """
        Extract features for an individual file from file metadata.

        Args:
            filepath: Full path to the file
            size: File size in bytes
            created_time: ISO 8601 timestamp
            modified_time: ISO 8601 timestamp
            accessed_time: ISO 8601 timestamp

        Returns:
            Dictionary of features
        """

        features = {}

        file_name = ntpath.basename(filepath)
        dir_path = ntpath.dirname(filepath)
        file_name_lower = file_name.lower()
        dir_path_lower = dir_path.lower()

        logger.debug(f"[FileFeatureExtractor:extract_features()] file_name: {file_name}")
        logger.debug(f"[FileFeatureExtractor:extract_features()] dir_path: {dir_path}")

        # Parse timestamps and ensure they're timezone aware
        try:
            created_dt = datetime.fromisoformat(created_time) if created_time else DEFAULT_TIMESTAMP
        except (ValueError, TypeError):
            created_dt = DEFAULT_TIMESTAMP

        try:
            modified_dt = datetime.fromisoformat(modified_time) if modified_time else DEFAULT_TIMESTAMP
        except (ValueError, TypeError):
            modified_dt = DEFAULT_TIMESTAMP

        try:
            accessed_dt = datetime.fromisoformat(accessed_time) if accessed_time else DEFAULT_TIMESTAMP
        except (ValueError, TypeError):
            accessed_dt = DEFAULT_TIMESTAMP

        # Get current time with timezone info if any of the input times have it
        now = datetime.now(created_dt.tzinfo if created_dt.tzinfo else None)

        # Basic path features
        features.update(
            {
                "directory_depth": len(ntpath.normpath(filepath).split(ntpath.sep)) - 1,
                "file_name_length": len(file_name),
                "dir_path_length": len(dir_path),
                "special_chars_in_file_name": len(re.findall(r"[^a-zA-Z0-9\.-/\\:]", file_name)),
                "special_chars_in_dir_path": len(re.findall(r"[^a-zA-Z0-9\.-/\\:]", dir_path)),
                "file_name_uppercase_ratio": self._safe_division(
                    sum(1 for c in file_name if c.isupper()), len(file_name)
                ),
                "dir_path_uppercase_ratio": self._safe_division(sum(1 for c in dir_path if c.isupper()), len(dir_path)),
                "dots_in_file_name": file_name.count("."),
                "dots_in_dir_path": dir_path.count("."),
                "file_name_has_unicode": int(any(ord(c) > 127 for c in str(file_name))),
                "dir_path_has_unicode": int(any(ord(c) > 127 for c in str(dir_path))),
                "file_name_entropy": self._calculate_entropy(str(file_name)),
                "dir_path_entropy": self._calculate_entropy(str(dir_path)),
                "full_path_entropy": self._calculate_entropy(str(filepath)),
                "numbers_in_file_name": len(re.findall(r"\d", file_name)),
                "numbers_in_dir_path": len(re.findall(r"\d", dir_path)),
                "file_name_naming_convention": self._get_naming_convention(file_name),
                "file_name_naming_convention": self._get_naming_convention(dir_path),
                "file_name_has_date_pattern": int(self._has_date_pattern(file_name)),
                "dir_path_has_date_pattern": int(self._has_date_pattern(dir_path)),
            }
        )

        # Hidden file detection
        features["is_hidden"] = int(file_name.startswith("."))

        # Sensitive filename similarity
        min_distance = min(
            self._levenshtein_distance(file_name_lower, sensitive.lower()) for sensitive in self.sensitive_filenames
        )
        features["file_name_sensitive_similarity"] = 1.0 / (1.0 + min_distance)

        # Path separator
        features["uses_windows_separator"] = int("\\" in str(filepath))

        # Extension features
        ext = ntpath.splitext(filepath)[1]
        if ext:
            ext = ext.lower()
        features.update(
            {
                "has_extension": int(bool(ext)),
                "ext_is_backup": int(ext in self.backup_extensions),
                "ext_is_source_code": int(ext in self.source_code_extensions),
                "ext_is_shell_executable": int(ext in self.shell_executable_extensions),
                "ext_is_binary": int(ext in self.binary_extensions),
                "ext_is_office_doc": int(ext in self.office_extensions),
                "ext_is_plaintext": int(ext in self.plaintext_extensions),
                "ext_is_config_file": int(ext in self.config_extensions),
                "ext_is_sensitive_extension": int(ext in self.sensitive_extensions),
                "has_multiple_extensions": int(len(ntpath.basename(filepath).split(".")) > 2),
            }
        )

        features.update(self._extract_version_pattern(file_name_lower, "_in_file_name"))
        features.update(self._extract_version_pattern(dir_path_lower, "_in_dir_path"))

        features.update(
            {
                # Technical keyword checks in file name
                "has_api_keyword_in_file_name": int(any(k in file_name_lower for k in self.api_service_keywords)),
                "has_db_keyword_in_file_name": int(any(k in file_name_lower for k in self.database_keywords)),
                "has_config_keyword_in_file_name": int(any(k in file_name_lower for k in self.config_keywords)),
                "has_infra_keyword_in_file_name": int(any(k in file_name_lower for k in self.infrastructure_keywords)),
                "has_devenv_keyword_in_file_name": int(any(k in file_name_lower for k in self.dev_env_keywords)),
                "has_network_keyword_in_file_name": int(any(k in file_name_lower for k in self.network_keywords)),
                # Technical keyword checks in dir path
                "has_api_keyword_in_dir_path": int(any(k in dir_path_lower for k in self.api_service_keywords)),
                "has_db_keyword_in_dir_path": int(any(k in dir_path_lower for k in self.database_keywords)),
                "has_config_keyword_in_dir_path": int(any(k in dir_path_lower for k in self.config_keywords)),
                "has_infra_keyword_in_dir_path": int(any(k in dir_path_lower for k in self.infrastructure_keywords)),
                "has_devenv_keyword_in_dir_path": int(any(k in dir_path_lower for k in self.dev_env_keywords)),
                "has_network_keyword_in_dir_path": int(any(k in dir_path_lower for k in self.network_keywords)),
                # Security keyword checks in file name
                "has_auth_keyword_in_file_name": int(any(k in file_name_lower for k in self.authentication_keywords)),
                "has_key_keyword_in_file_name": int(any(k in file_name_lower for k in self.key_keywords)),
                "has_token_keyword_in_file_name": int(any(k in file_name_lower for k in self.token_keywords)),
                "has_secret_keyword_in_file_name": int(any(k in file_name_lower for k in self.secret_keywords)),
                "has_cert_keyword_in_file_name": int(any(k in file_name_lower for k in self.certificate_keywords)),
                "has_identity_keyword_in_file_name": int(any(k in file_name_lower for k in self.identity_keywords)),
                "has_permission_keyword_in_file_name": int(any(k in file_name_lower for k in self.permission_keywords)),
                # Security keyword checks in dir path
                "has_auth_keyword_in_dir_path": int(any(k in dir_path_lower for k in self.authentication_keywords)),
                "has_key_keyword_in_dir_path": int(any(k in dir_path_lower for k in self.key_keywords)),
                "has_token_keyword_in_dir_path": int(any(k in dir_path_lower for k in self.token_keywords)),
                "has_secret_keyword_in_dir_path": int(any(k in dir_path_lower for k in self.secret_keywords)),
                "has_cert_keyword_in_dir_path": int(any(k in dir_path_lower for k in self.certificate_keywords)),
                "has_identity_keyword_in_dir_path": int(any(k in dir_path_lower for k in self.identity_keywords)),
                "has_permission_keyword_in_dir_path": int(any(k in dir_path_lower for k in self.permission_keywords)),
                # Directory type checks
                "has_source_code_dir": int(any(d in dir_path_lower for d in self.source_code_dirs)),
                "has_build_output_dir": int(any(d in dir_path_lower for d in self.build_output_dirs)),
                "has_vcs_dir": int(any(d in dir_path_lower for d in self.vcs_dirs)),
            }
        )

        # TODO: accounting/HR/etc.?

        # Standard path patterns
        pattern_features = self._check_path_patterns(filepath)
        features.update({f"path_pattern_{k}": int(v) for k, v in pattern_features.items()})

        # Time-based features for each timestamp type
        features.update(
            {
                # Hour of day features
                "created_hour_of_day": created_dt.hour,
                "modified_hour_of_day": modified_dt.hour,
                "accessed_hour_of_day": accessed_dt.hour,
                # Day of week features
                "created_day_of_week": created_dt.weekday(),
                "modified_day_of_week": modified_dt.weekday(),
                "accessed_day_of_week": accessed_dt.weekday(),
                # Business hours features
                "created_in_business_hours": int(self._is_business_hours(created_dt)),
                "modified_in_business_hours": int(self._is_business_hours(modified_dt)),
                "accessed_in_business_hours": int(self._is_business_hours(accessed_dt)),
                # Weekend features
                "created_on_weekend": int(self._is_weekend(created_dt)),
                "modified_on_weekend": int(self._is_weekend(modified_dt)),
                "accessed_on_weekend": int(self._is_weekend(accessed_dt)),
                # Days since each event
                "days_since_creation": (now - created_dt).days,
                "days_since_modification": (now - modified_dt).days,
                "days_since_access": (now - accessed_dt).days,
                # Time deltas between events
                "days_creation_to_modification": (modified_dt - created_dt).days,
                "days_creation_to_access": (accessed_dt - created_dt).days,
                "days_modification_to_access": (accessed_dt - modified_dt).days,
                # Automated timestamp patterns
                "created_is_automated": int(self._is_automated_timestamp(created_dt)),
                "modified_is_automated": int(self._is_automated_timestamp(modified_dt)),
                "accessed_is_automated": int(self._is_automated_timestamp(accessed_dt)),
                # Round number patterns
                "created_is_round_number": int(self._is_round_number_timestamp(created_dt)),
                "modified_is_round_number": int(self._is_round_number_timestamp(modified_dt)),
                "accessed_is_round_number": int(self._is_round_number_timestamp(accessed_dt)),
            }
        )

        # Size features
        features.update(
            {
                "size_bucket": self._get_size_bucket(size),
                "size_is_power_of_two": int(self._is_power_of_two(size)),
                "size_matches_cert_size": int(size in self.common_cert_sizes),
            }
        )

        features["_features_version"] = self.version
        return features

    @staticmethod
    def compute_population_stats(file_records: list[dict]) -> dict | None:
        """
        Compute population statistics from a list of file records.

        Args:
            file_records: List of dicts containing 'filepath' and 'size' keys

        Returns:
            Dictionary containing directory and extension statistics
        """
        dir_sizes = {}
        ext_sizes = {}
        dir_counts = {}
        ext_counts = {}
        dir_depths = []
        ext_size_lists = {}

        dir_times = {}  # Directory-level time tracking
        ext_times = {}  # Extension-level time tracking
        global_times = {"created": [], "modified": [], "accessed": []}

        for record in file_records:
            filepath = record["filepath"]
            dir_path = ntpath.dirname(filepath).lower()

            ext = ntpath.splitext(filepath)[1]
            if ext:
                ext = ext.lower()
            else:
                ext = "no_extension"

            size = record["size"]

            created_dt = datetime.fromisoformat(record["created_time"])
            modified_dt = datetime.fromisoformat(record["modified_time"])
            accessed_dt = datetime.fromisoformat(record["accessed_time"])

            # Initialize directory time tracking if needed
            if dir_path not in dir_times:
                dir_times[dir_path] = {"created": [], "modified": [], "accessed": []}

            # Initialize extension time tracking if needed
            if ext not in ext_times:
                ext_times[ext] = {
                    "created": [],
                    "modified": [],
                    "accessed": [],
                    "lifespans": [],  # Time between creation and last modification
                }

            dir_times[dir_path]["created"].append(created_dt)
            dir_times[dir_path]["modified"].append(modified_dt)
            dir_times[dir_path]["accessed"].append(accessed_dt)

            ext_times[ext]["created"].append(created_dt)
            ext_times[ext]["modified"].append(modified_dt)
            ext_times[ext]["accessed"].append(accessed_dt)
            ext_times[ext]["lifespans"].append((modified_dt - created_dt).total_seconds())

            global_times["created"].append(created_dt)
            global_times["modified"].append(modified_dt)
            global_times["accessed"].append(accessed_dt)

            # size and count updates...
            dir_sizes[dir_path] = dir_sizes.get(dir_path, 0) + size
            dir_counts[dir_path] = dir_counts.get(dir_path, 0) + 1
            ext_sizes[ext] = ext_sizes.get(ext, 0) + size
            ext_counts[ext] = ext_counts.get(ext, 0) + 1
            dir_depth = len(ntpath.normpath(filepath).split(ntpath.sep)) - 1
            dir_depths.append(dir_depth)

            # Track extension sizes for standard deviation calculation
            if ext not in ext_size_lists:
                ext_size_lists[ext] = []
            ext_size_lists[ext].append(size)

        # Process directory time statistics
        dir_time_patterns = {}
        for dir_str, times in dir_times.items():
            dir_time_patterns[dir_str] = {
                "created": {
                    "avg_hour": statistics.mean([t.hour for t in times["created"]]),
                    "std_hour": statistics.stdev([t.hour for t in times["created"]])
                    if len(times["created"]) > 1
                    else 0,
                    "time_spread_days": (max(times["created"]) - min(times["created"])).days,
                    "business_hours_ratio": sum(1 for t in times["created"] if 9 <= t.hour < 17)
                    / len(times["created"]),
                    "weekend_ratio": sum(1 for t in times["created"] if t.weekday() >= 5) / len(times["created"]),
                },
                "modified": {
                    "avg_hour": statistics.mean([t.hour for t in times["modified"]]),
                    "std_hour": statistics.stdev([t.hour for t in times["modified"]])
                    if len(times["modified"]) > 1
                    else 0,
                    "time_spread_days": (max(times["modified"]) - min(times["modified"])).days,
                    "business_hours_ratio": sum(1 for t in times["modified"] if 9 <= t.hour < 17)
                    / len(times["modified"]),
                    "weekend_ratio": sum(1 for t in times["modified"] if t.weekday() >= 5) / len(times["modified"]),
                },
            }

        # Process extension time statistics
        ext_time_patterns = {}
        for ext, times in ext_times.items():
            ext_time_patterns[ext] = {
                "avg_lifespan_days": statistics.mean(times["lifespans"]) / 86400,  # Convert seconds to days
                "std_lifespan_days": statistics.stdev(times["lifespans"]) / 86400 if len(times["lifespans"]) > 1 else 0,
                "median_update_interval_days": statistics.median(
                    [(b - a).days for a, b in zip(sorted(times["modified"])[:-1], sorted(times["modified"])[1:])]
                )
                if len(times["modified"]) > 1
                else 0,
                "access_frequency": len(times["accessed"])
                / ((max(times["accessed"]) - min(times["accessed"])).days + 1)
                if len(times["accessed"]) > 1
                else 0,
            }

        # Process global time patterns
        time_distribution = {
            "peak_activity_hours": {
                time_type: Counter([t.hour for t in times]).most_common(3) for time_type, times in global_times.items()
            },
            "business_hours_ratio": {
                time_type: sum(1 for t in times if 9 <= t.hour < 17) / len(times)
                for time_type, times in global_times.items()
            },
            "weekend_ratio": {
                time_type: sum(1 for t in times if t.weekday() >= 5) / len(times)
                for time_type, times in global_times.items()
            },
            "automated_timestamp_ratio": {
                time_type: sum(1 for t in times if t.second == 0) / len(times)
                for time_type, times in global_times.items()
            },
        }

        dir_avg_sizes = {
            dir_str: size / count
            for dir_str, (size, count) in ((d, (dir_sizes[d], dir_counts[d])) for d in dir_sizes)
            if count > 0
        }

        ext_avg_sizes = {
            ext: size / count
            for ext, (size, count) in ((e, (ext_sizes[e], ext_counts[e])) for e in ext_sizes)
            if count > 0
        }

        ext_size_std = {ext: statistics.stdev(sizes) if len(sizes) > 1 else 0 for ext, sizes in ext_size_lists.items()}

        return {
            "dir_avg_sizes": dir_avg_sizes,
            "extension_avg_sizes": ext_avg_sizes,
            "extension_counts": ext_counts,
            "avg_directory_depth": statistics.mean(dir_depths) if dir_depths else 1,
            "extension_size_std": ext_size_std,
            # time-based stats
            "dir_time_patterns": dir_time_patterns,
            "extension_time_patterns": ext_time_patterns,
            "time_distribution": time_distribution,
        }

    @staticmethod
    def compute_sibling_data(
        target_file: dict, sibling_files: list[dict], known_sensitive: set[str] | None = None
    ) -> dict:
        """
        Compute statistics about sibling files in the same directory.

        Args:
            target_file: Dict containing target file information including 'agent_id'
            sibling_files: List of dicts containing sibling file information
            known_sensitive: Optional set of known sensitive file paths

        Returns:
            Dictionary containing sibling statistics
        """
        target_path = f"{target_file['filepath']}"
        target_dir = ntpath.dirname(target_path).lower()
        target_agent = target_file["agent_id"]

        # Filter siblings to same directory AND same agent
        same_dir_siblings = [
            f
            for f in sibling_files
            if ntpath.dirname(f["filepath"]).lower() == target_dir and f["agent_id"] == target_agent
        ]

        # Parse target timestamps
        target_created = datetime.fromisoformat(target_file["created_time"])
        target_modified = datetime.fromisoformat(target_file["modified_time"])
        target_accessed = datetime.fromisoformat(target_file["accessed_time"])

        if same_dir_siblings:
            # Calculate reference times for siblings
            sibling_created_times = [datetime.fromisoformat(f["created_time"]) for f in same_dir_siblings]
            sibling_modified_times = [datetime.fromisoformat(f["modified_time"]) for f in same_dir_siblings]
            sibling_accessed_times = [datetime.fromisoformat(f["accessed_time"]) for f in same_dir_siblings]

            # Calculate average times (using min as reference point)
            avg_created_time = min(sibling_created_times)
            avg_modified_time = min(sibling_modified_times)
            avg_accessed_time = min(sibling_accessed_times)

            # Count files with similar timestamps (within 1 minute) for each time type
            SIMILAR_THRESHOLD = 60  # seconds
            similar_created_count = sum(
                1 for t in sibling_created_times if abs((t - target_created).total_seconds()) < SIMILAR_THRESHOLD
            )
            similar_modified_count = sum(
                1 for t in sibling_modified_times if abs((t - target_modified).total_seconds()) < SIMILAR_THRESHOLD
            )
            similar_accessed_count = sum(
                1 for t in sibling_accessed_times if abs((t - target_accessed).total_seconds()) < SIMILAR_THRESHOLD
            )

            # Calculate time spreads in directory
            created_time_spread = (max(sibling_created_times) - min(sibling_created_times)).total_seconds()
            modified_time_spread = (max(sibling_modified_times) - min(sibling_modified_times)).total_seconds()
            accessed_time_spread = (max(sibling_accessed_times) - min(sibling_accessed_times)).total_seconds()

        else:
            # Set default values if no siblings
            avg_created_time = target_created
            avg_modified_time = target_modified
            avg_accessed_time = target_accessed
            similar_created_count = 0
            similar_modified_count = 0
            similar_accessed_count = 0
            created_time_spread = 0
            modified_time_spread = 0
            accessed_time_spread = 0

        # Check for known sensitive files in directory
        has_sensitive_siblings = False
        if known_sensitive:
            has_sensitive_siblings = any(
                str(ntpath.basename(f["filepath"])) in known_sensitive for f in same_dir_siblings
            )

        # Calculate if file appears to be part of a batch operation
        # (similar timestamps across multiple files)
        BATCH_THRESHOLD = 3  # minimum files for a batch
        is_batch_created = similar_created_count >= BATCH_THRESHOLD
        is_batch_modified = similar_modified_count >= BATCH_THRESHOLD
        is_batch_accessed = similar_accessed_count >= BATCH_THRESHOLD

        return {
            "sibling_count": len(same_dir_siblings),
            # Average sibling times
            "avg_sibling_created_time": avg_created_time.isoformat(),
            "avg_sibling_modified_time": avg_modified_time.isoformat(),
            "avg_sibling_accessed_time": avg_accessed_time.isoformat(),
            # Similar timestamp counts
            "similar_created_count": similar_created_count,
            "similar_modified_count": similar_modified_count,
            "similar_accessed_count": similar_accessed_count,
            # Time spread in directory
            "created_time_spread_seconds": created_time_spread,
            "modified_time_spread_seconds": modified_time_spread,
            "accessed_time_spread_seconds": accessed_time_spread,
            # Batch operation indicators
            "is_batch_created": int(is_batch_created),
            "is_batch_modified": int(is_batch_modified),
            "is_batch_accessed": int(is_batch_accessed),
            # Sensitive file indicators
            "has_sensitive_siblings": int(has_sensitive_siblings),
        }


if __name__ == "__main__":
    # Initialize the extractor
    extractor = FileFeatureExtractor()

    # Example file records with agent_id
    file_records = [
        {
            "filepath": "C:\\path\\to\\file1.txt",
            "size": 1024,
            "created_time": "2024-01-28T10:00:00",
            "modified_time": "2024-01-28T11:00:00",
            "accessed_time": "2024-01-28T12:00:00",
            "agent_id": "AGENT001",
        },
        {
            "filepath": "C:\\path\\to\\file2.txt",
            "size": 2048,
            "created_time": "2024-01-28T10:00:00",
            "modified_time": "2024-01-28T11:00:00",
            "accessed_time": "2024-01-28T12:00:00",
            "agent_id": "AGENT001",
        },
        {
            "filepath": "C:\\path\\to\\file3.txt",
            "size": 2048,
            "created_time": "2023-01-28T10:00:00",
            "modified_time": "2023-01-28T11:00:00",
            "accessed_time": "2023-01-28T12:00:00",
            "agent_id": "AGENT001",
        },
        {
            "filepath": "C:\\path\\to\\file1.txt",
            "size": 1024,
            "created_time": "2024-01-28T10:00:00",
            "modified_time": "2024-01-28T11:00:00",
            "accessed_time": "2024-01-28T12:00:00",
            "agent_id": "AGENT002",
        },
    ]

    # Compute population stats
    population_stats = FileFeatureExtractor.compute_population_stats(file_records)

    # Compute sibling data (will only consider files from same agent_id)
    sibling_data = FileFeatureExtractor.compute_sibling_data(
        target_file=file_records[0], sibling_files=file_records[1:]
    )

    # Extract features for a specific file
    features = extractor.extract_indivdiual_features(
        filepath="C:\\path\\to\\file1.txt",
        size=1024,
        created_time="2024-01-28T10:00:00",
        modified_time="2024-01-28T11:00:00",
        accessed_time="2024-01-28T12:00:00",
    )

    # from pprint import pprint
    # pprint(population_stats)
