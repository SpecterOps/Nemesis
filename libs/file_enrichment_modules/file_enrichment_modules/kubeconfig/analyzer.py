# enrichment_modules/kubeconfig/analyzer.py
import base64
import tempfile
from pathlib import Path

import yaml
import yara_x
from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)


class KubeconfigParser(EnrichmentModule):
    name: str = "kubeconfig_parser"
    dependencies: list[str] = []

    def __init__(self):
        self.storage = StorageMinio()

        self.asyncpg_pool = None  # type: ignore
        # the workflows this module should automatically run in
        self.workflows = ["default"]

        self.size_limit = 1000000  # 1 MB limit - skip larger files

        # YARA rule to detect Kubernetes configuration files
        self.yara_rule = yara_x.compile("""
rule Detect_Kubeconfig {
    meta:
        description = "Detects Kubernetes configuration files containing cluster credentials"
        author = "Nemesis"
        severity = "High"

    strings:
        // Core kubeconfig structure markers
        $apiversion = "apiVersion:" nocase
        $kind_config = "kind: Config" nocase

        // Cluster configuration
        $clusters = "clusters:" nocase
        $server = "server:" nocase
        $certificate_authority = "certificate-authority" nocase

        // User credentials
        $users = "users:" nocase
        $user = "user:" nocase
        $client_certificate = "client-certificate" nocase
        $client_key = "client-key" nocase
        $token = "token:" nocase
        $exec = "exec:" nocase

        // Context configuration
        $contexts = "contexts:" nocase

    condition:
        $apiversion and $kind_config and
        $clusters and $users and $contexts and
        ($server or $certificate_authority) and
        ($client_certificate or $client_key or $token or $exec or $user)
}
        """)

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run based on file type and content."""
        file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

        # Must be plaintext
        if not file_enriched.is_plaintext:
            return False

        # Skip files larger than 1MB
        if file_enriched.size > self.size_limit:
            return False

        # Run YARA rule to detect kubeconfig structure
        if file_path:
            with open(file_path, "rb") as f:
                file_bytes = f.read(file_enriched.size)
        else:
            file_bytes = self.storage.download_bytes(file_enriched.object_id, length=file_enriched.size)

        return len(self.yara_rule.scan(file_bytes).matching_rules) > 0

    def _decode_base64_data(self, data: str | None) -> str | None:
        """Attempt to decode base64 data, return original if not base64."""
        if not data:
            return None
        try:
            decoded = base64.b64decode(data)
            # Check if it looks like a certificate or key (PEM format)
            if b"-----BEGIN" in decoded:
                return decoded.decode("utf-8")
            # Return hex representation for binary data
            return decoded.hex()
        except Exception:
            return data

    def _extract_clusters(self, kubeconfig: dict) -> list[dict]:
        """Extract cluster information from kubeconfig."""
        clusters = []
        for cluster_entry in kubeconfig.get("clusters", []):
            cluster_info = {
                "name": cluster_entry.get("name", "<unnamed>"),
                "server": None,
                "certificate_authority": None,
                "certificate_authority_data": None,
                "insecure_skip_tls_verify": False,
                "tls_server_name": None,
                "proxy_url": None,
                "extensions": None,
            }

            cluster = cluster_entry.get("cluster", {})
            cluster_info["server"] = cluster.get("server")
            cluster_info["certificate_authority"] = cluster.get("certificate-authority")
            cluster_info["insecure_skip_tls_verify"] = cluster.get("insecure-skip-tls-verify", False)
            cluster_info["tls_server_name"] = cluster.get("tls-server-name")
            cluster_info["proxy_url"] = cluster.get("proxy-url")

            # Handle embedded CA data
            if "certificate-authority-data" in cluster:
                cluster_info["certificate_authority_data"] = self._decode_base64_data(
                    cluster.get("certificate-authority-data")
                )

            # Handle extensions (can contain security-relevant info)
            if "extensions" in cluster:
                cluster_info["extensions"] = cluster.get("extensions")

            clusters.append(cluster_info)

        return clusters

    def _extract_users(self, kubeconfig: dict) -> list[dict]:
        """Extract user credential information from kubeconfig."""
        users = []
        for user_entry in kubeconfig.get("users", []):
            user_info = {
                "name": user_entry.get("name", "<unnamed>"),
                # Certificate-based auth
                "client_certificate": None,
                "client_certificate_data": None,
                "client_key": None,
                "client_key_data": None,
                # Token-based auth
                "token": None,
                "token_file": None,
                # Basic auth (deprecated)
                "username": None,
                "password": None,
                # Exec credential plugin
                "exec": None,
                # Auth provider (legacy OIDC/GCP/Azure)
                "auth_provider": None,
                # Impersonation
                "impersonate": None,
                "impersonate_uid": None,
                "impersonate_groups": None,
                "impersonate_extra": None,
            }

            user = user_entry.get("user", {})

            # Certificate-based auth
            user_info["client_certificate"] = user.get("client-certificate")
            user_info["client_key"] = user.get("client-key")

            # Embedded certificate data (base64 encoded)
            if "client-certificate-data" in user:
                user_info["client_certificate_data"] = self._decode_base64_data(
                    user.get("client-certificate-data")
                )
            if "client-key-data" in user:
                user_info["client_key_data"] = self._decode_base64_data(
                    user.get("client-key-data")
                )

            # Token-based auth
            user_info["token"] = user.get("token")
            user_info["token_file"] = user.get("tokenFile")

            # Basic auth (deprecated but still supported)
            user_info["username"] = user.get("username")
            user_info["password"] = user.get("password")

            # Exec-based auth (e.g., aws-iam-authenticator, gcloud, kubelogin)
            if "exec" in user:
                exec_config = user["exec"]
                user_info["exec"] = {
                    "api_version": exec_config.get("apiVersion"),
                    "command": exec_config.get("command"),
                    "args": exec_config.get("args", []),
                    "env": exec_config.get("env"),
                    "install_hint": exec_config.get("installHint"),
                    "provide_cluster_info": exec_config.get("provideClusterInfo", False),
                    "interactive_mode": exec_config.get("interactiveMode"),
                }

            # Auth provider (legacy - OIDC, GCP, Azure)
            if "auth-provider" in user:
                auth_provider = user["auth-provider"]
                provider_config = auth_provider.get("config", {})

                # Extract security-relevant tokens/secrets from provider config
                sensitive_keys = [
                    "access-token", "id-token", "refresh-token",
                    "client-secret", "client-id", "tenant-id",
                    "apiserver-id"
                ]
                sensitive_config = {}
                for key in sensitive_keys:
                    if key in provider_config:
                        sensitive_config[key] = provider_config[key]

                user_info["auth_provider"] = {
                    "name": auth_provider.get("name"),
                    "config": provider_config,
                    "sensitive_fields": sensitive_config,
                }

            # Impersonation settings
            user_info["impersonate"] = user.get("as")
            user_info["impersonate_uid"] = user.get("as-uid")
            user_info["impersonate_groups"] = user.get("as-groups")
            user_info["impersonate_extra"] = user.get("as-user-extra")

            users.append(user_info)

        return users

    def _extract_contexts(self, kubeconfig: dict) -> list[dict]:
        """Extract context information from kubeconfig."""
        contexts = []
        for context_entry in kubeconfig.get("contexts", []):
            context_info = {
                "name": context_entry.get("name", "<unnamed>"),
                "cluster": None,
                "user": None,
                "namespace": None,
            }

            context = context_entry.get("context", {})
            context_info["cluster"] = context.get("cluster")
            context_info["user"] = context.get("user")
            context_info["namespace"] = context.get("namespace")

            contexts.append(context_info)

        return contexts

    def _has_credentials(self, users: list[dict]) -> bool:
        """Check if any user has extractable credentials."""
        for user in users:
            if any([
                user.get("token"),
                user.get("client_key_data"),
                user.get("client_key"),
                user.get("password"),
                user.get("client_certificate_data"),
            ]):
                return True
            # Check auth provider for tokens
            auth_provider = user.get("auth_provider")
            if auth_provider and auth_provider.get("sensitive_fields"):
                return True
        return False

    def _get_credential_types(self, users: list[dict]) -> list[str]:
        """Get list of credential types found."""
        cred_types = set()
        for user in users:
            if user.get("token"):
                cred_types.add("bearer_token")
            if user.get("token_file"):
                cred_types.add("token_file_reference")
            if user.get("client_key_data") or user.get("client_key"):
                cred_types.add("client_certificate")
            if user.get("password"):
                cred_types.add("basic_auth")
            if user.get("exec"):
                cred_types.add("exec_credential")
            if user.get("auth_provider"):
                provider_name = user["auth_provider"].get("name", "unknown")
                cred_types.add(f"auth_provider_{provider_name}")
                # Check for sensitive tokens in auth provider
                sensitive = user["auth_provider"].get("sensitive_fields", {})
                if sensitive.get("access-token"):
                    cred_types.add("access_token")
                if sensitive.get("refresh-token"):
                    cred_types.add("refresh_token")
                if sensitive.get("id-token"):
                    cred_types.add("id_token")
                if sensitive.get("client-secret"):
                    cred_types.add("client_secret")
            if user.get("impersonate"):
                cred_types.add("impersonation")
        return list(cred_types)

    def _create_finding_summary(self, clusters: list[dict], users: list[dict],
                                 contexts: list[dict], current_context: str,
                                 file_name: str) -> str:
        """Creates a markdown summary for the kubeconfig finding."""
        summary = f"# Kubernetes Configuration Analysis - {file_name}\n\n"

        # Current context
        summary += f"**Current Context**: `{current_context or 'not set'}`\n\n"

        # Clusters
        summary += f"## Clusters ({len(clusters)})\n\n"
        for cluster in clusters:
            summary += f"### {cluster['name']}\n"
            summary += f"* **Server**: `{cluster['server']}`\n"
            if cluster.get("certificate_authority"):
                summary += f"* **CA File**: `{cluster['certificate_authority']}`\n"
            if cluster.get("certificate_authority_data"):
                summary += "* **CA Data**: (embedded)\n"
            if cluster.get("insecure_skip_tls_verify"):
                summary += "* **TLS Verification**: DISABLED\n"
            if cluster.get("tls_server_name"):
                summary += f"* **TLS Server Name**: `{cluster['tls_server_name']}`\n"
            if cluster.get("proxy_url"):
                summary += f"* **Proxy URL**: `{cluster['proxy_url']}`\n"
            if cluster.get("extensions"):
                summary += f"* **Extensions**: {len(cluster['extensions'])} configured\n"
            summary += "\n"

        # Users
        summary += f"## Users ({len(users)})\n\n"
        for user in users:
            summary += f"### {user['name']}\n"

            # Token auth
            if user.get("token"):
                token = user["token"]
                display_token = f"{token[:20]}...{token[-10:]}" if len(token) > 35 else token
                summary += f"* **Bearer Token**: `{display_token}`\n"
            if user.get("token_file"):
                summary += f"* **Token File**: `{user['token_file']}`\n"

            # Cert auth
            if user.get("client_certificate") or user.get("client_certificate_data"):
                summary += "* **Client Certificate**: present\n"
            if user.get("client_key") or user.get("client_key_data"):
                summary += "* **Client Key**: present\n"

            # Basic auth
            if user.get("username"):
                summary += f"* **Username**: `{user['username']}`\n"
            if user.get("password"):
                summary += f"* **Password**: `{user['password']}`\n"

            # Exec auth
            if user.get("exec"):
                exec_info = user["exec"]
                args_str = ' '.join(exec_info.get('args', []))
                summary += f"* **Exec Command**: `{exec_info['command']} {args_str}`\n"
                if exec_info.get("env"):
                    env_vars = [f"{e['name']}={e['value']}" for e in exec_info["env"] if e]
                    summary += f"* **Exec Env**: `{', '.join(env_vars)}`\n"

            # Auth provider
            if user.get("auth_provider"):
                auth_info = user["auth_provider"]
                summary += f"* **Auth Provider**: `{auth_info['name']}`\n"
                sensitive = auth_info.get("sensitive_fields", {})
                for key, value in sensitive.items():
                    if value:
                        display_val = f"{value[:20]}..." if len(str(value)) > 25 else value
                        summary += f"* **{key}**: `{display_val}`\n"

            # Impersonation
            if user.get("impersonate"):
                summary += f"* **Impersonate User**: `{user['impersonate']}`\n"
            if user.get("impersonate_uid"):
                summary += f"* **Impersonate UID**: `{user['impersonate_uid']}`\n"
            if user.get("impersonate_groups"):
                summary += f"* **Impersonate Groups**: `{', '.join(user['impersonate_groups'])}`\n"
            if user.get("impersonate_extra"):
                summary += f"* **Impersonate Extra**: {user['impersonate_extra']}\n"

            summary += "\n"

        # Contexts
        summary += f"## Contexts ({len(contexts)})\n\n"
        for ctx in contexts:
            is_current = ctx["name"] == current_context
            marker = " (CURRENT)" if is_current else ""
            summary += f"### {ctx['name']}{marker}\n"
            summary += f"* **Cluster**: `{ctx['cluster']}`\n"
            summary += f"* **User**: `{ctx['user']}`\n"
            if ctx.get("namespace"):
                summary += f"* **Namespace**: `{ctx['namespace']}`\n"
            summary += "\n"

        return summary

    def _analyze_kubeconfig(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze kubeconfig file and generate enrichment result.

        Args:
            file_path: Path to the kubeconfig file to analyze
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)

        try:
            content = Path(file_path).read_text(encoding="utf-8")

            # Parse YAML
            try:
                kubeconfig = yaml.safe_load(content)
            except yaml.YAMLError as e:
                logger.error(f"Failed to parse kubeconfig YAML: {e}")
                return None

            if not kubeconfig or not isinstance(kubeconfig, dict):
                logger.error("Kubeconfig is empty or not a valid dictionary")
                return None

            # Extract components
            clusters = self._extract_clusters(kubeconfig)
            users = self._extract_users(kubeconfig)
            contexts = self._extract_contexts(kubeconfig)
            current_context = kubeconfig.get("current-context")

            # Check for credentials
            has_creds = self._has_credentials(users)
            cred_types = self._get_credential_types(users)

            # Create finding summary
            summary_markdown = self._create_finding_summary(
                clusters, users, contexts, current_context, file_enriched.file_name
            )

            # Create display data
            display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

            # Determine severity based on credential types
            severity = 5 if not has_creds else 8
            if any(ct in cred_types for ct in ["bearer_token", "basic_auth", "access_token", "refresh_token", "client_secret"]):
                severity = 9  # Direct credentials are highest severity

            # Create finding
            finding = Finding(
                category=FindingCategory.CREDENTIAL if has_creds else FindingCategory.MISC,
                finding_name="kubeconfig_credentials_detected" if has_creds else "kubeconfig_detected",
                origin_type=FindingOrigin.ENRICHMENT_MODULE,
                origin_name=self.name,
                object_id=file_enriched.object_id,
                severity=severity,
                raw_data={
                    "clusters": clusters,
                    "users": users,
                    "contexts": contexts,
                    "current_context": current_context,
                    "credential_types": cred_types,
                },
                data=[display_data],
            )

            enrichment_result.findings = [finding]
            enrichment_result.results = {
                "clusters": clusters,
                "users": users,
                "contexts": contexts,
                "current_context": current_context,
                "cluster_count": len(clusters),
                "user_count": len(users),
                "context_count": len(contexts),
                "has_credentials": has_creds,
                "credential_types": cred_types,
            }

            # Create a displayable version of the results
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_display_file:
                display = f"Kubernetes Configuration Analysis - {file_enriched.file_name}\n"
                display += "=" * (40 + len(file_enriched.file_name)) + "\n\n"
                display += f"Current Context: {current_context or 'not set'}\n"
                display += f"Credential Types Found: {', '.join(cred_types) if cred_types else 'none'}\n\n"

                # Clusters section
                display += f"CLUSTERS ({len(clusters)})\n"
                display += "-" * 50 + "\n"
                for cluster in clusters:
                    display += f"\n  [{cluster['name']}]\n"
                    display += f"    Server:     {cluster['server']}\n"
                    if cluster.get("certificate_authority"):
                        display += f"    CA File:    {cluster['certificate_authority']}\n"
                    if cluster.get("certificate_authority_data"):
                        display += "    CA Data:    (embedded)\n"
                    if cluster.get("insecure_skip_tls_verify"):
                        display += "    TLS Verify: DISABLED\n"
                    if cluster.get("tls_server_name"):
                        display += f"    TLS Name:   {cluster['tls_server_name']}\n"
                    if cluster.get("proxy_url"):
                        display += f"    Proxy:      {cluster['proxy_url']}\n"
                    if cluster.get("extensions"):
                        display += f"    Extensions: {len(cluster['extensions'])} configured\n"

                # Users section
                display += f"\n\nUSERS ({len(users)})\n"
                display += "-" * 50 + "\n"
                for user in users:
                    display += f"\n  [{user['name']}]\n"

                    # Token auth
                    if user.get("token"):
                        token = user["token"]
                        display += f"    Token:       {token[:30]}... (truncated)\n"
                    if user.get("token_file"):
                        display += f"    Token File:  {user['token_file']}\n"

                    # Cert auth
                    if user.get("client_certificate") or user.get("client_certificate_data"):
                        display += "    Client Cert: present\n"
                    if user.get("client_key") or user.get("client_key_data"):
                        display += "    Client Key:  present\n"

                    # Basic auth
                    if user.get("username"):
                        display += f"    Username:    {user['username']}\n"
                    if user.get("password"):
                        display += f"    Password:    {user['password']}\n"

                    # Exec auth
                    if user.get("exec"):
                        exec_info = user["exec"]
                        args_str = ' '.join(exec_info.get('args', []))
                        cmd = f"{exec_info['command']} {args_str}"
                        display += f"    Exec:        {cmd}\n"
                        if exec_info.get("env"):
                            for env_var in exec_info["env"]:
                                if env_var:
                                    display += f"    Exec Env:    {env_var['name']}={env_var['value']}\n"

                    # Auth provider
                    if user.get("auth_provider"):
                        auth_info = user["auth_provider"]
                        display += f"    AuthProvider: {auth_info['name']}\n"
                        sensitive = auth_info.get("sensitive_fields", {})
                        for key, value in sensitive.items():
                            if value:
                                display_val = f"{value[:30]}..." if len(str(value)) > 35 else value
                                display += f"    {key}: {display_val}\n"

                    # Impersonation
                    if user.get("impersonate"):
                        display += f"    Impersonate: {user['impersonate']}\n"
                    if user.get("impersonate_uid"):
                        display += f"    Imp. UID:    {user['impersonate_uid']}\n"
                    if user.get("impersonate_groups"):
                        display += f"    Imp. Groups: {', '.join(user['impersonate_groups'])}\n"
                    if user.get("impersonate_extra"):
                        display += f"    Imp. Extra:  {user['impersonate_extra']}\n"

                # Contexts section
                display += f"\n\nCONTEXTS ({len(contexts)})\n"
                display += "-" * 50 + "\n"
                for ctx in contexts:
                    is_current = ctx["name"] == current_context
                    marker = " (CURRENT)" if is_current else ""
                    display += f"\n  [{ctx['name']}]{marker}\n"
                    display += f"    Cluster:   {ctx['cluster']}\n"
                    display += f"    User:      {ctx['user']}\n"
                    if ctx.get("namespace"):
                        display += f"    Namespace: {ctx['namespace']}\n"

                tmp_display_file.write(display)
                tmp_display_file.flush()

                display_object_id = self.storage.upload_file(tmp_display_file.name)

                displayable_parsed = Transform(
                    type="displayable_parsed",
                    object_id=f"{display_object_id}",
                    metadata={
                        "file_name": f"{file_enriched.file_name}_analysis.txt",
                        "display_type_in_dashboard": "monaco",
                        "default_display": True,
                    },
                )
                enrichment_result.transforms = [displayable_parsed]

            return enrichment_result

        except Exception:
            logger.exception(message=f"Error analyzing kubeconfig for {file_enriched.file_name}")
            return None

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process kubeconfig file and extract cluster/credential details.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            EnrichmentResult or None if processing fails
        """
        try:
            file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

            # Use provided file_path if available, otherwise download
            if file_path:
                return self._analyze_kubeconfig(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as temp_file:
                    return self._analyze_kubeconfig(temp_file.name, file_enriched)

        except Exception:
            logger.exception(message="Error processing kubeconfig file")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return KubeconfigParser()
