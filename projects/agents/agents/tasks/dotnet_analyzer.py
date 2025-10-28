"""
Adapted directly from https://github.com/dreadnode/example-agents/tree/6dbbfe85b335618ca5f4ca2bc5f439052b84d0b1/dotnet_reversing
Author: @dreadnode
License: None
"""

import json
import os
import sys
import tempfile
import typing as t
from dataclasses import dataclass
from pathlib import Path

import psycopg
import structlog
from agents.base_agent import BaseAgent
from agents.logger import set_agent_metadata
from agents.model_manager import ModelManager
from agents.prompt_manager import PromptManager
from agents.schemas import DotNetAnalysisResponse
from common.db import get_postgres_connection_str
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext
from pydantic_ai import Agent, RunContext
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.settings import ModelSettings
from pydantic_ai.usage import UsageLimits
from pythonnet import load  # type: ignore [import-untyped]

logger = structlog.get_logger(__name__)

# Load .NET runtime
load("coreclr")

import clr  # type: ignore [import-untyped] # noqa: E402

# Add references to .NET libraries
lib_dir = Path(__file__).parent.parent / "lib"
sys.path.append(str(lib_dir))

clr.AddReference("ICSharpCode.Decompiler")
clr.AddReference("Mono.Cecil")

from ICSharpCode.Decompiler import (  # type: ignore [import-not-found] # noqa: E402
    DecompilerSettings,
)
from ICSharpCode.Decompiler.CSharp import (  # type: ignore [import-not-found] # noqa: E402
    CSharpDecompiler,
)
from ICSharpCode.Decompiler.Metadata import (  # type: ignore [import-not-found] # noqa: E402
    MetadataTokenHelpers,
)
from Mono.Cecil import AssemblyDefinition  # type: ignore [import-not-found] # noqa: E402

# Helper functions (adapted from dotnet_reversing/reversing.py)


def _shorten_dotnet_name(name: str) -> str:
    return name.split(" ")[-1].split("(")[0]


def _get_decompiler(path: Path | str) -> CSharpDecompiler:
    settings = DecompilerSettings()
    settings.ThrowOnAssemblyResolveErrors = False
    return CSharpDecompiler(str(path), settings)


def _decompile_token(path: Path | str, token: int) -> str:
    entity_handle = MetadataTokenHelpers.TryAsEntityHandle(token.ToUInt32())  # type: ignore [attr-defined]
    return _get_decompiler(path).DecompileAsString(entity_handle)  # type: ignore [no-any-return]


def _find_references(assembly: AssemblyDefinition, search: str) -> list[str]:
    flexible_search_strings = [
        search.lower(),
        search.lower().replace(".", "::"),
        search.lower().replace("::", "."),
    ]

    using_methods: set[str] = set()
    for module in assembly.Modules:
        methods = []
        for module_type in module.Types:
            for method in module_type.Methods:
                methods.append(method)

        for method in methods:
            if not method.HasBody:
                continue

            for instruction in method.Body.Instructions:
                intruction_str = str(instruction.Operand).lower()

                for _search in flexible_search_strings:
                    if _search in intruction_str:
                        using_methods.add(method.FullName)

    return list(using_methods)


DEFAULT_EXCLUDE = [
    "mscorlib.dll",
]


@dataclass
class DotnetReversing:
    """Adapted from @dreadnode's dotnet_reversing/reversing.py"""

    file_path: Path

    @classmethod
    def from_file(cls, path: Path | str) -> "DotnetReversing":
        file_path = Path(path)
        if not file_path.exists():
            raise ValueError(f"File path does not exist: {file_path}")
        return cls(file_path=file_path)

    def decompile_module(self) -> str:
        """Decompile the entire module and return the decompiled code as a string."""
        logger.info(f"decompile_module({self.file_path})")
        return _get_decompiler(self.file_path).DecompileWholeModuleAsString()  # type: ignore [no-any-return]

    def decompile_type(self, type_name: str) -> str:
        """Decompile a specific type and return the decompiled code as a string."""
        logger.info(f"decompile_type({self.file_path}, {type_name})")
        try:
            # Use metadata token approach directly since the API signature is different
            assembly = AssemblyDefinition.ReadAssembly(str(self.file_path))
            for module in assembly.Modules:
                for module_type in module.Types:
                    if module_type.FullName == type_name:
                        return _decompile_token(self.file_path, module_type.MetadataToken)
            return f"Type '{type_name}' not found in assembly"
        except Exception as e:
            logger.error(f"Error decompiling type '{type_name}': {e}")
            return f"Error decompiling type '{type_name}': {str(e)}"

    def list_namespaces(self) -> list[str]:
        """List all namespaces in the assembly."""
        logger.info(f"list_namespaces({self.file_path})")
        assembly = AssemblyDefinition.ReadAssembly(str(self.file_path))

        namespaces = set()
        for module in assembly.Modules:
            for module_type in module.Types:
                if "." in module_type.FullName:
                    # Get namespace part (everything before the last dot)
                    namespace = ".".join(module_type.FullName.split(".")[:-1])
                    namespaces.add(namespace)
                else:
                    # Handle types without namespace (add as root)
                    namespaces.add("<root>")

        return sorted(namespaces)

    def list_types_in_namespace(self, namespace: str) -> list[str]:
        """List all types in the specified namespace."""
        logger.info(f"list_types_in_namespace({self.file_path}, {namespace})")
        assembly = AssemblyDefinition.ReadAssembly(str(self.file_path))

        types = []
        for module in assembly.Modules:
            for module_type in module.Types:
                if namespace == "<root>":
                    # Handle types without namespace
                    if "." not in module_type.FullName or (
                        module_type.FullName.count(".") == 1 and module_type.FullName.endswith("Module")
                    ):
                        types.append(module_type.FullName)
                elif module_type.FullName.startswith(f"{namespace}."):
                    # Check if the type belongs directly to this namespace (not a sub-namespace)
                    remainder = module_type.FullName[len(namespace) + 1 :]
                    if "." not in remainder:
                        types.append(module_type.FullName)

        return types

    def list_types(self) -> list[str]:
        """List all types in the assembly and return their full names."""
        logger.info(f"list_types({self.file_path})")
        assembly = AssemblyDefinition.ReadAssembly(str(self.file_path))
        return [module_type.FullName for module in assembly.Modules for module_type in module.Types]

    def list_methods(self) -> list[str]:
        """List all methods in the assembly and return their full names."""
        logger.info(f"list_methods({self.file_path})")
        assembly = AssemblyDefinition.ReadAssembly(str(self.file_path))
        methods: list[str] = []
        for module in assembly.Modules:
            for module_type in module.Types:
                methods.extend([method.FullName for method in module_type.Methods])
        return methods

    def search_for_references(self, search: str) -> list[str]:
        """Locate all methods inside the assembly that reference the search string."""
        logger.info(f"search_for_references({self.file_path}, {search})")
        assembly = AssemblyDefinition.ReadAssembly(str(self.file_path))
        return _find_references(assembly, search)

    def decompile_methods(self, method_names: list[str]) -> dict[str, str]:
        """Decompile specific methods and return a dictionary with method names as keys and decompiled code as values."""
        logger.info(f"decompile_methods({self.file_path}, {method_names})")
        flexible_method_names = [_shorten_dotnet_name(name).lower() for name in method_names]
        assembly = AssemblyDefinition.ReadAssembly(str(self.file_path))
        methods: dict[str, str] = {}
        for module in assembly.Modules:
            for module_type in module.Types:
                for method in module_type.Methods:
                    method_name = _shorten_dotnet_name(method.FullName).lower()
                    if method_name in flexible_method_names:
                        methods[method.FullName] = _decompile_token(self.file_path, method.MetadataToken)
        return methods

    def list_methods_in_type(self, type_name: str) -> list[str]:
        """List all methods in the specified type."""
        logger.info(f"list_methods_in_type({self.file_path}, {type_name})")
        assembly = AssemblyDefinition.ReadAssembly(str(self.file_path))

        methods = []
        for module in assembly.Modules:
            for module_type in module.Types:
                if module_type.FullName == type_name:
                    methods.extend([method.Name for method in module_type.Methods])
                    break

        return methods

    def search_by_name(self, search: str) -> dict[str, list[str]]:
        """Search for types and methods in the assembly that match the search string."""
        logger.info(f"search_by_name({self.file_path}, {search})")

        results: dict[str, list[str]] = {
            "types": [],
            "methods": [],
        }

        assembly = AssemblyDefinition.ReadAssembly(str(self.file_path))
        search_lower = search.lower()

        # Type search
        for module in assembly.Modules:
            for module_type in module.Types:
                if search_lower in module_type.FullName.lower():
                    results["types"].append(module_type.FullName)

        # Method search
        for module in assembly.Modules:
            for module_type in module.Types:
                for method in module_type.Methods:
                    if search_lower in method.FullName.lower():
                        results["methods"].append(method.FullName)

        return results

    def get_call_flows_to_method(self, method_name: str, max_depth: int = 10) -> list[list[str]]:
        """Find all unique call flows to the target method and return nested list of method names representing call paths."""
        logger.info(f"get_call_flows_to_method({self.file_path}, {method_name})")

        def _extract_unique_call_paths(
            tree: dict[str, t.Any], current_path: list[str] | None = None
        ) -> list[list[str]]:
            if current_path is None:
                current_path = []

            if not tree:  # Leaf node
                return [current_path] if current_path else []

            paths = []
            for method, subtree in tree.items():
                new_path = [method, *current_path]
                paths.extend(_extract_unique_call_paths(subtree, new_path))

            return paths

        assembly = AssemblyDefinition.ReadAssembly(str(self.file_path))
        short_target_name = _shorten_dotnet_name(method_name)

        def build_tree(method_name: str, current_depth: int = 0, visited: set[str] | None = None) -> dict[str, t.Any]:
            visited = visited or set()
            if method_name in visited or current_depth > max_depth:
                return {}

            visited.add(method_name)
            tree = {}

            for caller in _find_references(assembly, method_name):
                if caller not in visited:
                    tree[caller] = build_tree(
                        _shorten_dotnet_name(caller),
                        current_depth + 1,
                        visited.copy(),
                    )

            return tree

        call_tree = build_tree(short_target_name)
        return _extract_unique_call_paths(call_tree)


class DotNetAnalyzer(BaseAgent):
    """Agent for analyzing .NET assemblies using LLM."""

    def __init__(self):
        super().__init__()
        self.prompt_manager = PromptManager(get_postgres_connection_str())
        self.name = ".NET Assembly Analyzer"
        self.description = "Adapted @dreadnode agent that analyzes .NET assemblies"
        self.agent_type = "llm_based"
        self.has_prompt = True
        self.llm_temperature = 0.3
        # Usage limits from environment variables with defaults
        self.request_limit = int(os.getenv("DOTNET_ANALYSIS_RUN_REQUEST_LIMIT", 25))
        self.total_tokens_limit = int(os.getenv("DOTNET_ANALYSIS_RUN_TOKENS_LIMIT", 1_000_000))
        #         self.system_prompt = """You are a .NET reverse engineering expert with access to decompilation and analysis tools.

        # Analyze the following .NET assembly and resolve the task below using all the tools available to you.
        # Provide a report for all interesting findings you discover while performing the task.

        # Focus your analysis on:
        # 1. **Architecture & Design Patterns**: Identify architectural patterns, design patterns used
        # 2. **Security Analysis**: Highlight potential security concerns, suspicious methods, crypto usage
        # 3. **Functionality Assessment**: Describe what the assembly does, its main purposes
        # 4. **Key Components**: Identify the most important classes, methods, and namespaces
        # 5. **External Dependencies**: Note any interesting external API calls or P/Invoke usage
        # 6. **Obfuscation/Protection**: Identify any signs of obfuscation, packing, or anti-analysis

        # Provide your analysis in markdown format with clear sections and practical insights for a security analyst."""

        self.system_prompt = """You are a .NET security vulnerability analyst with access to decompilation and analysis tools.

Use the available tools systematically to analyze the assembly:
1. Start with high-level overview (namespaces, types)
2. Focus on security-relevant code patterns
3. Decompile suspicious methods for detailed analysis

Provide analysis in markdown format with actionable security findings."""
        self.storage = StorageMinio()
        self.dotnet_analyzer = None  # Will be set during execution
        self.postgres_connection_url = get_postgres_connection_str()

    def decompile_module(self, ctx: RunContext) -> str:
        """Decompile the entire module and return the decompiled code as a string."""
        if not self.dotnet_analyzer:
            return "Error: .NET analyzer not initialized"
        return self.dotnet_analyzer.decompile_module()

    def decompile_type(self, ctx: RunContext, type_name: t.Annotated[str, "The specific type to decompile"]) -> str:
        """Decompile a specific type and return the decompiled code as a string."""
        if not self.dotnet_analyzer:
            return "Error: .NET analyzer not initialized"
        return self.dotnet_analyzer.decompile_type(type_name)

    def decompile_methods(
        self, ctx: RunContext, method_names: t.Annotated[list[str], "List of methods to decompile"]
    ) -> dict[str, str]:
        """Decompile specific methods and return a dictionary with method names as keys and decompiled code as values."""
        if not self.dotnet_analyzer:
            return {"error": ".NET analyzer not initialized"}
        return self.dotnet_analyzer.decompile_methods(method_names)

    def list_namespaces(self, ctx: RunContext) -> list[str]:
        """List all namespaces in the assembly."""
        if not self.dotnet_analyzer:
            logger.error("TOOL ERROR: .NET analyzer not initialized")
            return ["Error: .NET analyzer not initialized"]
        result = self.dotnet_analyzer.list_namespaces()
        return result

    def list_types_in_namespace(
        self, ctx: RunContext, namespace: t.Annotated[str, "The namespace to list types from"]
    ) -> list[str]:
        """List all types in the specified namespace."""
        if not self.dotnet_analyzer:
            return ["Error: .NET analyzer not initialized"]
        return self.dotnet_analyzer.list_types_in_namespace(namespace)

    def list_methods_in_type(self, ctx: RunContext, type_name: t.Annotated[str, "The full type name"]) -> list[str]:
        """List all methods in the specified type."""
        if not self.dotnet_analyzer:
            return ["Error: .NET analyzer not initialized"]
        return self.dotnet_analyzer.list_methods_in_type(type_name)

    def list_types(self, ctx: RunContext) -> list[str]:
        """List all types in the assembly and return their full names."""
        if not self.dotnet_analyzer:
            logger.error("TOOL ERROR: .NET analyzer not initialized")
            return ["Error: .NET analyzer not initialized"]
        result = self.dotnet_analyzer.list_types()
        return result

    def list_methods(self, ctx: RunContext) -> list[str]:
        """List all methods in the assembly and return their full names."""
        if not self.dotnet_analyzer:
            return ["Error: .NET analyzer not initialized"]
        return self.dotnet_analyzer.list_methods()

    def search_for_references(
        self, ctx: RunContext, search: t.Annotated[str, "A flexible search string used to check called function names"]
    ) -> list[str]:
        """Locate all methods inside the assembly that reference the search string. This can be used to locate uses of a specific function or method anywhere in the assembly."""
        if not self.dotnet_analyzer:
            return ["Error: .NET analyzer not initialized"]
        return self.dotnet_analyzer.search_for_references(search)

    def get_call_flows_to_method(
        self, ctx: RunContext, method_name: t.Annotated[str, "Target method name"], max_depth: int = 10
    ) -> list[list[str]]:
        """Find all unique call flows to the target method and return a nested list of method names representing the call paths."""
        if not self.dotnet_analyzer:
            return [["Error: .NET analyzer not initialized"]]
        return self.dotnet_analyzer.get_call_flows_to_method(method_name, max_depth)

    def _is_dotnet_file(self, object_id: str) -> bool:
        """Check if the file is a .NET assembly."""
        try:
            file_enriched = get_file_enriched(object_id)
            return "mono/.net assembly" in file_enriched.magic_type.lower()
        except Exception as e:
            logger.error(f"Error checking if file is .NET assembly: {e}")
            return False

    def get_prompt(self) -> str:
        """Get the .NET analysis prompt from database or use default."""
        try:
            # Try to get prompt from database
            prompt_data = self.prompt_manager.get_prompt(self.name)

            if prompt_data:
                return prompt_data["prompt"]
            else:
                # No prompt in database, try to save default
                logger.info("No prompt found in database, initializing with default", agent_name=self.name)
                success = self.prompt_manager.save_prompt(self.name, self.system_prompt, self.description)
                if success:
                    logger.info("Default prompt saved to database", agent_name=self.name)
                else:
                    # This is expected during startup when event loop is running
                    logger.debug(
                        "Could not save default prompt to database (likely during startup)", agent_name=self.name
                    )

                return self.system_prompt

        except Exception as e:
            logger.warning("Error managing prompt, using default", agent_name=self.name, error=str(e))
            return self.system_prompt

    def execute(self, ctx: WorkflowActivityContext, activity_input: dict) -> dict:
        """Analyze .NET assembly content in the given file using interactive tools."""
        object_id = activity_input.get("object_id", "")

        logger.debug(".NET analysis activity started", object_id=object_id)

        # Check if this is a .NET file
        if not self._is_dotnet_file(object_id):
            return {"success": False, "error": "File is not a .NET assembly"}

        model = ModelManager.get_model()

        if not model:
            logger.warning("No model available from ModelManager")
            return {"success": False, "error": "AI model not available for .NET analysis"}

        try:
            # Set metadata for this agent run
            set_agent_metadata(
                agent_name="dotnet_analyzer",
                object_id=object_id,
                tags=["dotnet", "reverse_engineering"],
            )

            # Download the file to a temporary location for analysis
            file_enriched = get_file_enriched(object_id)
            with self.storage.download(object_id) as temp_file:
                # Initialize the dotnet analyzer for use by tools
                self.dotnet_analyzer = DotnetReversing.from_file(temp_file.name)

                # Get the current prompt from database or default
                current_prompt = self.get_prompt()

                # Create agent with tools
                agent = Agent(
                    model=model,
                    system_prompt=current_prompt,
                    output_type=DotNetAnalysisResponse,
                    instrument=ModelManager.is_instrumentation_enabled(),
                    retries=3,
                    model_settings=ModelSettings(
                        temperature=self.llm_temperature,
                        max_tokens=16384,  # Allow for detailed analysis output
                    ),
                )

                # Add tools to the agent
                agent.tool(self.decompile_module)
                agent.tool(self.decompile_type)
                agent.tool(self.decompile_methods)
                agent.tool(self.list_namespaces)
                agent.tool(self.list_types_in_namespace)
                agent.tool(self.list_methods_in_type)
                agent.tool(self.list_types)
                agent.tool(self.list_methods)
                agent.tool(self.search_for_references)
                agent.tool(self.get_call_flows_to_method)

                prompt = f"""<task>
Analyze this .NET assembly for security vulnerabilities. Focus on:
- Input validation issues (SQL injection, path traversal, etc.)
- Authentication/authorization bypasses
- Cryptographic weaknesses
- Unsafe deserialization
- Privilege escalation vectors

Prioritize findings by exploitability and business impact.
</task>

<files>
{file_enriched.file_name} (analyzing: {temp_file.name})
</files>"""

                try:
                    result = agent.run_sync(
                        prompt,
                        usage_limits=UsageLimits(
                            request_limit=self.request_limit, total_tokens_limit=self.total_tokens_limit
                        ),
                    )
                except UsageLimitExceeded as e:
                    logger.error(".NET analysis hit usage limit", error=str(e), object_id=object_id)
                    return {"success": False, "error": f"Analysis hit usage limit: {str(e)}"}
                logger.debug(
                    ".NET analysis LLM analysis completed",
                    object_id=object_id,
                    total_tokens=result.usage().total_tokens,
                    request_tokens=result.usage().request_tokens,
                    response_tokens=result.usage().response_tokens,
                )

                analysis = result.output.analysis

                # Store the analysis as a file
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_analysis:
                    tmp_analysis.write(analysis)
                    tmp_analysis.flush()
                    analysis_id = self.storage.upload_file(tmp_analysis.name)

                # Add transform to database
                with psycopg.connect(self.postgres_connection_url) as conn:
                    with conn.cursor() as cur:
                        metadata = {
                            "file_name": "dotnet_analysis.md",
                            "display_type_in_dashboard": "markdown",
                            "display_title": ".NET Assembly Analysis",
                            "default_display": True,
                        }

                        cur.execute(
                            """
                            INSERT INTO transforms (object_id, type, transform_object_id, metadata)
                            VALUES (%s, %s, %s, %s)
                            """,
                            (object_id, "dotnet_analysis", analysis_id, json.dumps(metadata)),
                        )
                    conn.commit()

                logger.debug(".NET analysis completed", object_id=object_id)
                return {"success": True, "transform_id": analysis_id}

        except Exception as e:
            logger.error(".NET analysis failed", object_id=object_id, error=str(e))
            return {"success": False, "error": str(e)}


def analyze_dotnet_assembly(ctx: WorkflowActivityContext, activity_input: dict) -> dict:
    """Wrapper function to maintain compatibility with existing workflow calls."""
    agent = DotNetAnalyzer()
    return agent.execute(ctx, activity_input)
