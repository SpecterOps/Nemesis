"""Chatbot agent for interactive querying of Nemesis data."""

import asyncio
import os
from collections.abc import AsyncGenerator
from pathlib import Path

import httpx
import structlog
from agents.base_agent import BaseAgent
from agents.logger import set_agent_metadata
from agents.model_manager import ModelManager
from agents.prompt_manager import PromptManager
from common.db import get_postgres_connection_str
from fastapi import HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStreamableHTTP
from pydantic_ai.settings import ModelSettings

logger = structlog.get_logger(__name__)

# MCP Server configuration
MCP_SERVER_HOST = "127.0.0.1"
MCP_SERVER_PORT = 5000
MCP_SERVER_URL = f"http://{MCP_SERVER_HOST}:{MCP_SERVER_PORT}/mcp"
MCP_STARTUP_TIMEOUT = float(os.getenv("MCP_STARTUP_TIMEOUT", "30"))
MCP_HEALTH_CHECK_INTERVAL = 0.5
MCP_HEALTH_CHECK_RETRIES = int(MCP_STARTUP_TIMEOUT / MCP_HEALTH_CHECK_INTERVAL)


class ChatMessage(BaseModel):
    """A single chat message."""

    role: str  # "user" or "assistant"
    content: str


class ChatbotRequest(BaseModel):
    """Request model for chatbot queries."""

    message: str
    history: list[ChatMessage] = []
    use_history: bool = True
    temperature: float = 0.7


class ChatbotAgent(BaseAgent):
    """Agent for interactive data querying via natural language."""

    def __init__(self):
        super().__init__()
        self.prompt_manager = PromptManager(get_postgres_connection_str())
        self.name = "chatbot"
        self.description = "Interactive chatbot for querying Nemesis data"
        self.agent_type = "llm_based"
        self.has_prompt = True
        self.llm_temperature = 0.7  # Default, can be overridden per request

        # Get max rows from environment
        max_results = int(os.getenv("MCP_MAX_RESULTS", "1000"))

        # System prompt - will be saved to DB on first use
        self.system_prompt = f"""You are a data query assistant for Nemesis, an offensive security data platform.

Your role is to retrieve and report data from the database. Do NOT provide recommendations, analysis, or suggestions - only report the requested data. You have access to MCP tools to query the Nemesis PostgreSQL database.

When answering questions:
1. Query the database using the appropriate tools
2. Report ONLY the data retrieved unless explicitly instructed otherwise - i.e., no analysis or recommendations unless a user explicitly asks for it
3. Present results clearly and concisely
4. For large result sets, summarize counts and key details
5. Use case-insensitive pattern matching for host/source filters
6. Be brief - users want facts, not explanations unless they explicitly request them
7. Don't return the "project" field to users

Query Guidelines:
- Use a `limit` of {max_results} for maximum results
- Filter by severity, category, or source to narrow results
- Use search-document-content when users ask to search "for" or "containing" specific text but otherwise restrict your usage of "search-document-content" since it can return a lot of results
- a `originating_object_id` field points to the `object_id` the finding/file originated from

Searching for Credentials to Access Systems:
When users ask about accessing a specific system or finding credentials for a hostname, follow this order:
1. First, use search-credential-findings-by-host to find credential findings related to the target hostname
2. Second, use search-logins-by-host to find decrypted browser credentials for the target hostname
3. Only as a last resort, if the above return no results, use search-document-content with the hostname to search file contents
This order ensures you check the most relevant credential sources first before falling back to broader document searches.
"""

        self._mcp_process: asyncio.subprocess.Process | None = None
        self._mcp_stdout_task: asyncio.Task | None = None
        self._mcp_stderr_task: asyncio.Task | None = None
        self._mcp_ready = asyncio.Event()

    def get_prompt(self) -> str:
        """Get the chatbot prompt from database or use default."""
        try:
            prompt_data = self.prompt_manager.get_prompt(self.name)

            if prompt_data:
                return prompt_data["prompt"]
            else:
                logger.info("No prompt found in database, initializing with default", agent_name=self.name)
                success = self.prompt_manager.save_prompt(self.name, self.system_prompt, self.description)
                if success:
                    logger.info("Default prompt saved to database", agent_name=self.name)
                else:
                    logger.debug(
                        "Could not save default prompt to database (likely during startup)", agent_name=self.name
                    )

                return self.system_prompt

        except Exception as e:
            logger.warning("Error managing prompt, using default", agent_name=self.name, error=str(e))
            return self.system_prompt

    def execute(self, ctx, activity_input: dict) -> dict:
        """
        Execute method required by BaseAgent.

        Note: ChatbotAgent is designed for interactive HTTP streaming,
        not workflow-based execution. Use the chatbot_stream endpoint instead.
        """
        logger.warning("ChatbotAgent.execute called but this agent is designed for HTTP streaming only")
        return {
            "success": False,
            "error": "ChatbotAgent does not support workflow execution. Use /agents/chatbot/stream endpoint instead.",
        }

    def _get_chatbot_connection_string(self) -> str:
        """Get PostgreSQL connection string for chatbot read-only user."""
        chatbot_password = os.getenv("CHATBOT_DB_PASSWORD", "chatbot_pass_change_me")
        postgres_host = os.getenv("POSTGRES_HOST", "postgres")
        postgres_port = os.getenv("POSTGRES_PORT", "5432")
        postgres_db = os.getenv("POSTGRES_DB", "enrichment")
        postgres_params = os.getenv("POSTGRES_PARAMETERS", "sslmode=disable")

        return f"postgresql://chatbot_readonly:{chatbot_password}@{postgres_host}:{postgres_port}/{postgres_db}?{postgres_params}"

    async def _stream_output(self, stream: asyncio.StreamReader, name: str) -> None:
        """Stream subprocess output to logger without blocking."""
        try:
            while True:
                line = await stream.readline()
                if not line:
                    break
                decoded = line.decode().rstrip()
                if decoded:
                    logger.debug(f"MCP server {name}", output=decoded)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning(f"Error reading MCP server {name}", error=str(e))

    async def _check_mcp_health(self) -> bool:
        """Check if the MCP server is responding to requests."""
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                # genai-toolbox responds to GET on the /mcp endpoint
                response = await client.get(MCP_SERVER_URL)
                # 405 Method Not Allowed is expected for GET on MCP endpoint (it wants POST)
                # 200 or any response means the server is up
                return response.status_code in (200, 405)
        except httpx.ConnectError:
            return False
        except httpx.TimeoutException:
            return False
        except Exception as e:
            logger.debug("MCP health check failed", error=str(e))
            return False

    async def _wait_for_mcp_ready(self) -> bool:
        """Wait for MCP server to become ready with retries."""
        for attempt in range(MCP_HEALTH_CHECK_RETRIES):
            if await self._check_mcp_health():
                logger.info(
                    "MCP server is ready",
                    attempts=attempt + 1,
                    url=MCP_SERVER_URL,
                )
                return True

            # Check if process died
            if self._mcp_process and self._mcp_process.returncode is not None:
                return False

            await asyncio.sleep(MCP_HEALTH_CHECK_INTERVAL)

        return False

    def _is_mcp_running(self) -> bool:
        """Check if the MCP process is still running."""
        return self._mcp_process is not None and self._mcp_process.returncode is None

    async def start_mcp_server(self) -> None:
        """Start the genai-toolbox MCP server as a subprocess listening on HTTP.

        Uses asyncio.create_subprocess_exec for non-blocking subprocess management.
        Performs health checks to verify the server is actually ready before returning.

        Raises:
            FileNotFoundError: If tools.yaml configuration is missing
            RuntimeError: If the server fails to start or become ready within timeout
        """
        # Check if process is already running and healthy
        if self._is_mcp_running():
            if await self._check_mcp_health():
                logger.debug("MCP server already running and healthy")
                return
            else:
                logger.warning("MCP process running but unhealthy, restarting")
                await self.stop_mcp_server()

        # Check if another instance is already running (e.g., from previous container)
        if await self._check_mcp_health():
            logger.info("MCP server already running externally", url=MCP_SERVER_URL)
            self._mcp_ready.set()
            return

        tools_file = Path(__file__).parent.parent / "mcp" / "tools.yaml"
        if not tools_file.exists():
            raise FileNotFoundError(f"MCP tools configuration not found at {tools_file}")

        # Get database connection string for chatbot readonly user
        db_url = self._get_chatbot_connection_string()

        # Prepare environment with database URL
        env = {**os.environ, "DATABASE_URL": db_url}

        logger.info(
            "Starting genai-toolbox MCP HTTP server",
            tools_file=str(tools_file),
            address=f"0.0.0.0:{MCP_SERVER_PORT}",
        )

        try:
            # Use asyncio.create_subprocess_exec for proper async subprocess management
            self._mcp_process = await asyncio.create_subprocess_exec(
                "genai-toolbox",
                "--tools-file",
                str(tools_file),
                "--address",
                "0.0.0.0",
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Start background tasks to drain stdout/stderr (prevents pipe buffer blocking)
            if self._mcp_process.stdout:
                self._mcp_stdout_task = asyncio.create_task(
                    self._stream_output(self._mcp_process.stdout, "stdout"),
                    name="mcp_stdout_reader",
                )
            if self._mcp_process.stderr:
                self._mcp_stderr_task = asyncio.create_task(
                    self._stream_output(self._mcp_process.stderr, "stderr"),
                    name="mcp_stderr_reader",
                )

            # Wait for the server to become ready
            if await self._wait_for_mcp_ready():
                self._mcp_ready.set()
                logger.info(
                    "MCP HTTP server started successfully",
                    url=MCP_SERVER_URL,
                    pid=self._mcp_process.pid,
                )
                return

            # Server didn't become ready - collect error information
            error_context = {"timeout": MCP_STARTUP_TIMEOUT}

            if self._mcp_process.returncode is not None:
                error_context["return_code"] = self._mcp_process.returncode

            await self.stop_mcp_server()
            raise RuntimeError(
                f"MCP server failed to become ready within {MCP_STARTUP_TIMEOUT}s. "
                f"Check logs for genai-toolbox errors. Context: {error_context}"
            )

        except FileNotFoundError as e:
            raise RuntimeError("genai-toolbox binary not found. Ensure it is installed and in PATH.") from e
        except PermissionError as e:
            raise RuntimeError("Permission denied when starting genai-toolbox. Check file permissions.") from e
        except Exception as e:
            await self.stop_mcp_server()
            raise RuntimeError(f"Failed to start MCP server: {e}") from e

    async def stop_mcp_server(self) -> None:
        """Stop the MCP server subprocess gracefully.

        Cancels output reader tasks and terminates the subprocess with a timeout.
        Falls back to SIGKILL if graceful shutdown fails.
        """
        self._mcp_ready.clear()

        # Cancel output reader tasks
        for task, name in [
            (self._mcp_stdout_task, "stdout"),
            (self._mcp_stderr_task, "stderr"),
        ]:
            if task and not task.done():
                task.cancel()
                try:
                    await asyncio.wait_for(task, timeout=1.0)
                except (TimeoutError, asyncio.CancelledError):
                    pass
                except Exception as e:
                    logger.debug(f"Error cancelling {name} task", error=str(e))

        self._mcp_stdout_task = None
        self._mcp_stderr_task = None

        # Terminate the process
        if self._mcp_process is None:
            return

        if self._mcp_process.returncode is not None:
            logger.debug("MCP process already exited", return_code=self._mcp_process.returncode)
            self._mcp_process = None
            return

        logger.info("Stopping MCP server", pid=self._mcp_process.pid)

        try:
            self._mcp_process.terminate()
            try:
                await asyncio.wait_for(self._mcp_process.wait(), timeout=5.0)
                logger.info("MCP server stopped gracefully")
            except TimeoutError:
                logger.warning("MCP server didn't stop gracefully, sending SIGKILL")
                self._mcp_process.kill()
                await asyncio.wait_for(self._mcp_process.wait(), timeout=2.0)
        except ProcessLookupError:
            logger.debug("MCP process already terminated")
        except Exception as e:
            logger.warning("Error stopping MCP server", error=str(e))
        finally:
            self._mcp_process = None

    async def ensure_mcp_ready(self) -> None:
        """Ensure the MCP server is running and ready.

        Raises:
            RuntimeError: If the MCP server cannot be started or is unhealthy
        """
        if self._mcp_ready.is_set() and await self._check_mcp_health():
            return

        # Server not ready, try to start it
        await self.start_mcp_server()

    async def stream_chat_response(self, request: ChatbotRequest) -> AsyncGenerator[str]:
        """
        Stream chatbot responses token-by-token.

        Args:
            request: ChatbotRequest with message, history, and settings

        Yields:
            Chunks of the response as they're generated
        """
        model = ModelManager.get_model()

        if not model:
            logger.warning("No model available from ModelManager")
            raise HTTPException(status_code=503, detail="AI model not available")

        try:
            # Set metadata for Phoenix tracing
            set_agent_metadata(
                agent_name="chatbot",
                message_length=len(request.message),
                has_history=len(request.history) > 0 if request.use_history else False,
                tags=["chatbot", "interactive_query"],
            )

            # Get current prompt from database
            current_prompt = self.get_prompt()

            # Build conversation history if enabled
            conversation = ""
            if request.use_history and request.history:
                for msg in request.history:
                    role_label = "User" if msg.role == "user" else "Assistant"
                    conversation += f"{role_label}: {msg.content}\n\n"

            # Add current message
            conversation += f"User: {request.message}\n\nAssistant:"

            # Connect to MCP HTTP server (genai-toolbox running on http://127.0.0.1:5000/mcp)
            mcp_server = MCPServerStreamableHTTP(url="http://127.0.0.1:5000/mcp")

            # Create agent with MCP tools
            agent = Agent(
                model=model,
                system_prompt=current_prompt,
                toolsets=[mcp_server],
                instrument=ModelManager.is_instrumentation_enabled(),
                retries=5,  # Increased from 2 to handle transient MCP tool failures
                model_settings=ModelSettings(temperature=request.temperature),
            )

            logger.info("Starting chatbot stream", message=request.message, temperature=request.temperature)

            # When tools are involved, streaming doesn't work as expected
            # Get the complete result and send it
            result = await agent.run(conversation)

            # Log tool calls and their results with full details
            tool_calls = []
            tool_errors = []
            if hasattr(result, "all_messages"):
                for msg_idx, msg in enumerate(result.all_messages()):
                    logger.debug(
                        f"Message {msg_idx}: type={type(msg).__name__}, role={getattr(msg, 'role', 'unknown')}"
                    )
                    if hasattr(msg, "parts"):
                        for part_idx, part in enumerate(msg.parts):
                            part_type = type(part).__name__
                            logger.debug(f"  Part {part_idx}: type={part_type}")

                            # Log tool calls (requests)
                            if hasattr(part, "tool_name"):
                                tool_info = {"tool": part.tool_name, "args": getattr(part, "args", {})}
                                logger.info(f"TOOL CALL: {part.tool_name}", args=tool_info["args"])
                                tool_calls.append(tool_info)

                            # Log tool returns (responses)
                            if hasattr(part, "tool_name") and hasattr(part, "content"):
                                full_content = str(part.content)
                                logger.debug(
                                    f"TOOL RESPONSE: {part.tool_name}",
                                    content_length=len(full_content),
                                    full_content=full_content,  # Log FULL content for debugging
                                )

                            # Log errors
                            if hasattr(part, "error"):
                                error_info = {"tool": getattr(part, "tool_name", "unknown"), "error": str(part.error)}
                                logger.error("TOOL ERROR", error_info=error_info)
                                tool_errors.append(error_info)

            if tool_calls:
                logger.info("MCP tools called", count=len(tool_calls), tools=[t["tool"] for t in tool_calls])
            else:
                logger.warning("No MCP tools were called by the LLM")

            if tool_errors:
                logger.error("Tool errors occurred", error_count=len(tool_errors))

            # Extract just the text output from the result
            if hasattr(result, "data"):
                final_text = str(result.data)
            elif hasattr(result, "output"):
                final_text = str(result.output)
            else:
                final_text = str(result)

            logger.info(f"Got complete response, {len(final_text)} chars")

            # Debug: Log final response to check for UUID corruption
            if "object_id" in final_text.lower() or "uuid" in final_text.lower():
                logger.warning(
                    "FINAL RESPONSE contains object_id/UUID",
                    final_response=final_text[:2000],  # Log first 2000 chars
                )

            # Send the complete response
            if final_text:
                yield final_text
            else:
                logger.warning("No text in final result")

            # Log completion metrics
            logger.info(
                "Chatbot response completed",
                total_tokens=result.usage().total_tokens if hasattr(result, "usage") else None,
            )

        except Exception as e:
            logger.error("Chatbot streaming failed", error=str(e))
            yield f"\n\n[Error: {str(e)}]"


# Global chatbot agent instance
_chatbot_agent: ChatbotAgent | None = None


def get_chatbot_agent() -> ChatbotAgent:
    """Get or create the global chatbot agent instance."""
    global _chatbot_agent
    if _chatbot_agent is None:
        _chatbot_agent = ChatbotAgent()
    return _chatbot_agent


async def chatbot_stream(request: ChatbotRequest) -> StreamingResponse:
    """
    FastAPI endpoint handler for streaming chatbot responses.

    Args:
        request: ChatbotRequest with message and settings

    Returns:
        StreamingResponse with text/event-stream content

    Raises:
        HTTPException: If the MCP server cannot be started
    """
    agent = get_chatbot_agent()

    # Ensure MCP HTTP server is running and healthy
    try:
        await agent.ensure_mcp_ready()
    except RuntimeError as e:
        logger.error("MCP server not available", error=str(e))
        raise HTTPException(status_code=503, detail=f"MCP server unavailable: {e}") from e

    # Stream the response (connects to MCP server via HTTP)
    return StreamingResponse(
        agent.stream_chat_response(request),
        media_type="text/plain",
    )
