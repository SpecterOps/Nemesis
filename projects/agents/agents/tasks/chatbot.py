"""Chatbot agent for interactive querying of Nemesis data."""

import asyncio
import os
import subprocess
from pathlib import Path
from typing import AsyncGenerator

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

        # System prompt - will be saved to DB on first use
        self.system_prompt = """You are a data query assistant for Nemesis, an offensive security data platform.

Your role is to retrieve and report data from the database. Do NOT provide recommendations, analysis, or suggestions - only report the requested data.

You have access to a PostgreSQL database with the following tables:
- files_enriched: Processed files with metadata (path, filename, extension, size, magic_type, hashes, etc.)
- plaintext_content: Searchable text content extracted from files (full-text search available)
- enrichments: Detailed analysis results from various enrichment modules (module_name, result_data)
- findings: Security findings categorized by severity and type (finding_name, category, severity, data)
- file_linkings: Relationships between files showing connections (source, file_path_1, file_path_2, link_type)
- chromium.cookies: Browser cookies from Chromium-based browsers (host_key, name, value, expiration)
- chromium.logins: Saved credentials from Chromium browsers (origin_url, username_value, password_value)

Content Search Capabilities:
- Use search-document-content to search through plaintext extracted from files
- Supports full-text search across document content, logs, configuration files, etc.
- Can filter by path, project, agent, source, or date range
- Returns the first matching chunk from each file

When answering questions:
1. Query the database using the appropriate tools
2. Report ONLY the data retrieved - no analysis or recommendations
3. Present results clearly and concisely
4. For large result sets, summarize counts and key details
5. Use case-insensitive pattern matching for host/source filters
6. Be brief - users want facts, not explanations

Query Guidelines:
- Maximum 1000 rows per query
- Use COUNT(*) for totals before retrieving detailed data
- Use GROUP BY to aggregate when appropriate
- Filter by severity, category, or source to narrow results
- Use search-document-content when users ask to search "for" or "containing" specific text

Remember: Report data only. Do not suggest next steps, provide security advice, or make recommendations."""

        self.mcp_process = None

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
            "error": "ChatbotAgent does not support workflow execution. Use /agents/chatbot/stream endpoint instead."
        }

    def _get_chatbot_connection_string(self) -> str:
        """Get PostgreSQL connection string for chatbot read-only user."""
        chatbot_password = os.getenv("CHATBOT_DB_PASSWORD", "chatbot_pass_change_me")
        postgres_host = os.getenv("POSTGRES_HOST", "postgres")
        postgres_port = os.getenv("POSTGRES_PORT", "5432")
        postgres_db = os.getenv("POSTGRES_DB", "enrichment")
        postgres_params = os.getenv("POSTGRES_PARAMETERS", "sslmode=disable")

        return f"postgresql://chatbot_readonly:{chatbot_password}@{postgres_host}:{postgres_port}/{postgres_db}?{postgres_params}"

    async def start_mcp_server(self):
        """Start the genai-toolbox MCP server as a subprocess listening on HTTP."""
        # Check if process is already running
        if self.mcp_process and self.mcp_process.poll() is None:
            logger.debug("MCP server already running")
            return

        try:
            tools_file = Path(__file__).parent.parent / "mcp" / "tools.yaml"
            if not tools_file.exists():
                raise FileNotFoundError(f"tools.yaml not found at {tools_file}")

            # Get database connection string for chatbot readonly user
            db_url = self._get_chatbot_connection_string()

            # Start genai-toolbox HTTP server (default port 5000)
            logger.info("Starting genai-toolbox MCP HTTP server", tools_file=str(tools_file))

            self.mcp_process = subprocess.Popen(
                ["genai-toolbox", "--tools-file", str(tools_file)],
                env={**os.environ, "DATABASE_URL": db_url},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Give it a moment to start
            await asyncio.sleep(2)

            if self.mcp_process.poll() is not None:
                stderr = self.mcp_process.stderr.read().decode() if self.mcp_process.stderr else ""
                # If it failed due to address in use, that's actually okay
                if "address already in use" in stderr.lower():
                    logger.info("MCP server already running (address in use)")
                    self.mcp_process = None
                    return
                raise RuntimeError(f"MCP server failed to start: {stderr}")

            logger.info("MCP HTTP server started successfully on http://127.0.0.1:5000/mcp")

        except Exception as e:
            logger.error("Failed to start MCP server", error=str(e))
            raise

    async def stop_mcp_server(self):
        """Stop the MCP server subprocess."""
        if self.mcp_process and self.mcp_process.poll() is None:
            logger.info("Stopping MCP server")
            self.mcp_process.terminate()
            try:
                self.mcp_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning("MCP server didn't stop gracefully, killing")
                self.mcp_process.kill()
            self.mcp_process = None

    async def stream_chat_response(self, request: ChatbotRequest) -> AsyncGenerator[str, None]:
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
            mcp_server = MCPServerStreamableHTTP(url='http://127.0.0.1:5000/mcp')

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

            # Log tool calls and their results
            tool_calls = []
            tool_errors = []
            if hasattr(result, 'all_messages'):
                for msg in result.all_messages():
                    if hasattr(msg, 'parts'):
                        for part in msg.parts:
                            if hasattr(part, 'tool_name'):
                                tool_info = {
                                    'tool': part.tool_name,
                                    'args': getattr(part, 'args', {})
                                }
                                # Check if there's an error in the tool result
                                if hasattr(part, 'content'):
                                    tool_info['content'] = str(part.content)[:200]  # First 200 chars
                                if hasattr(part, 'error'):
                                    tool_info['error'] = str(part.error)
                                    tool_errors.append(tool_info)
                                tool_calls.append(tool_info)

            if tool_calls:
                logger.info("MCP tools called", tool_calls=tool_calls, count=len(tool_calls))
            else:
                logger.warning("No MCP tools were called by the LLM")

            if tool_errors:
                logger.error("Tool errors occurred", errors=tool_errors)

            # Extract just the text output from the result
            if hasattr(result, 'data'):
                final_text = str(result.data)
            elif hasattr(result, 'output'):
                final_text = str(result.output)
            else:
                final_text = str(result)

            logger.info(f"Got complete response, {len(final_text)} chars")

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
    """
    agent = get_chatbot_agent()

    # Ensure MCP HTTP server is running
    await agent.start_mcp_server()

    # Stream the response (connects to MCP server via HTTP)
    return StreamingResponse(
        agent.stream_chat_response(request),
        media_type="text/plain",
    )
