import asyncio
import inspect
import os
from collections.abc import Callable
from functools import wraps
from typing import Any

import dapr.ext.workflow as wf
from common.logger import WORKFLOW_RUNTIME_LOG_LEVEL, get_logger
from dapr.ext.workflow.logger.options import LoggerOptions


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name, "").strip()
    if not value:
        return default
    try:
        parsed = int(value)
    except ValueError as e:
        raise ValueError(f"{name} must be a positive integer, got {value!r}") from e
    if parsed < 1:
        raise ValueError(f"{name} must be a positive integer, got {value!r}")
    return parsed


# Worker limits. These live in the SDK, not the Dapr Configuration: Dapr turns WorkflowsFastPath off
# when workflow concurrency limits are set there. Activities are async, so they hold no thread while
# they run; the thread pool only sends results to the sidecar and runs orchestrator replays.
WORKFLOW_MAX_CONCURRENT_ACTIVITIES = _env_int("WORKFLOW_MAX_CONCURRENT_ACTIVITIES", 100)
WORKFLOW_MAX_CONCURRENT_ORCHESTRATIONS = _env_int("WORKFLOW_MAX_CONCURRENT_ORCHESTRATIONS", 100)
WORKFLOW_THREAD_POOL_WORKERS = _env_int("WORKFLOW_THREAD_POOL_WORKERS", 16)

wf_runtime: wf.WorkflowRuntime = wf.WorkflowRuntime(
    logger_options=LoggerOptions(
        log_level=WORKFLOW_RUNTIME_LOG_LEVEL,
    ),
    maximum_concurrent_activity_work_items=WORKFLOW_MAX_CONCURRENT_ACTIVITIES,
    maximum_concurrent_orchestration_work_items=WORKFLOW_MAX_CONCURRENT_ORCHESTRATIONS,
    maximum_thread_pool_workers=WORKFLOW_THREAD_POOL_WORKERS,
)

logger = get_logger(__name__)
workflow_loop: asyncio.AbstractEventLoop | None = None


def set_workflow_runtime_loop(loop: asyncio.AbstractEventLoop) -> None:
    global workflow_loop
    workflow_loop = loop


def workflow_activity(fn: Callable | None = None, *, name: str | None = None) -> Callable:
    """
    Register a function as a workflow activity.

    Async activities are registered as native async activities: the Dapr worker awaits them on its own
    event loop, so a running activity does not hold a worker thread. The coroutine itself runs on the
    FastAPI event loop (set with set_workflow_runtime_loop), because the activities share resources
    bound to that loop (asyncpg pool, Dapr aio client, ...). Sync functions are registered unchanged
    and run in the worker's thread pool.

    Can be used with or without parentheses:
        @workflow_activity
        async def my_activity(): ...

        @workflow_activity(name="custom_name")
        async def my_activity(): ...
    """

    def decorator(func: Callable) -> Callable:
        activity_name = name or func.__name__

        if not inspect.iscoroutinefunction(func):
            return wf_runtime.activity(name=name)(func)  # pyright: ignore[reportCallIssue]

        @wraps(func)
        async def run_on_app_loop(*args, **kwargs) -> Any:
            logger.debug(f"Executing activity: {activity_name}")
            if workflow_loop is None:
                raise RuntimeError("FastAPI event loop is not set.")
            if workflow_loop is asyncio.get_running_loop():
                return await func(*args, **kwargs)
            # Cancelling this await (worker shutdown) also cancels the coroutine on the app loop
            return await asyncio.wrap_future(asyncio.run_coroutine_threadsafe(func(*args, **kwargs), workflow_loop))

        return wf_runtime.activity(name=name)(run_on_app_loop)  # pyright: ignore[reportCallIssue]

    # If called without parentheses, fn will be the function
    if fn is not None:
        return decorator(fn)

    # If called with parentheses (with or without arguments), return the decorator
    return decorator
