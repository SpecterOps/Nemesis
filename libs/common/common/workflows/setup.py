import asyncio
from collections.abc import Callable
from functools import wraps
from typing import Any

import dapr.ext.workflow as wf
from common.logger import WORKFLOW_RUNTIME_LOG_LEVEL
from dapr.ext.workflow.logger.options import LoggerOptions

wf_runtime: wf.WorkflowRuntime = wf.WorkflowRuntime(
    logger_options=LoggerOptions(
        log_level=WORKFLOW_RUNTIME_LOG_LEVEL,
    )
)


def set_fastapi_loop(loop: asyncio.AbstractEventLoop) -> None:
    global fastapi_loop
    fastapi_loop = loop


def workflow_activity(fn: Callable | None = None, *, name: str | None = None) -> Callable:
    """
    Decorator to mark an async function as a workflow activity.
    The default @wf_runtime.activity decorator does not support async functions.

    Can be used with or without parentheses:
        @workflow_activity
        async def my_activity(): ...

        @workflow_activity()
        async def my_activity(): ...

        @workflow_activity(name="custom_name")
        async def my_activity(): ...
    """

    def decorator(func: Callable) -> Callable:
        # To facilitate unit-testing, avoid using the @wf_runtime.activity decorator
        # and simply return the function as is.
        # if settings.pytest_running:
        #     return func

        @wf_runtime.activity(name=name)
        @wraps(func)
        def wrapped_fn(*args, **kwargs) -> Any:  # type: ignore
            result = func(*args, **kwargs)
            if not asyncio.iscoroutine(result):
                # If the result is not a coroutine, just return it as is.
                return result

            if fastapi_loop is None:
                raise RuntimeError("FastAPI event loop is not set.")
            return asyncio.run_coroutine_threadsafe(result, fastapi_loop).result()

        return wrapped_fn

    # If called without parentheses, fn will be the function
    if fn is not None:
        return decorator(fn)

    # If called with parentheses (with or without arguments), return the decorator
    return decorator
