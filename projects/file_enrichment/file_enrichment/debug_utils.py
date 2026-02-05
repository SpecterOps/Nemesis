"""Debug utilities for identifying asyncio blocking issues."""
# pyright: reportAttributeAccessIssue=false, reportOptionalMemberAccess=false

import asyncio
import faulthandler
import os
import signal
import sys
import threading
import traceback
from datetime import datetime

from common.logger import get_logger

logger = get_logger(__name__)


def dump_all_stacks(sig=None, frame=None):
    """Dump stack traces of all threads when SIGUSR1 is received."""
    logger.warning("=" * 80)
    logger.warning(f"STACK TRACE DUMP - {datetime.now().isoformat()}")
    logger.warning(f"PID: {os.getpid()}")
    logger.warning("=" * 80)

    # Dump all thread stacks
    for thread_id, frame in sys._current_frames().items():
        thread_name = None
        for thread in threading.enumerate():
            if thread.ident == thread_id:
                thread_name = thread.name
                break

        logger.warning(f"\nThread {thread_id} ({thread_name}):")
        for line in traceback.format_stack(frame):
            logger.warning(line.strip())

    # Dump asyncio tasks if available
    try:
        loop = asyncio.get_running_loop()
        all_tasks = asyncio.all_tasks(loop)

        logger.warning("\n" + "=" * 80)
        logger.warning(f"ASYNCIO TASKS ({len(all_tasks)} total)")
        logger.warning("=" * 80)

        for i, task in enumerate(all_tasks):
            logger.warning(f"\nTask {i}: {task.get_name()}")
            logger.warning(f"  Done: {task.done()}")
            logger.warning(f"  Cancelled: {task.cancelled()}")

            try:
                coro = task.get_coro()
                if coro.cr_frame:
                    logger.warning(f"  Coroutine: {coro.__name__}")
                    logger.warning(f"  File: {coro.cr_frame.f_code.co_filename}:{coro.cr_frame.f_lineno}")
                    logger.warning(f"  Function: {coro.cr_frame.f_code.co_name}")

                    # Print the stack of the coroutine
                    stack = traceback.format_stack(coro.cr_frame)
                    logger.warning("  Stack:")
                    for line in stack:
                        logger.warning(f"    {line.strip()}")
            except Exception as e:
                logger.warning(f"  Error getting coroutine info: {e}")

    except RuntimeError:
        logger.warning("No asyncio event loop running")

    logger.warning("\n" + "=" * 80)
    logger.warning("END STACK TRACE DUMP")
    logger.warning("=" * 80)


def dump_blocking_threads():
    """Identify threads that might be blocking."""
    logger.warning("\nBLOCKING THREAD ANALYSIS:")

    for thread in threading.enumerate():
        logger.warning(f"\nThread: {thread.name} (daemon={thread.daemon})")
        logger.warning(f"  Alive: {thread.is_alive()}")

        # Check if thread is in a blocking state
        if thread.ident:
            frame = sys._current_frames().get(thread.ident)
            if frame:
                # Look for common blocking patterns
                code = frame.f_code
                if "wait" in code.co_name or "lock" in code.co_name or "result" in code.co_name:
                    logger.warning(f"  ⚠️  POTENTIALLY BLOCKING: {code.co_filename}:{frame.f_lineno} in {code.co_name}")


def setup_debug_signals():
    """Setup signal handlers for debugging."""

    # Enable faulthandler to dump on SIGSEGV
    faulthandler.enable()

    # Dump all stacks on SIGUSR1
    signal.signal(signal.SIGUSR1, dump_all_stacks)

    # Dump blocking threads on SIGUSR2
    signal.signal(signal.SIGUSR2, lambda sig, frame: dump_blocking_threads())

    logger.info(
        "Debug signal handlers installed",
        usage="Kill -USR1 <pid> to dump all stacks, kill -USR2 <pid> to analyze blocking threads",
    )
