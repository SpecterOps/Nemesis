import asyncio
import logging

from .db import init_db


async def amain():
    await init_db("nemesis", True)


loop = asyncio.get_event_loop()
try:
    task = amain()
    loop.run_until_complete(task)
except asyncio.exceptions.CancelledError:
    logging.debug("Primary App asyncio task cancelled. Application is shutting down.")
