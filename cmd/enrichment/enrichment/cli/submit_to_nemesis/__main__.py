# Standard Libraries
import asyncio
import signal

# 3rd Party Libraries
from enrichment.cli.submit_to_nemesis.submit_to_nemesis import amain


def handle_exception(loop: asyncio.AbstractEventLoop, context):
    e = context.get("exception")
    msg = context.get("message")

    if e:
        if type(e) == SystemExit:
            # Something called sys.exit()
            pass
        else:
            print(f"Caught unhandled global exception: {type(e)}. Message: {msg}")
    else:
        print(f"Caught unhandled global exception: {msg}")

    asyncio.create_task(shutdown(loop))


async def shutdown(loop: asyncio.AbstractEventLoop, signal=None):
    """Cleanup tasks tied to the service's shutdown."""
    if signal:
        # print(f"Received exit signal {signal.name}...")
        pass

    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    [task.cancel() for task in tasks]

    await asyncio.gather(*tasks, return_exceptions=True)
    loop.stop()


def main():
    loop = asyncio.get_event_loop()
    signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
    for s in signals:
        loop.add_signal_handler(s, lambda s=s: asyncio.create_task(shutdown(loop, signal=s)))
    loop.set_exception_handler(handle_exception)

    try:
        task = loop.create_task(amain())
        loop.run_until_complete(task)
    finally:
        loop.close()


if __name__ == "__main__":
    main()
