# Standard Libraries
import asyncio

# 3rd Party Libraries
import structlog
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

logger = structlog.getLogger()


class NewFileHandler(FileSystemEventHandler):
    def __init__(self, queue, loop: asyncio.AbstractEventLoop):
        self.queue = queue
        self.loop = loop

    def on_created(self, event):
        if event.is_directory:
            return

        self.loop.call_soon_threadsafe(self.loop.create_task, self.queue.put(event.src_path))


async def monitor_directory(directory, loop):
    queue = asyncio.Queue()
    event_handler = NewFileHandler(queue, loop)
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=True)
    observer.start()

    try:
        while True:
            file_path = await queue.get()
            yield file_path
    finally:
        observer.stop()
        observer.join()
