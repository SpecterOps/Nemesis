# monitor.py
import logging
import os
import sys
import time
from pathlib import Path

import click
from cli.log import setup_logging
from cli.submit import submit_files
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class NewFileHandler(FileSystemEventHandler):
    """Handler for new file events in the monitored directory"""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        project: str,
        agent_id: str,
        logger: logging.Logger,
        container: bool = False,
        source: str | None = None,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.project = project
        self.agent_id = agent_id
        self.logger = logger
        self.container = container
        self.source = source

    def on_created(self, event):
        """Called when a file or directory is created"""
        if not event.is_directory:
            file_path = Path(os.fsdecode(event.src_path))
            self.logger.info(f"New file detected: {file_path}")

            # Wait a moment to ensure file is fully written
            time.sleep(0.5)

            # Submit the new file
            try:
                submit_files(
                    paths=[file_path],
                    host=self.host,
                    recursive=False,  # Single file
                    workers=1,
                    username=self.username,
                    password=self.password,
                    project=self.project,
                    agent_id=self.agent_id,
                    container=self.container,
                    source=self.source,
                )
            except Exception as e:
                self.logger.error(f"Failed to submit new file {file_path}: {e}")

    def on_moved(self, event):
        """Called when a file or directory is moved into the monitored directory"""
        if not event.is_directory:
            file_path = Path(os.fsdecode(event.dest_path))
            self.logger.info(f"File moved into directory: {file_path}")

            # Submit the moved file
            try:
                submit_files(
                    paths=[file_path],
                    host=self.host,
                    recursive=False,  # Single file
                    workers=1,
                    username=self.username,
                    password=self.password,
                    project=self.project,
                    agent_id=self.agent_id,
                    container=self.container,
                    source=self.source,
                )
            except Exception as e:
                self.logger.error(f"Failed to submit moved file {file_path}: {e}")


def monitor_main(
    path: str,
    debug: bool,
    host: str,
    username: str,
    password: str,
    project: str,
    agent_id: str,
    only_monitor: bool,
    workers: int,
    container: bool,
    source: str | None = None,
):
    """Monitor a folder for new files and submit them to Nemesis"""
    try:
        logger = setup_logging(debug)

        # Validate that path is a directory
        folder_path = Path(path)
        if not folder_path.exists():
            logger.error(f"Path does not exist: {folder_path}")
            sys.exit(1)

        if not folder_path.is_dir():
            logger.error(f"Path is not a directory: {folder_path}")
            sys.exit(1)

        logger.info(f"Monitoring folder: {folder_path}")

        # Submit existing files if not in only-monitor mode
        if not only_monitor:
            logger.info("Submitting existing files...")
            success = submit_files(
                paths=[folder_path],
                host=host,
                recursive=True,  # Process subdirectories recursively
                workers=workers,
                username=username,
                password=password,
                project=project,
                agent_id=agent_id,
                container=container,
                source=source,
            )

            if not success:
                logger.error("Failed to submit existing files.")
                # sys.exit(1)

        else:
            logger.info("Skipping existing files (--only-monitor enabled)")

        # Set up file system watcher
        event_handler = NewFileHandler(host, username, password, project, agent_id, logger, container, source)
        observer = Observer()
        observer.schedule(event_handler, str(folder_path), recursive=True)

        # Start monitoring
        observer.start()
        logger.info("File monitoring started. Press Ctrl+C to stop...")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping monitor...")
            observer.stop()

        observer.join()
        logger.info("Monitor stopped")

    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)
