# Standard Libraries
import os
from pathlib import Path
from typing import Dict, List, Optional

# 3rd Party Libraries
import structlog
from enrichment.tasks.webapi.crack_list.wordlist import Wordlist

logger = structlog.get_logger(module=__name__)


class ClientWordlists:
    def __init__(self, base_path: Optional[str] = None):
        self.clients: Dict[str, Wordlist] = {}
        self.base_path = base_path

        if base_path is None:
            logger.info("No base path provided. Client wordlists will not be saved.")
            return

        if not os.path.isdir(base_path):
            raise ValueError(f"Base path {base_path} is not a directory")
        else:
            logger.info(f"Storing client wordlists in: {base_path}")

        for client_wordlist in os.listdir(base_path):
            client_id = client_wordlist.split(".")[0]
            with open(os.path.join(base_path, client_wordlist), "r") as f:
                data = Wordlist.from_json(f.read())
                if data:
                    self.clients[client_id] = data

    def _save_client(self, client_id: str) -> None:
        if self.base_path is None:
            return

        path_name = os.path.join(self.base_path, f"{client_id}.json")
        client_json = self.clients[client_id].to_json()
        Path(path_name).write_text(client_json)

    def add_file(self, client_id: str, text: str, length_filter: bool) -> None:
        if client_id not in self.clients:
            self.clients[client_id] = Wordlist()
        self.clients[client_id].add(text, length_filter)
        self._save_client(client_id)

    def get(self, client_id: str, count: Optional[int] = None) -> List[str]:
        if client_id in self.clients:
            return self.clients[client_id].get(count=count)
        else:
            return []

    def get_as_file(self, client_id: str, count: Optional[int] = None) -> str:
        if client_id in self.clients:
            words = self.clients[client_id].get(count=count)
            return "\n".join(words)
        else:
            return ""
