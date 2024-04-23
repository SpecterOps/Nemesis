# Standard Libraries
from abc import abstractmethod
from typing import Optional

# 3rd Party Libraries
import httpx
import structlog

logger = structlog.get_logger(__name__)


class TextExtractorInterface:
    @abstractmethod
    async def extract(self, text: str) -> Optional[str]:
        pass

    @abstractmethod
    async def detect(self, text: str) -> Optional[str]:
        pass


class TikaTextExtractor(TextExtractorInterface):
    http_client: httpx.AsyncClient
    tika_uri: str

    def __init__(self, tika_uri: str, http_client: httpx.AsyncClient) -> None:
        self.tika_uri = tika_uri
        self.http_client = http_client

    async def extract(self, file_path: str) -> Optional[str]:
        """Extracts text from the supplied file using Apache Tika a returns the text in the document.

        Args:
            file_path (str): Path to a document on disk

        Returns:
            str: Text extracted from the document
        """
        url = f"{self.tika_uri}tika"

        with open(file_path, "rb") as doc_file:
            try:
                data = doc_file.read()
                resp = await self.http_client.put(url, content=data, headers={"Accept": "text/plain"}, timeout=120)
                # resp = await self.http_client.put(url, content=data, headers={"Accept": "text/plain"})
                resp.raise_for_status()

                # check if it's empty, otherwise return it
                text = resp.text.strip()
                return text if text else None
            except httpx.HTTPStatusError as e:
                # See https://cwiki.apache.org/confluence/display/TIKA/TikaServer
                if e.response.status_code == 422 and e.response.text == "Unprocessable Entity":
                    await logger.awarning(
                        "Tika could not process the file (Unsupported mime-type, encrypted document, etc)",
                        file_path=file_path,
                    )
                    return None

                # This is an response code we didn't expect, so re-raise it
                raise

    async def detect(self, file_path: str) -> Optional[str]:
        """Uses Tika to detect the type of the file and whether it is supported.

        Args:
            file_path (str): Path to a document on disk

        Returns:
            str: The mime type detected by Tika.
        """
        url = f"{self.tika_uri}detect/stream"

        with open(file_path, "rb") as doc_file:
            try:
                data = doc_file.read()
                resp = await self.http_client.put(url, content=data, headers={"Accept": "text/plain"}, timeout=30)
                # resp = await self.http_client.put(url, content=data, headers={"Accept": "text/plain"})
                resp.raise_for_status()
                if resp.status_code == 200:
                    return resp.text.strip()
                else:
                    await logger.awarning(f"Tika response code: {resp.status_code}", file_path=file_path)
                    return None
            except httpx.HTTPStatusError as e:
                # See https://cwiki.apache.org/confluence/display/TIKA/TikaServer
                if e.response.status_code == 422 and e.response.text == "Unprocessable Entity":
                    await logger.awarning(
                        "Tika could not process the file (Unsupported mime-type, encrypted document, etc)",
                        file_path=file_path,
                    )
                    return None

                # This is an response code we didn't expect, so re-raise it
                raise
