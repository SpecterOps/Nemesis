# # Standard library imports
# from typing import Any, Optional
# from urllib.parse import urlunparse

# # Third-party imports
# import requests
# from requests.auth import HTTPBasicAuth

# from cli.mythic_connector.config import Settings
# from cli.mythic_connector.logger import get_logger

# logger = get_logger(__name__)


# class NemesisClient:
#     """Client for interacting with the Nemesis API.

#     This class encapsulates all communication with the Nemesis service,
#     providing a clean interface for uploading files and posting data.
#     """

#     def __init__(self, cfg: Settings) -> None:
#         """Initialize the Nemesis client.

#         Args:
#             config: Application configuration
#         """
#         self.cfg = cfg
#         self.auth = HTTPBasicAuth(
#             cfg.nemesis.credential.username,
#             cfg.nemesis.credential.password,
#         )

#     def post_data(self, data: dict[str, Any]) -> Optional[dict[str, Any]]:
#         """Post data to the Nemesis API.

#         Args:
#             data: JSON-serializable data to post

#         Returns:
#             Response JSON if successful, None otherwise
#         """
#         try:
#             response = requests.post(f"{self.cfg.nemesis.url}/data", auth=self.auth, json=data, verify=False)

#             if response.status_code != 200:
#                 logger.error(f"Error posting to Nemesis ({response.status_code}): {response.text}")
#                 return None

#             return response.json()

#         except Exception as e:
#             logger.error(f"Error posting data to Nemesis: {e}")
#             return None

#     def post_file(self, file_bytes: bytes) -> Optional[str]:
#         """Upload file bytes to Nemesis.

#         Args:
#             file_bytes: Raw bytes of the file

#         Returns:
#             Object ID if successful, None otherwise
#         """
#         try:
#             url = urlunparse(self.cfg.nemesis.url)
#             response = requests.post(
#                 f"{url}/file",
#                 auth=self.auth,
#                 data=file_bytes,
#                 headers={"Content-Type": "application/octet-stream"},
#                 verify=False,
#             )

#             if response.status_code != 200:
#                 logger.error(f"Error uploading file to Nemesis: {response.status_code}")
#                 return None

#             result = response.json()
#             return result.get("object_id")

#         except Exception as e:
#             logger.error(f"Error uploading file to Nemesis: {e}")
#             return None
