# Standard Libraries
import asyncio
from base64 import b64decode
from typing import Dict

import nemesispb.nemesis_pb2 as pb
import structlog
from Cryptodome.Cipher import AES
from enrichment.lib.nemesis_db import NemesisDb
from enrichment.tasks.dpapi.dpapi_blob import DPAPI_BLOB
from nemesiscommon.messaging import (MessageQueueConsumerInterface,
                                     MessageQueueProducerInterface)
from nemesiscommon.tasking import TaskInterface
from prometheus_async import aio
from prometheus_client import Summary

# 3rd Party Libraries


logger = structlog.get_logger(module=__name__)


class ChromiumCookie(TaskInterface):
    """
    Class responsible for decrypting cookies in Chromium-based browsers/applications.
    """

    db: NemesisDb

    # Queues
    in_q_chromiumcookies: MessageQueueConsumerInterface
    in_q_cookieingestion: MessageQueueConsumerInterface
    out_q_chromium_cookies: MessageQueueProducerInterface
    out_q_chromium_cookiesprocessed: MessageQueueProducerInterface

    def __init__(
        self,
        db: NemesisDb,
        in_q_chromiumcookies: MessageQueueConsumerInterface,
        in_q_cookieingestion: MessageQueueConsumerInterface,
        out_q_chromium_cookies: MessageQueueProducerInterface,
        out_q_chromium_cookiesprocessed: MessageQueueProducerInterface,
    ):
        self.db = db
        self.in_q_chromiumcookies = in_q_chromiumcookies
        self.in_q_cookieingestion = in_q_cookieingestion
        self.out_q_chromium_cookies = out_q_chromium_cookies
        self.out_q_chromium_cookiesprocessed = out_q_chromium_cookiesprocessed

    async def run(self) -> None:
        await logger.ainfo("Starting the Cookie service")

        await asyncio.gather(
            self.in_q_cookieingestion.Read(self.handle_cookie_ingestion),  # type: ignore
            self.in_q_chromiumcookies.Read(self.handle_chromium_cookies),  # type: ignore
        )
        await asyncio.Future()

    async def handle_chromium_cookies(self, q_msg: pb.ChromiumCookieMessage) -> None:
        await self.process_chromium_cookies(q_msg)

    async def handle_cookie_ingestion(self, q_msg: pb.CookieIngestionMessage) -> None:
        await self.process_cookie_ingestion(q_msg)

    @aio.time(Summary("process_chromium_cookies", "Time spent processing a Chromium cookie parsed from a Cookies file"))  # type: ignore
    async def process_chromium_cookies(self, event: pb.ChromiumCookieMessage) -> None:
        """Main function to process chromium_cookies events.

        Cookie values are checked for AES/DPAPI decryption, and the appropriate
        state key or DPAPI masterkey is pulled if it's present and decrypted.
        If present, this key is then used to decrypt the cookie value to plaintext.
        """

        if not len(event.data) > 0:
            return

        masterkeys = await self.get_linked_masterkeys(event)
        data_directories = await self.get_linked_statekeys(event)

        for entry in event.data:
            if not entry.is_decrypted:
                # first do any cookie decryption
                if entry.masterkey_guid in masterkeys:
                    blob = DPAPI_BLOB(entry.value_enc)
                    blob_dec_bytes = blob.decrypt(masterkeys[entry.masterkey_guid])
                    if blob_dec_bytes:
                        entry.value_dec = blob_dec_bytes.decode("UTF-8")
                        entry.is_decrypted = True
                elif entry.encryption_type == "aes" and entry.user_data_directory in data_directories:
                    state_key_bytes_dec = data_directories[entry.user_data_directory]
                    if state_key_bytes_dec:
                        try:
                            plaintext = await self.decrypt_chromium_aes_entry(state_key_bytes_dec, entry.value_enc)
                            if plaintext and plaintext != "":
                                entry.value_dec = plaintext
                                entry.is_decrypted = True
                        except Exception as e:
                            await logger.aerror(
                                "Error AES decrypting cookie value",
                                source=event.metadata.source,
                                cookie_name=entry.name,
                                user_data_directory=entry.user_data_directory,
                            )

            # now do the cookie site/name classification enrichment
            # TODO: implement

        # publish out to the cookie_processed_q queue
        await self.out_q_chromium_cookiesprocessed.Send(event.SerializeToString())

    @aio.time(Summary("process_cookie_ingestion", "Time spent processing a cookie ingested through the frontend API"))  # type: ignore
    async def process_cookie_ingestion(self, event: pb.CookieIngestionMessage) -> None:
        """Main function to process cookie_ingestion events."""

        if not len(event.data) > 0:
            return

        cookie_message = pb.ChromiumCookieMessage()
        cookie_message.metadata.CopyFrom(event.metadata)

        for data in event.data:
            cookie_data = cookie_message.data.add()

            # this indicates null, i.e. that this wasn't carved from a file
            cookie_data.originating_object_id = "00000000-0000-0000-0000-000000000000"
            cookie_data.masterkey_guid = "00000000-0000-0000-0000-000000000000"

            if data.user_data_directory and data.user_data_directory != "":
                path = data.user_data_directory.replace("\\", "/")
                chromium_file_path = helpers.parse_chromium_file_path(path)
                cookie_data.user_data_directory = path
                if chromium_file_path.success and chromium_file_path.username:
                    cookie_data.username = chromium_file_path.username
                if chromium_file_path.success and chromium_file_path.browser:
                    cookie_data.browser = chromium_file_path.browser

            if data.domain and data.domain != "":
                cookie_data.host_key = data.domain.lstrip(".").lower()

            cookie_data.name = data.name

            # TODO: implement the site/cookie name classification mapping

            cookie_data.path = data.path

            if data.creation:
                cookie_data.creation.CopyFrom(data.creation)
            if data.expires:
                cookie_data.expires.CopyFrom(data.expires)
            if data.last_access:
                cookie_data.last_access.CopyFrom(data.last_access)
            if data.last_update:
                cookie_data.last_update.CopyFrom(data.last_update)

            cookie_data.is_secure = data.secure
            cookie_data.is_httponly = data.http_only
            cookie_data.is_session = data.session

            if data.samesite and data.samesite != "":
                cookie_data.samesite = data.samesite.upper()

            cookie_data.source_port = data.source_port
            cookie_data.value_dec = data.value

            if len(data.value) > 0:
                cookie_data.is_decrypted = True

            if len(data.value_enc) > 0:
                cookie_data.value_enc = b64decode(data.value_enc)
                if cookie_data.value_enc.startswith(b"v10"):
                    cookie_data.encryption_type = "aes"
                else:
                    blob = await helpers.parse_dpapi_blob(cookie_data.value_enc)
                    if blob.success:
                        cookie_data.encryption_type = "dpapi"
                        if blob.dpapi_master_key_guid:
                            cookie_data.masterkey_guid = blob.dpapi_master_key_guid
                    else:
                        raise Exception(f"Unknown cookie encryption type. Encrypted cookie value: {data.value_enc}")

        # publish out to the cookie_processed_q queue
        await self.out_q_chromium_cookies.Send(cookie_message.SerializeToString())

    async def get_linked_masterkeys(self, event: pb.ChromiumCookieMessage) -> Dict[str, str]:
        """Helper that returns all masterkey GUID:key mappings from a set of cookie messages."""
        masterkey_guids_uniq = set([entry.masterkey_guid for entry in event.data if (entry.encryption_type == "dpapi" and entry.masterkey_guid != "00000000-0000-0000-0000-000000000000")])
        masterkeys = {}
        for mk_guid in masterkey_guids_uniq:
            results = await self.db.get_decrypted_dpapi_masterkey(mk_guid)
            if results:
                (masterkey_sha1, masterkey_full) = results
                if masterkey_sha1:
                    masterkeys[mk_guid] = masterkey_sha1
                elif masterkey_full:
                    masterkeys[mk_guid] = masterkey_full
        return masterkeys

    async def get_linked_statekeys(self, event: pb.ChromiumCookieMessage) -> Dict[str, bytes]:
        """Helper that returns all statekey AES keys from a set of cookie messages."""
        # get the decrypted AES state key value(s) linked to these cookies, if it/they exist
        #   we use source + user_data_directory for relative "uniqueness"
        data_directories_uniq = set([entry.user_data_directory for entry in event.data])
        data_directories = {}
        for data_directory in data_directories_uniq:
            result = await self.db.get_decrypted_chromium_state_key(event.metadata.source, data_directory)
            if result:
                data_directories[data_directory] = result
        return data_directories

    async def decrypt_chromium_aes_entry(self, state_key_bytes_dec: bytes, value_enc: bytes) -> str:
        """Helper that takes a Chromium AES key and a cookie/login value and decrypts it.

        Ref- https://stackoverflow.com/a/60423699
        """

        nonce = value_enc[3 : 3 + 12]
        ciphertext = value_enc[3 + 12 : -16]
        tag = value_enc[-16:]
        cipher = AES.new(state_key_bytes_dec, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        if plaintext and plaintext is not None:
            return plaintext.decode("UTF-8")
        else:
            return ""
