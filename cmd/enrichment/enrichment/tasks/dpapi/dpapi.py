# Standard Libraries
import asyncio
import uuid
from hashlib import pbkdf2_hmac
from typing import List, Optional, Tuple

# 3rd Party Libraries
import nemesispb.nemesis_pb2 as pb
import structlog
from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.Hash import HMAC, MD4, SHA1
from enrichment.lib.nemesis_db import NemesisDb
from enrichment.tasks.dpapi.dpapi_blob import DPAPI_BLOB
from enrichment.tasks.dpapi.masterkey import MasterKey

# from enrichment.tasks.dpapi.masterkey import MasterKey
from impacket.dpapi import DPAPI_DOMAIN_RSA_MASTER_KEY  # MasterKey,
from impacket.dpapi import PRIVATE_KEY_BLOB, PVK_FILE_HDR, privatekeyblob_to_pkcs1
from impacket.uuid import bin_to_string
from nemesiscommon.messaging import (
    MessageQueueConsumerInterface,
    MessageQueueProducerInterface,
)
from nemesiscommon.nemesis_tempfile import TempFile
from nemesiscommon.services.alerter import AlerterInterface
from nemesiscommon.storage import StorageInterface
from nemesiscommon.tasking import TaskInterface
from prometheus_async import aio
from prometheus_client import Summary

logger = structlog.get_logger(module=__name__)


class Dpapi(TaskInterface):
    data_download_dir: str
    alerter: AlerterInterface
    db: NemesisDb

    # Queues
    in_q_dpapi_blob: MessageQueueConsumerInterface
    in_q_dpapi_masterkey: MessageQueueConsumerInterface
    in_q_dpapi_domainbackupkey: MessageQueueConsumerInterface
    in_q_chromiumlogins: MessageQueueConsumerInterface
    in_q_chromiumstatefile: MessageQueueConsumerInterface
    in_q_authentication_data: MessageQueueConsumerInterface
    out_q_dpapiblobprocessed: MessageQueueProducerInterface
    out_q_dpapimasterkeyprocessed: MessageQueueProducerInterface
    out_q_chromiumloginsprocessed: MessageQueueProducerInterface
    out_q_chromiumstatefileprocessed: MessageQueueProducerInterface

    def __init__(
        self,
        data_download_dir: str,
        alerter: AlerterInterface,
        db: NemesisDb,
        storage: StorageInterface,
        in_q_chromiumlogins: MessageQueueConsumerInterface,
        in_q_chromiumstatefile: MessageQueueConsumerInterface,
        in_q_dpapiblob: MessageQueueConsumerInterface,
        in_q_dpapidomainbackupkey: MessageQueueConsumerInterface,
        in_q_dpapimasterkey: MessageQueueConsumerInterface,
        in_q_authentication_data: MessageQueueConsumerInterface,
        out_q_chromiumloginsprocessed: MessageQueueProducerInterface,
        out_q_chromiumstatefileprocessed: MessageQueueProducerInterface,
        out_q_dpapiblobprocessed: MessageQueueProducerInterface,
        out_q_dpapimasterkeyprocessed: MessageQueueProducerInterface,
    ):
        self.data_download_dir = data_download_dir
        self.alerter = alerter
        self.db = db
        self.storage = storage

        # Queues
        self.in_q_chromiumlogins = in_q_chromiumlogins
        self.in_q_chromiumstatefile = in_q_chromiumstatefile
        self.in_q_dpapi_blob = in_q_dpapiblob
        self.in_q_dpapi_domainbackupkey = in_q_dpapidomainbackupkey
        self.in_q_dpapi_masterkey = in_q_dpapimasterkey
        self.in_q_authentication_data = in_q_authentication_data
        self.out_q_chromiumloginsprocessed = out_q_chromiumloginsprocessed
        self.out_q_chromiumstatefileprocessed = out_q_chromiumstatefileprocessed
        self.out_q_dpapiblobprocessed = out_q_dpapiblobprocessed
        self.out_q_dpapimasterkeyprocessed = out_q_dpapimasterkeyprocessed

    async def run(self) -> None:
        await logger.ainfo("Starting the DPAPI service")

        await asyncio.gather(
            self.in_q_dpapi_blob.Read(self.handle_dpapi_blob),  # type: ignore
            self.in_q_dpapi_masterkey.Read(self.handle_dpapi_masterkey),  # type: ignore
            self.in_q_dpapi_domainbackupkey.Read(self.handle_dpapi_domain_backupkey),  # type: ignore
            self.in_q_chromiumlogins.Read(self.handle_chromium_logins),  # type: ignore
            self.in_q_chromiumstatefile.Read(self.handle_chromium_state_file),  # type: ignore
            self.in_q_authentication_data.Read(self.handle_authentication_data),  # type: ignore
        )
        await asyncio.Future()

    async def handle_dpapi_blob(self, q_msg: pb.DpapiBlobMessage) -> None:
        await self.process_dpapi_blob(q_msg)

    async def handle_dpapi_masterkey(self, q_msg: pb.DpapiMasterkeyMessage) -> None:
        await self.process_dpapi_masterkey(q_msg)

    async def handle_dpapi_domain_backupkey(self, q_msg: pb.DpapiDomainBackupkeyMessage) -> None:
        await self.process_dpapi_domain_backupkey(q_msg)

    async def handle_chromium_logins(self, q_msg: pb.ChromiumLoginMessage) -> None:
        await self.process_chromium_logins(q_msg)

    async def handle_chromium_state_file(self, q_msg: pb.ChromiumStateFileMessage) -> None:
        await self.process_chromium_state_file(q_msg)

    async def handle_authentication_data(self, q_msg: pb.AuthenticationDataIngestionMessage) -> None:
        await self.process_authentication_data(q_msg)

    @aio.time(Summary("process_dpapi_blob", "Time spent processing a DPAPI blob"))  # type: ignore
    async def process_dpapi_blob(self, event: pb.DpapiBlobMessage) -> None:
        """Main function to process dpapi_blob events."""

        for i in range(len(event.data)):
            data = event.data[i]

            if data.is_file:
                # if this blob is over 1024 bytes, it's uploaded to S3
                blob_file_uuid = blob_file_uuid = uuid.UUID(data.enc_data_object_id)

                with await self.storage.download(blob_file_uuid) as temp_file_enc:
                    # download the file and try to decrypt these bytes
                    with open(temp_file_enc.name, "rb") as f:
                        blob_bytes = f.read()

                    # try to decrypt this blob if there's a linked key
                    blob_dec_bytes = await self.decrypt_dpapi_blob(blob_bytes)

                    if blob_dec_bytes:
                        async with TempFile(self.data_download_dir) as temp_file_dec:
                            with open(temp_file_dec.path, "wb") as f:
                                f.write(blob_dec_bytes)

                            decrypted_file_uuid = await self.storage.upload(temp_file_dec.path)
                            data.is_decrypted = True
                            data.dec_data_object_id = str(decrypted_file_uuid)
            else:
                # otherwise we're dealing with the raw bytes if the size is < 1024
                blob_dec_bytes = await self.decrypt_dpapi_blob(data.enc_data_bytes)
                if blob_dec_bytes:
                    data.is_decrypted = True
                    data.dec_data_bytes = blob_dec_bytes

        # publish out to the dpapi_blob_processed_q_out queue
        await self.out_q_dpapiblobprocessed.Send(event.SerializeToString())

    @aio.time(Summary("process_dpapi_masterkey", "Time spent processing a DPAPI masterkey"))  # type: ignore
    async def process_dpapi_masterkey(self, event: pb.DpapiMasterkeyMessage) -> None:
        """Main function to process dpapi_masterkey events.

        This function will take any incoming masterkeys, check if there
        are any linked encrypted domain backup keys in the DB, decrypting
        the masterkey and updating it in the DB if so.

        Broken out separately to get the Prometheus decorator to work correctly.
        """

        for i in range(len(event.data)):
            masterkey = event.data[i]

            if not masterkey.is_decrypted:
                if masterkey.type == "machine":
                    # TODO: handle machine DPAPI keys
                    pass
                else:
                    if masterkey.domain_backupkey_guid and masterkey.domainkey_pb_secret:
                        # if there's a linked domain backup key, try to decrypt this masterkey
                        results = await self.decrypt_dpapi_domain_masterkey(
                            masterkey.domainkey_pb_secret, domain_backupkey_guid=masterkey.domain_backupkey_guid
                        )

                        if results:
                            await logger.adebug(
                                "Decrypted masterkey with domain backup key", masterkey_guid=masterkey.masterkey_guid
                            )
                            # update this object with the decrypted values
                            masterkey.decrypted_key_sha1, masterkey.decrypted_key_full = results
                            masterkey.is_decrypted = True

                    if not masterkey.is_decrypted and masterkey.user_sid:
                        # if domain key decryption didn't work or a domain backup key wasn't present,
                        #   try decrypting with plaintext passwords/NTLM hashes
                        plaintext_passwords = await self.db.get_plaintext_passwords(masterkey.username)
                        ntlm_hashes = await self.db.get_ntlm_hashes(masterkey.username)
                        if plaintext_passwords or ntlm_hashes:
                            results = await self.decrypt_dpapi_masterkey(
                                masterkey.masterkey_bytes, masterkey.user_sid, plaintext_passwords, ntlm_hashes
                            )
                            if results:
                                await logger.adebug("Decrypted masterkey with existing plaintext password or ntlm hash")
                                # update this object with the decrypted values
                                masterkey.decrypted_key_sha1, masterkey.decrypted_key_full = results
                                masterkey.is_decrypted = True

            m = event.metadata
            obj = DpapiMasterkey(
                agent_id=m.agent_id,
                project_id=m.project,
                source=m.source,
                timestamp=m.timestamp.ToDatetime(),
                expiration=m.expiration.ToDatetime(),
                object_id=masterkey.object_id,
                type=masterkey.type,
                username=masterkey.username,
                user_sid=masterkey.user_sid,
                masterkey_guid=uuid.UUID(masterkey.masterkey_guid),
                is_decrypted=masterkey.is_decrypted,
                masterkey_bytes=masterkey.masterkey_bytes,
                domain_backupkey_guid=uuid.UUID(masterkey.domain_backupkey_guid)
                if masterkey.domain_backupkey_guid
                else None,
                domainkey_pb_secret=masterkey.domainkey_pb_secret,
                decrypted_key_full=masterkey.decrypted_key_full,
                decrypted_key_sha1=masterkey.decrypted_key_sha1,
            )
            await self.db.add_dpapi_masterkey(obj)

            if masterkey.is_decrypted:
                # decrypt any existing linked DPAPI blobs
                await self.decrypt_existing_dpapi_blobs(masterkey.masterkey_guid)
                await logger.ainfo(
                    "Decrypted any existing blobs protected by the masterkey", masterkey_guid=masterkey.masterkey_guid
                )

                # decrypt any existing linked Chromium data
                await self.decrypt_existing_chromium_data(masterkey.masterkey_guid)
                await logger.ainfo(
                    "Decrypted any existing Chromium data by the masterkey", masterkey_guid=masterkey.masterkey_guid
                )

        # publish out to the dpapi_masterkey_processed_q_out queue
        await self.out_q_dpapimasterkeyprocessed.Send(event.SerializeToString())

    @aio.time(Summary("process_dpapi_domain_backupkey", "Time spent processing a DPAPI masterkey"))  # type: ignore
    async def process_dpapi_domain_backupkey(self, event) -> None:
        """Main function to process dpapi_domain_backupkey events.

        This function will process a DPAPI domain backup key event,
        adding the key to the database and decrypting any existing
        DPAPI masterkeys.
        """

        for key in event.data:
            domain_backupkey_guid = key.domain_backupkey_guid
            domain_controller = key.domain_controller
            domain_backupkey_bytes = key.domain_backupkey_bytes

            # add the key to the database
            obj = DpapiDomainBackupkey(
                agent_id=event.metadata.agent_id,
                project_id=event.metadata.project,
                source=event.metadata.source,
                timestamp=event.metadata.timestamp.ToDatetime(),
                expiration=event.metadata.expiration.ToDatetime(),
                domain_backupkey_guid=domain_backupkey_guid,
                domain_controller=domain_controller,
                domain_backupkey_bytes=domain_backupkey_bytes,
            )
            await self.db.add_dpapi_domain_backupkey(obj)

            # alert to Slack
            await self.alerter.alert(
                f"*DPAPI Domain Backup Key Added*\nAdded domain backupkey (GUID: *{domain_backupkey_guid}*) to the database"
            )

            await logger.adebug("Added domain backupkey to the database", domain_backupkey_guid=domain_backupkey_guid)

            # decrypt any existing linked masterkeys
            await self.decrypt_existing_dpapi_masterkeys_with_domain_key(domain_backupkey_guid)

    @aio.time(Summary("process_chromium_logins", "Time spent processing a Chromium Logins file message"))  # type: ignore
    async def process_chromium_logins(self, event: pb.ChromiumLoginMessage) -> None:
        """Main function to process chromium_logins events.

        Login entries are checked for AES/DPAPI decryption, and the appropriate
        state key or DPAPI masterkey is pulled if it's present and decrypted.
        If present, this key is then used to decrypt the login entry to plaintext.
        """

        # get all of the unique masterkey GUIDs off the bat so we can retrieve them just once
        masterkey_guids_uniq = set(
            [
                entry.masterkey_guid
                for entry in event.data
                if (entry.encryption_type == "dpapi" and entry.masterkey_guid != "00000000-0000-0000-0000-000000000000")
            ]
        )
        masterkeys = {}
        for mk_guid in masterkey_guids_uniq:
            results = await self.db.get_decrypted_dpapi_masterkey(mk_guid)
            if results:
                (masterkey_sha1, masterkey_full) = results
                if masterkey_sha1:
                    masterkeys[mk_guid] = masterkey_sha1
                elif masterkey_full:
                    masterkeys[mk_guid] = masterkey_full

        # get the decrypted AES state key value(s) linked to these logins, if it/they exist
        #   we use source + user_data_directory for relative "uniqueness"
        data_directories_uniq = set([entry.user_data_directory for entry in event.data])
        data_directories = {}
        for data_directory in data_directories_uniq:
            result = await self.db.get_decrypted_chromium_state_key(event.metadata.source, data_directory)
            if result:
                data_directories[data_directory] = result

        for i in range(len(event.data)):
            entry = event.data[i]
            if entry.masterkey_guid in masterkeys:
                # use the Impacket DPAPI_BLOB structure in lib/dpapi_blob.py
                blob = DPAPI_BLOB(entry.password_value_enc)
                blob_dec_bytes = blob.decrypt(masterkeys[entry.masterkey_guid])
                if blob_dec_bytes:
                    entry.password_value_dec = blob_dec_bytes.decode("UTF-8")
                    entry.is_decrypted = True

            elif entry.encryption_type == "aes" and entry.user_data_directory in data_directories:
                state_key_bytes_dec = data_directories[entry.user_data_directory]
                if state_key_bytes_dec:
                    try:
                        plaintext = await self.decrypt_chromium_aes_entry(state_key_bytes_dec, entry.password_value_enc)
                        if plaintext:
                            entry.password_value_dec = plaintext
                            entry.is_decrypted = True
                    except Exception:
                        await logger.aerror(
                            "Error AES decrypting login value",
                            source=event.metadata.source,
                            signon_realm=entry.signon_realm,
                            user_data_directory=entry.user_data_directory,
                        )

        # publish out to the chromium_logins_processed_q_out queue
        await self.out_q_chromiumloginsprocessed.Send(event.SerializeToString())

    @aio.time(Summary("process_chromium_state_file", "Time spent processing a Chromium Local State file message"))  # type: ignore
    async def process_chromium_state_file(self, event: pb.ChromiumStateFileMessage) -> None:
        """Main function to process chromium_state_file events.

        The encrypted_key value for Local State file is parsed as a DPAPI protected
        blob and the appropriate DPAPI masterkey is pulled if it's present and decrypted.
        If present, this key is then used to decrypt the encryption key.
        """

        # get all of the unique masterkey GUIDs off the bat so we can retrieve them just once
        masterkey_guids_uniq = set(
            [
                entry.masterkey_guid
                for entry in event.data
                if entry.masterkey_guid != "00000000-0000-0000-0000-000000000000"
            ]
        )
        masterkeys = {}
        for mk_guid in masterkey_guids_uniq:
            results = await self.db.get_decrypted_dpapi_masterkey(mk_guid)
            if results:
                (masterkey_sha1, masterkey_full) = results
                if masterkey_sha1:
                    masterkeys[mk_guid] = masterkey_sha1
                elif masterkey_full:
                    masterkeys[mk_guid] = masterkey_full

        for i in range(len(event.data)):
            data = event.data[i]
            if data.masterkey_guid in masterkeys:
                try:
                    # use the Impacket DPAPI_BLOB struture in lib/dpapi_blob.py
                    blob = DPAPI_BLOB(data.key_bytes_enc)
                    blob_dec_bytes = blob.decrypt(masterkeys[data.masterkey_guid])
                    if blob_dec_bytes:
                        data.is_decrypted = True
                        data.key_bytes_dec = blob_dec_bytes

                    # if data.app_bound_fixed_data_enc is not None:
                    #     blob2 = DPAPI_BLOB(data.app_bound_fixed_data_enc)
                    #     blob_dec_bytes2 = blob2.decrypt(masterkeys[data.masterkey_guid])
                    #     if blob_dec_bytes2:
                    #         data.app_bound_fixed_data_dec = blob_dec_bytes2
                except Exception as e:
                    await logger.aexception(e, message="error decrypting state key DPAPI value")

        # publish out to the chromium_state_file_processed_q_out queue
        await self.out_q_chromiumstatefileprocessed.Send(event.SerializeToString())

    @aio.time(Summary("process_authentication_data2", "Time spent processing a authentication data message"))  # type: ignore
    async def process_authentication_data(self, event: pb.AuthenticationDataIngestionMessage) -> None:
        """Main function to process authentication_data events.

        Specifically, we're looking for any message with the "type" of dpapi_master_key so we
        can extract out the GUID:masterkey values and create a new masterkey in the database.
        """

        m = event.metadata

        for i in range(len(event.data)):
            data = event.data[i]

            if data.type and data.type == "dpapi_master_key":
                if ":" in data.data:
                    (guid, key) = data.data.split(":")
                    guid = guid.strip("{}")
                    username = data.username

                    obj = DpapiMasterkey(
                        agent_id=m.agent_id,
                        project_id=m.project,
                        source=m.source,
                        timestamp=m.timestamp.ToDatetime(),
                        expiration=m.expiration.ToDatetime(),
                        username=username,
                        masterkey_guid=uuid.UUID(guid),
                        is_decrypted=True,
                        decrypted_key_sha1=key,
                    )
                    await self.db.add_dpapi_masterkey(obj)

            elif data.type and data.type == "password":
                await self.decrypt_existing_dpapi_masterkeys_with_user_key(data.username, "password", data.data)

            elif data.type and data.type == "ntlm_hash":
                await self.decrypt_existing_dpapi_masterkeys_with_user_key(data.username, "ntlm_hash", data.data)

    ###################################################
    #
    # DPAPI helpers
    #
    ###################################################

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

    async def decrypt_dpapi_blob(self, blob_bytes):
        """
        Takes DPAPI blob bytes, queries the DB for an applicable decryption key,
        and decrypts the bytes if possible.

        Returns None on failure.
        """

        blob = DPAPI_BLOB(blob_bytes)

        # extract the masterkey GUID from this DPAPI blob
        masterkey_guid = bin_to_string(blob["GuidMasterKey"]).lower()

        if masterkey_guid:
            # check if this masterkey is decrypted in Postgres
            results = await self.db.get_decrypted_dpapi_masterkey(masterkey_guid)

            if results:
                (masterkey_sha1, masterkey_full) = results
                if masterkey_sha1:
                    return blob.decrypt(masterkey_sha1)
                elif masterkey_full:
                    return blob.decrypt(masterkey_full)
                else:
                    return None
            else:
                return None

    async def decrypt_dpapi_masterkey(
        self,
        masterkey_bytes: bytes,
        user_sid: str,
        passwords: Optional[List[str]] = None,
        ntlm_hashes: Optional[List[str]] = None,
    ) -> Optional[Tuple[bytes, bytes]]:
        """
        Takes raw masterkey bytes + user sid and optional lists of plaintext
        passwords and/or NTLM hashes and attempts to decrypt the masterkey,
        returning the SHA1 and "full" keys if possible.

        Returns None on failure.

        TODO: any way to parallelize this?
        """

        mk = MasterKey(masterkey_bytes)

        if passwords:
            for password in passwords:
                keys = await self.derive_keys_from_user(user_sid, password)
                for key in list(keys):
                    decrypted_masterkey = mk.decrypt(key)
                    # print(f"Password key tried in: {time.time() - start} seconds ({key.hex()})")
                    if decrypted_masterkey:
                        return (decrypted_masterkey, SHA1.new(decrypted_masterkey).digest())
            await logger.ainfo(f"Failed to decrypt DPAPI masterkey with {len(passwords)} total passwords")
        if ntlm_hashes:
            for ntlm_hash in ntlm_hashes:
                keys = await self.derive_keys_from_user_key(user_sid, ntlm_hash)
                for key in list(keys):
                    decrypted_masterkey = mk.decrypt(key)
                    # print(f"NTLM hash key tried in: {time.time() - start} seconds ({key.hex()})")
                    if decrypted_masterkey:
                        return (decrypted_masterkey, SHA1.new(decrypted_masterkey).digest())
            await logger.ainfo(f"Failed to decrypt DPAPI masterkey with {len(ntlm_hashes)} NTLM hashes")
            return None
        else:
            await logger.awarning("No passwords or ntlm hashes passed for masterkey decryption")

    async def decrypt_dpapi_domain_masterkey(
        self,
        masterkey_secret_bytes: bytes,
        domain_backupkey_guid: Optional[str] = None,
        domain_backupkey_bytes: Optional[bytes] = None,
    ) -> Optional[Tuple[bytes, bytes]]:
        """
        Takes the GUID of the specified domain DPAPI backup key and the `domainkey_pb_secret`
        bytes from a masterkey, queries the DB for an applicable dpapi domain backupkey,
        and decrypts the masterkey if possible, returning the SHA1 and "full" keys.

        Returns None on failure.
        """

        if domain_backupkey_guid:
            # query the DB for the bytes for this specific domain backup key GUID
            domain_backupkey_bytes = await self.db.get_dpapi_domain_backupkey(domain_backupkey_guid)

        if domain_backupkey_bytes:
            # adapted from Impacket: https://github.com/fortra/impacket/blob/8799a1a2c42ad74423841d21ed5f4193ea54f3d5/examples/dpapi.py#L214-L224
            #   Apache License Version 1.1
            key = PRIVATE_KEY_BLOB(domain_backupkey_bytes[len(PVK_FILE_HDR()) :])
            private = privatekeyblob_to_pkcs1(key)
            cipher = PKCS1_v1_5.new(private)
            decrypted_key = cipher.decrypt(masterkey_secret_bytes[::-1], None)

            if decrypted_key:
                domain_master_key = DPAPI_DOMAIN_RSA_MASTER_KEY(decrypted_key)
                full_key = domain_master_key["buffer"][: domain_master_key["cbMasterKey"]]
                sha1_key = SHA1.new(full_key).digest()

                # # For string representations:
                # full_key = hexlify(key).decode('latin-1')
                # sha1_key = hexlify(SHA1.new(key).digest()).decode('latin-1')

                return (sha1_key, full_key)
            else:
                await logger.aerror(
                    "Failed to decrypt DPAPI masterkey with domain backupkey",
                    domain_backupkey_guid=domain_backupkey_guid,
                )
        else:
            return None

    async def decrypt_existing_dpapi_masterkeys_with_user_key(self, username: str, key_type: str, key: str) -> None:
        """
        Given a username and password/NTLM hash, query the DB for any
        masterkeys for that username and attempt to decrypt the masterkey
        with the plaintext or hash.

        key_type -> "password" or "ntlm_hash"

        This is "retroactive" masterkey decryption with a password/hash.
        """

        await logger.adebug(
            "Checking if the password/NTLM hash can decrypt any masterkeys", username=username, key_type=key_type
        )

        encrypted_masterkeys = await self.db.get_encrypted_dpapi_masterkeys_from_username(username)

        if not encrypted_masterkeys:
            await logger.adebug("No masterkeys found in the DB matching the username", username=username)
            return

        await logger.adebug(
            "Found masterkeys in the DB matching the username",
            username=username,
            count=len(encrypted_masterkeys),
        )

        decrypted_masterkeys = 0
        for masterkey in encrypted_masterkeys:
            masterkey_guid = masterkey[0]
            user_sid = masterkey[1]
            masterkey_bytes = masterkey[2]

            if key_type == "password":
                results = await self.decrypt_dpapi_masterkey(masterkey_bytes, user_sid, [key], [])
            else:
                results = await self.decrypt_dpapi_masterkey(masterkey_bytes, user_sid, [], [key])

            if results:
                decrypted_masterkeys += 1
                decrypted_key_full = results[0]
                decrypted_key_sha1 = results[1]

                # update the masterkey in the DB with the decrypted values
                await self.db.update_decrypted_dpapi_masterkey(masterkey_guid, decrypted_key_sha1, decrypted_key_full)

                # decrypt existing DPAPI blobs
                await self.decrypt_existing_dpapi_blobs(masterkey_guid)

                # decrypt existing Chromium data
                await self.decrypt_existing_chromium_data(masterkey_guid)

                await logger.adebug(
                    "Decrypted any existing blobs protected by the newly decrypted GUID master key",
                    masterkey_guid=masterkey_guid,
                )
            else:
                await logger.aerror(
                    "Failed to decrypt DPAPI masterkey supplied password/NTLM hash",
                    masterkey_guid=masterkey_guid,
                    key_type=key_type,
                    key=key,
                )

    async def decrypt_existing_dpapi_masterkeys_with_domain_key(self, domain_backupkey_guid: str) -> None:
        """
        Given a domain_backupkey_guid, query the DB for any linked encrypted
        masterkeys, decrypting the keys and updating the encrypted value if
        decryption is successful.

        This is "retroactive" masterkey decryption with a domain key.
        """
        await logger.adebug(
            "Decrypt masterkeys protected by the GUID domain backupkey", domain_backupkey_guid=domain_backupkey_guid
        )

        # query the DB for the bytes for this specific domain backup key GUID
        domain_backupkey_bytes = await self.db.get_dpapi_domain_backupkey(domain_backupkey_guid)

        if not domain_backupkey_bytes:
            await logger.ainfo("No domain backupkey found in the DB", domain_backupkey_guid=domain_backupkey_guid)
            return

        # query the DB for any masterkeys protected by this domain backupkey
        encrypted_masterkeys = await self.db.get_encrypted_dpapi_masterkeys_from_backup_guid(domain_backupkey_guid)
        if not encrypted_masterkeys:
            await logger.ainfo(
                "No masterkeys found in the DB matching the domain backup key",
                domain_backupkey_guid=domain_backupkey_guid,
            )
            return
        else:
            await logger.ainfo(
                "Found masterkeys in the DB matching the domain backup key",
                domain_backupkey_guid=domain_backupkey_guid,
                count=len(encrypted_masterkeys),
            )

        decrypted_masterkeys = 0
        for masterkey in encrypted_masterkeys:
            masterkey_guid = masterkey[0]
            domainkey_pb_secret = masterkey[1]

            results = await self.decrypt_dpapi_domain_masterkey(
                domainkey_pb_secret, domain_backupkey_bytes=domain_backupkey_bytes
            )

            if results:
                decrypted_masterkeys += 1
                decrypted_key_sha1 = results[0]
                decrypted_key_full = results[1]

                # update the masterkey in the DB with the decrypted values
                await self.db.update_decrypted_dpapi_masterkey(masterkey_guid, decrypted_key_sha1, decrypted_key_full)

                # decrypt existing DPAPI blobs
                await self.decrypt_existing_dpapi_blobs(masterkey_guid)

                # decrypt existing Chromium data
                await self.decrypt_existing_chromium_data(masterkey_guid)

                await logger.adebug(
                    "Decrypted any existing blobs protected by the newly decrypted GUID master key",
                    masterkey_guid=masterkey_guid,
                )
            else:
                await logger.aerror(
                    "Failed to decrypt DPAPI masterkey with domain backupkey",
                    masterkey_guid=masterkey_guid,
                    domain_backupkey_guid=domain_backupkey_guid,
                )

    async def decrypt_existing_dpapi_blobs(self, masterkey_guid: str):
        """
        Given a masterkey_guid, query the DB for any linked encrypted
        blobs, decrypting the blobs and updating the encrypted value if
        decryption is successful.

        This is "retroactive" decryption for DPAPI blobs.
        """

        # get the decrypted masterkey bytes for the masterkey GUID
        masterkey_keys = await self.db.get_decrypted_dpapi_masterkey(masterkey_guid)

        if masterkey_keys:
            (masterkey_sha1, masterkey_full) = masterkey_keys
            masterkey_bytes = masterkey_sha1 if masterkey_sha1 else masterkey_full

            for blob in await self.db.get_encrypted_dpapi_blobs(masterkey_guid):
                dpapi_blob_id = blob[0]
                is_file = blob[1]
                enc_data_bytes = blob[2]
                enc_data_object_id = blob[3]

                if is_file:
                    # if this blob is over 1024 bytes, it's uploaded to S3
                    with await self.storage.download(enc_data_object_id) as temp_file:
                        # download the file and try to decrypt these bytes
                        with open(temp_file.name, "rb") as f:
                            enc_data_bytes = f.read()

                # try to decrypt this blob if there's a linked key
                dec_data = DPAPI_BLOB(enc_data_bytes).decrypt(masterkey_bytes)

                if not dec_data:
                    raise RuntimeError("Failed to decrypt DPAPI blob despite having a plaintext masterkey")

                await logger.adebug(
                    "Decrypted DPAPI blob with masterkey", dpapi_blob_id=dpapi_blob_id, masterkey_guid=masterkey_guid
                )
                if is_file:
                    # if the original enc_bytes were stored as a S3 file, store the decypted bytes in S3 as well
                    async with TempFile(self.data_download_dir) as temp_file_dec:
                        with open(temp_file_dec.path, "wb") as f:
                            f.write(dec_data)

                        decrypted_file_uuid = await self.storage.upload(temp_file_dec.path)
                        await self.db.update_decrypted_dpapi_blob(dpapi_blob_id, None, decrypted_file_uuid)
                else:
                    await self.db.update_decrypted_dpapi_blob(dpapi_blob_id, dec_data, None)
        else:
            await logger.adebug("No decrypted masterkeys found for masterkey GUID", masterkey_guid=masterkey_guid)

    async def decrypt_existing_chromium_data(self, masterkey_guid):
        """
        Given a masterkey_guid, query the DB for any linked encrypted
        Chromium data, decrypting the data and updating the associated
        values if decryption is successful.

        This is "retroactive" decryption for Chromium DPAPI data.

        Chromium data processed: logins, cookies, state files
        """

        # get the decrypted masterkey bytes for the masterkey GUID
        masterkey_keys = await self.db.get_decrypted_dpapi_masterkey(masterkey_guid)

        if masterkey_keys:
            (masterkey_sha1, masterkey_full) = masterkey_keys
            masterkey_bytes = masterkey_sha1 if masterkey_sha1 else masterkey_full

            # first check for Chromium state keys protected by this masterkey
            for state_file in await self.db.get_encrypted_chromium_state_key(masterkey_guid):
                (source, user_data_directory, unique_db_id, key_bytes_enc, app_bound_fixed_data_enc) = state_file

                # try to decrypt this state key if there's a linked key
                key_bytes_dec = DPAPI_BLOB(key_bytes_enc).decrypt(masterkey_bytes)
                app_bound_fixed_data_dec = None

                # try:
                #     # TODO: this isn't working properly, something with padding on decryption
                #     app_bound_fixed_data_blob = await helpers.parse_dpapi_blob(app_bound_fixed_data_enc)
                #     blob = DPAPI_BLOB(app_bound_fixed_data_blob.dpapi_data)
                #     app_bound_fixed_data_dec = blob.decrypt(masterkey_bytes)
                # except Exception as e:
                #     await logger.adebug(
                #         "Error decypting app_bound_fixed_data value",
                #         exception=f"{e}",
                #         unique_db_id=unique_db_id,
                #         masterkey_guid=masterkey_guid,
                #     )

                if not key_bytes_dec:
                    raise RuntimeError(
                        "Failed to decrypt Chromium state encryption key despite having a plaintext masterkey"
                    )

                await logger.adebug(
                    "Decrypted Chromium state key with masterkey",
                    unique_db_id=unique_db_id,
                    masterkey_guid=masterkey_guid,
                )
                await self.db.update_decrypted_chromium_state_key(unique_db_id, key_bytes_dec, app_bound_fixed_data_dec)

                # NOW we have to retroactively decrypt any cookies/logins that use this AES key
                decrypted_logins_count = 0
                for login in await self.db.get_aes_encrypted_chromium_logins(source, user_data_directory):
                    unique_db_id = login[0]
                    password_value_enc = login[1]
                    plaintext = await self.decrypt_chromium_aes_entry(key_bytes_dec, password_value_enc)
                    if plaintext:
                        decrypted_logins_count += 1
                        await self.db.update_decrypted_chromium_login(unique_db_id, plaintext)

                if decrypted_logins_count > 0:
                    await logger.adebug(
                        "Decrypted existing Chromium logins with newly Chromium state key",
                        decrypted_logins_count=decrypted_logins_count,
                    )

                decrypted_cookies_count = 0
                for cookie in await self.db.get_aes_encrypted_chromium_cookies(source, user_data_directory):
                    unique_db_id = cookie[0]
                    value_dec = cookie[1]
                    try:
                        plaintext = await self.decrypt_chromium_aes_entry(key_bytes_dec, value_dec)
                        if plaintext:
                            decrypted_cookies_count += 1
                            await self.db.update_decrypted_chromium_cookie(unique_db_id, plaintext)
                    except Exception as e:
                        await logger.aerror(
                            "Error AES decrypting cookie value",
                            exception=e,
                            unique_db_id=unique_db_id,
                            source=source,
                            user_data_directory=user_data_directory,
                        )

                if decrypted_cookies_count > 0:
                    await logger.adebug(
                        "Decrypted existing Chromium cookies with newly Chromium state key",
                        decrypted_cookies_count=decrypted_cookies_count,
                    )

            # then try for any DPAPI protected Logins
            for login in await self.db.get_dpapi_encrypted_chromium_logins(masterkey_guid):
                unique_db_id = login[0]
                password_value_enc = login[1]

                # try to decrypt this login value if there's a linked key
                password_value_dec = DPAPI_BLOB(password_value_enc).decrypt(masterkey_bytes)

                if not password_value_dec:
                    raise RuntimeError("Failed to decrypt Chromium login despite having a plaintext masterkey")

                password_value_dec = password_value_dec.decode("UTF-8")

                await logger.adebug(
                    "Decrypted Chromium login with masterkey", unique_db_id=unique_db_id, masterkey_guid=masterkey_guid
                )
                await self.db.update_decrypted_chromium_login(unique_db_id, password_value_dec)

            # finally check for any DPAPI protected Cookies
            for cookie in await self.db.get_dpapi_encrypted_chromium_cookies(masterkey_guid):
                unique_db_id = cookie[0]
                password_value_enc = cookie[1]

                # try to decrypt this login value if there's a linked key
                value_dec = DPAPI_BLOB(password_value_enc).decrypt(masterkey_bytes)

                if not value_dec:
                    raise RuntimeError("Failed to decrypt Chromium cookie despite having a plaintext masterkey")

                value_dec = value_dec.decode("UTF-8")

                await logger.adebug(
                    "Decrypted Chromium cookie with masterkey", unique_db_id=unique_db_id, masterkey_guid=masterkey_guid
                )
                await self.db.update_decrypted_chromium_cookie(unique_db_id, value_dec)

    async def derive_keys_from_user(self, sid, password):
        """
        Given a user SID and password, derive the DPAPI masterkey keys needed.

        TODO: not yet used

        From https://github.com/SecureAuthCorp/impacket/blob/7a18ef5c8b06aac5e36334927789429777382928/examples/dpapi.py#L94
             Apache License Version 1.1
        """
        # Will generate two keys, one with SHA1 and another with MD4
        key1 = HMAC.new(SHA1.new(password.encode("utf-16le")).digest(), (sid + "\0").encode("utf-16le"), SHA1).digest()
        key2 = HMAC.new(MD4.new(password.encode("utf-16le")).digest(), (sid + "\0").encode("utf-16le"), SHA1).digest()
        # For Protected users
        # TODO!!
        tmpKey = pbkdf2_hmac("sha256", MD4.new(password.encode("utf-16le")).digest(), sid.encode("utf-16le"), 10000)
        tmpKey2 = pbkdf2_hmac("sha256", tmpKey, sid.encode("utf-16le"), 1)[:16]
        key3 = HMAC.new(tmpKey2, (sid + "\0").encode("utf-16le"), SHA1).digest()[:20]
        return key1, key2, key3

    async def derive_keys_from_user_key(self, sid, pwdhash):
        """
        Given a user SID and NTLM hash, derive the DPAPI masterkey keys needed.

        TODO: not yet used

        From https://github.com/SecureAuthCorp/impacket/blob/7a18ef5c8b06aac5e36334927789429777382928/examples/dpapi.py#L105
             Apache License Version 1.1
        """
        pwdhash = bytes.fromhex(pwdhash)
        if len(pwdhash) == 20:
            # SHA1
            key1 = HMAC.new(pwdhash, (sid + "\0").encode("utf-16le"), SHA1).digest()
            key2 = None
        else:
            # Assume MD4
            key1 = HMAC.new(pwdhash, (sid + "\0").encode("utf-16le"), SHA1).digest()
            # For Protected users
            tmpKey = pbkdf2_hmac("sha256", pwdhash, sid.encode("utf-16le"), 10000)
            tmpKey2 = pbkdf2_hmac("sha256", tmpKey, sid.encode("utf-16le"), 1)[:16]
            key2 = HMAC.new(tmpKey2, (sid + "\0").encode("utf-16le"), SHA1).digest()[:20]
        return key1, key2
