# Standard Libraries
import asyncio
import os

# 3rd Party Libraries
import asyncpg
import nemesispb.nemesis_pb2 as pb
import structlog
from nemesiscommon.messaging import (MessageQueueConsumerInterface,
                                     MessageQueueProducerInterface)
from nemesiscommon.services.alerter import AlerterInterface
from nemesiscommon.tasking import TaskInterface
from passwordcracker.services.john_the_ripper_cracker import \
    PasswordCrackerInterface
from passwordcracker.settings import PasswordCrackerSettings
from prometheus_async import aio
from prometheus_client import Summary

logger = structlog.get_logger(module=__name__)


class PasswordCracker(TaskInterface):
    cfg: PasswordCrackerSettings
    alerter: AlerterInterface
    db_pool: asyncpg.pool.Pool
    cracker: PasswordCrackerInterface
    semaphore: asyncio.Semaphore

    # Queues
    auth_data_q_in: MessageQueueConsumerInterface
    extracted_hash_q_out: MessageQueueProducerInterface

    def __init__(
        self,
        cfg: PasswordCrackerSettings,
        alerter: AlerterInterface,
        db_pool: asyncpg.pool.Pool,
        cracker: PasswordCrackerInterface,
        auth_data_q_in: MessageQueueConsumerInterface,
        extracted_hash_q_out: MessageQueueProducerInterface,
    ):
        self.cfg = cfg
        self.alerter = alerter
        self.db_pool = db_pool
        self.cracker = cracker
        self.auth_data_q_in = auth_data_q_in
        self.extracted_hash_q_out = extracted_hash_q_out

        current_dir = os.path.dirname(os.path.realpath(__file__))
        self.wordlist_path = os.path.join(current_dir, "..", "wordlists", f"top_{self.cfg.crack_wordlist_top_words}.txt")
        self.wordlist_path = os.path.abspath(self.wordlist_path)

        if not os.path.exists(self.wordlist_path):
            raise Exception(f"Wordlist file {self.wordlist_path} does not exist")

        # TODO: test the semaphore
        self.semaphore = asyncio.Semaphore()

    async def run(self) -> None:
        await logger.ainfo("Starting the password cracking service")

        await asyncio.gather(
            self.auth_data_q_in.Read(self.handle_auth_data),  # type: ignore
        )
        await asyncio.Future()

    async def handle_auth_data(self, q_msg: pb.AuthenticationDataIngestionMessage) -> None:
        await self.process_auth_data(q_msg)

    async def get_cracked_hash_value(self, hash_value: str):
        """Returns the plaintext value for a hash if it's already cracked."""

        async with self.db_pool.acquire() as conn:
            results = await conn.fetch(
                "SELECT plaintext_value FROM nemesis.extracted_hashes WHERE is_cracked = True AND hash_value = $1",
                hash_value,
            )
            if results:
                return results[0][0]
            else:
                return None

    async def check_if_unsuccessful_crack(self, hash_value: str):
        """Returns True if we already tried to crack this value and failed to do so."""

        async with self.db_pool.acquire() as conn:
            return await conn.fetchval(
                "SELECT EXISTS (SELECT unique_db_id FROM nemesis.extracted_hashes WHERE is_cracked = False AND checked_against_top_passwords = False AND hash_value = $1 LIMIT 1)",
                hash_value,
            )

    @aio.time(Summary("process_auth_data", "Time spent processing an Auth Data event"))  # type: ignore
    async def process_auth_data(self, event: pb.AuthenticationDataIngestionMessage):
        """Main function to process authentication data events."""

        for data in event.data:
            # Skip any event that isn't a hash
            if not len(data.type) > 0 or not data.type.startswith("hash_"):
                continue

            # limit the number of simultaneous JTR instances
            extracted_hash_msg = pb.ExtractedHashMessage()
            extracted_hash_msg.metadata.CopyFrom(event.metadata)
            extracted_hash = extracted_hash_msg.data.add()
            extracted_hash.hash_type = data.type
            extracted_hash.hash_value = data.data
            extracted_hash.originating_object_id = data.originating_object_id

            # TODO: formatting for Hashcat/JTR formats
            extracted_hash.jtr_formatted_value = data.data

            # check if we attempted to crack this value but failed
            unsuccessful_crack = await self.check_if_unsuccessful_crack(data.data)
            if unsuccessful_crack:
                extracted_hash.is_cracked = False
                extracted_hash.checked_against_top_passwords = True
                await logger.ainfo("Hash was previously unsuccessfully cracked, skipping cracking.")
            else:
                # check if this value was already successfully cracked
                cracked_hash_value = await self.get_cracked_hash_value(data.data)
                if cracked_hash_value:
                    # this means the hash is already cracked, so don't crack
                    extracted_hash.is_cracked = True
                    extracted_hash.plaintext_value = cracked_hash_value
                    await logger.ainfo("Hash is already cracked, using existing value and skipping cracking.")
                else:
                    # send the message before using cracking so it can be displayed ASAP
                    await self.extracted_hash_q_out.Send(extracted_hash_msg.SerializeToString())

                    async with self.semaphore:
                        match extracted_hash.hash_type:
                            # handle specific hash types that need the type specified
                            case "hash_crypt":
                                jtr_pot_line = await self.cracker.crack(data.data, self.wordlist_path, "crypt")
                            case _:
                                jtr_pot_line = await self.cracker.crack(data.data, self.wordlist_path)

                        extracted_hash.checked_against_top_passwords = True

                    if jtr_pot_line:
                        extracted_hash.jtr_pot_line = jtr_pot_line
                        extracted_hash.is_cracked = True
                        plaintext = jtr_pot_line
                        extracted_hash.plaintext_value = plaintext
                        await self.send_hash_cracked_alert(extracted_hash, extracted_hash_msg.metadata.message_id)

            # publish the extracted hash out to the extracted_hash_q_out queue
            await self.extracted_hash_q_out.Send(extracted_hash_msg.SerializeToString())

    async def send_hash_cracked_alert(self, extracted_hash: pb.ExtractedHash, message_id: str):
        if extracted_hash.originating_object_id:
            hash_url = await self.get_hashes_url(extracted_hash.originating_object_id)
            view_file_url = await self.get_view_file_url(extracted_hash.originating_object_id)

            await self.alerter.alert(
                f"""
*Hash Cracked*
Hash of type *{extracted_hash.hash_type}* extracted from file *{extracted_hash.originating_object_id}* has been successfully cracked against the top {self.cfg.crack_wordlist_top_words} words in JohnTheRipper
<{hash_url}|*View Cracked Hash*>
<{view_file_url}|*View Originating File*>
"""
            )
        else:
            kibana_url = await self.get_kibana_hash_url(message_id)
            await self.alerter.alert(
                f"""
*Hash Cracked*
Hash of type *{extracted_hash.hash_type}* has been successfully cracked against the top {self.cfg.crack_wordlist_top_words} words in JohnTheRipper
<{kibana_url}|*Cracked hash in Kibana*>"""
            )

    async def get_view_file_url(self, file_uuid: str):
        return f"{self.cfg.public_nemesis_url}File_Viewer?object_id={file_uuid}"

    async def get_hashes_url(self, file_uuid: str):
        return f"{self.cfg.public_nemesis_url}Hashes?object_id={file_uuid}"

    async def get_kibana_hash_url(self, message_uuid: str):
        return f"{self.cfg.public_kibana_url}/app/discover#/?_a=(filters:!((query:(match_phrase:(metadata.messageId:'{message_uuid}')))),index:'d884e1d0-c7a2-11ed-99da-e7509f36608c')&_g=(time:(from:now-1y%2Fd,to:now))"
