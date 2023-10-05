# Standard Libraries
import tempfile
import uuid
from os import urandom
from types import TracebackType
from typing import Optional, Type

# 3rd Party Libraries
import aioboto3
import structlog
from Cryptodome.Cipher import AES
from nemesiscommon.nemesis_tempfile import TempFile
from nemesiscommon.storage import StorageInterface

logger = structlog.get_logger(module=__name__)


class StorageS3(StorageInterface):
    num_bytes_for_len: int
    block_size: int
    cmk_id: str
    data_download_dir: str
    aws_bucket: str
    assessment_id: str

    def __init__(
        self,
        assessment_id: str,
        data_download_dir: str,
        aws_access_key_id: str,
        aws_secret_access_key: str,
        aws_default_region: str,
        aws_bucket_name: str,
        aws_kms_key_alias: str,
    ) -> None:
        self.data_download_dir = data_download_dir
        self.aws_bucket = aws_bucket_name
        self.assessment_id = assessment_id

        self.num_bytes_for_len = 4  # number of bytes used to store the file encryption key size
        self.block_size = AES.block_size  # 16 bytes

        self.cmk_id = f"alias/{aws_kms_key_alias}"
        self._aws_client_args = {
            "aws_access_key_id": aws_access_key_id,
            "aws_secret_access_key": aws_secret_access_key,
            "region_name": aws_default_region,
        }

    async def download(self, file_uuid: uuid.UUID, delete: bool = True) -> tempfile._TemporaryFileWrapper:
        key = await self.get_s3_file_path(file_uuid)

        async with aioboto3.Session().client(service_name="s3", **self._aws_client_args) as s3_client:
            with tempfile.NamedTemporaryFile(dir=self.data_download_dir) as temp_file_enc:
                await logger.adebug(
                    "Downloading from storage",
                    file_uuid=file_uuid,
                    dest_path=temp_file_enc.name,
                )
                temp_file_dec = tempfile.NamedTemporaryFile(dir=self.data_download_dir, delete=delete)

                try:
                    await s3_client.download_file(self.aws_bucket, key, temp_file_enc.name)
                except BaseException as e:
                    await logger.aexception(e, message="Failed to download file")
                    raise
                finally:
                    await logger.ainfo("Downloaded file", file_uuid=file_uuid)
                # decrypt the file by using the associated KMS key
                await self.kms_decrypt_file(temp_file_enc.name, temp_file_dec.name)
                return temp_file_dec

    async def upload(self, file_path: str) -> uuid.UUID:
        await logger.adebug("Uploading to storage", file_path=file_path)

        async with aioboto3.Session().client(service_name="s3", **self._aws_client_args) as s3_client:
            async with TempFile(self.data_download_dir) as encrypted_file:
                new_file_uuid = uuid.uuid4()
                s3_key = await self.get_s3_file_path(new_file_uuid)

                # encrypt the file to the temporarily file path
                await self.kms_encrypt_file(file_path, encrypted_file.path)

                # upload the encrypted file to S3
                with open(encrypted_file.path, "rb") as spfp:
                    await s3_client.upload_fileobj(spfp, self.aws_bucket, s3_key)

                return new_file_uuid

    async def exists(self, file_name: str) -> bool:
        raise NotImplementedError

    async def get_s3_file_path(self, file_uuid: uuid.UUID) -> str:
        return f"{self.assessment_id}/{file_uuid}.enc"

    async def create_data_key(self, key_spec="AES_256"):
        """Used to create a KMS data key."""

        async with aioboto3.Session().client(service_name="kms", **self._aws_client_args) as kms_client:
            kms_resp = await kms_client.generate_data_key(
                KeyId=self.cmk_id,
                KeySpec=key_spec,
            )
            return kms_resp["CiphertextBlob"], kms_resp["Plaintext"]

    async def kms_encrypt_file(self, input_file, output_file):
        """Used to encrypt a file via the appropriate KMS master key."""

        await logger.adebug("Encrypting", input_file=input_file, output_file=output_file)

        IV = urandom(self.block_size)

        # generate a new data key for this file, protected by the KMS key
        data_key_encrypted, data_key_plaintext = await self.create_data_key()

        cipher = AES.new(data_key_plaintext, AES.MODE_CBC, IV)
        finished = False

        with open(input_file, "rb") as in_file, open(output_file, "wb") as out_file:
            # write out the size of the data key
            out_file.write(len(data_key_encrypted).to_bytes(self.num_bytes_for_len, byteorder="big"))

            # write out the data key
            out_file.write(data_key_encrypted)

            # write out the IV (always 16 bytes)
            out_file.write(IV)

            # now encrypt and write out the data
            while not finished:
                chunk = in_file.read(8196 * self.block_size)
                if len(chunk) == 0 or len(chunk) % self.block_size != 0:
                    # final block/chunk is padded before encryption
                    padding_length = (self.block_size - len(chunk) % self.block_size) or self.block_size
                    chunk += str.encode(padding_length * chr(padding_length))
                    finished = True
                out_file.write(cipher.encrypt(chunk))

    async def kms_decrypt_file(self, input_file, output_file):
        """Used to decrypt a file via the appropriate KMS master key."""

        await logger.adebug("Decrypting file with KMS key", input_file=input_file, output_file=output_file)

        async with aioboto3.Session().client(service_name="kms", **self._aws_client_args) as kms_client:
            with open(input_file, "rb") as in_file, open(output_file, "wb") as out_file:
                # read the size of the data key
                data_key_encrypted_len = int.from_bytes(in_file.read(self.num_bytes_for_len), byteorder="big")

                # skip the data key length bytes
                in_file.seek(self.num_bytes_for_len)

                # ask kms to decrypt the data key for this file
                data_key_encrypted = in_file.read(data_key_encrypted_len)
                response = await kms_client.decrypt(CiphertextBlob=data_key_encrypted)
                data_key_plaintext = response["Plaintext"]

                # grab the IV
                IV = in_file.read(self.block_size)

                # skip to the actual encrypted data
                in_file.seek(self.num_bytes_for_len + data_key_encrypted_len + self.block_size)

                # decrypt everything
                cipher = AES.new(data_key_plaintext, AES.MODE_CBC, IV)
                next_chunk = b""
                finished = False

                while not finished:
                    chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(8196 * self.block_size))
                    if len(next_chunk) == 0:
                        padding_length = chunk[-1]
                        chunk = chunk[:-padding_length]
                        finished = True
                    out_file.write(chunk)

    async def __aenter__(self):
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        pass
