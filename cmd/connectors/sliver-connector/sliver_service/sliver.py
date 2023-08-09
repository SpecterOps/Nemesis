# Heavily inspired/stolen from https://github.com/moloch--/sliver-py
from __future__ import annotations
import logging
import json
import os
from typing import AsyncGenerator, List, Union

import grpc

from sliver_service.pb.rpcpb.services_pb2_grpc import SliverRPCStub
from sliver_service.pb.clientpb import client_pb2
from sliver_service.pb.commonpb import common_pb2


KB = 1024
MB = 1024 * KB
GB = 1024 * MB
TIMEOUT = 60



class SliverClientConfig(object):
    """
    This class parses and represents Sliver operator configuration files, typically this class is automatically
    instantiated using one of the class methods :class:`SliverClientConfig.parse_config()` or :class:`SliverClientConfig.parse_config_file()` but can be directly
    instantiated too.

    :param operator: Operator name, note that this value is only used by the client and is ignored by the server.
    :param lhost: The listener host to connect to (i.e., the Sliver server host).
    :param lhost: The TCP port of the host listener (i.e., the TCP port of the Sliver "multiplayer" service).
    :param ca_certificate: The Sliver server certificate authority.
    :param certificate: The mTLS client certificate.
    :param private_key: The mTLS private key.
    :param token: The user's authentication token.

    :raises ValueError: A parameter contained an invalid value.
    """

    def __init__(
        self,
        operator: str,
        lhost: str,
        lport: int,
        ca_certificate: str,
        certificate: str,
        private_key: str,
        token: str,
    ):
        self.operator = operator
        self.lhost = lhost
        if not 0 < lport < 65535:
            raise ValueError("Invalid lport %d" % lport)
        self.lport = lport
        self.ca_certificate = ca_certificate
        self.certificate = certificate
        self.private_key = private_key
        self.token = token

    def __str__(self):
        return "%s@%s:%d" % (
            self.operator,
            self.lhost,
            self.lport,
        )

    def __repr__(self):
        return "<Operator: %s, Lhost: %s, Lport: %d, CA: %s, Cert: %s>" % (
            self.operator,
            self.lhost,
            self.lport,
            self.ca_certificate,
            self.certificate,
        )

    @classmethod
    def parse_config(cls, data: Union[str, bytes]) -> SliverClientConfig:
        """Parses the content of a Sliver operator configuration file and
        returns the instantiated :class:`SliverClientConfig`

        :param data: The Sliver operator configuration file content.
        :type data: Union[str, bytes]
        :return: An instantiated :class:`SliverClientConfig` object.
        :rtype: SliverClientConfig
        """
        return cls(**json.loads(data))

    @classmethod
    def parse_config_file(cls, filepath: os.PathLike[str]) -> SliverClientConfig:
        """Parse a given file path as a Sliver operator configuration file.

        :param filepath: File system path to an operator configuration file.
        :type filepath: str
        :return: An instantiated :class:`SliverClientConfig` object.
        :rtype: SliverClientConfig
        """
        with open(filepath, "r") as fp:
            data = fp.read()
        return cls.parse_config(data)


class BaseClient(object):

    # 2GB triggers an overflow error in the gRPC library so we do 2GB-1
    MAX_MESSAGE_LENGTH = (2 * GB) - 1

    KEEP_ALIVE_TIMEOUT = 10000
    CERT_COMMON_NAME = "multiplayer"

    def __init__(self, config: SliverClientConfig):
        self.config = config
        self._channel: grpc.aio.Channel = None  # type: ignore[assignment]
        self._stub: SliverRPCStub = None  # type: ignore[assignment]
        self._log = logging.getLogger(self.__class__.__name__)

    def is_connected(self) -> bool:
        return self._channel is not None

    @property
    def target(self) -> str:
        return "%s:%d" % (
            self.config.lhost,
            self.config.lport,
        )

    @property
    def credentials(self) -> grpc.ChannelCredentials:
        return grpc.composite_channel_credentials(
            grpc.ssl_channel_credentials(
                root_certificates=self.config.ca_certificate.encode(),
                private_key=self.config.private_key.encode(),
                certificate_chain=self.config.certificate.encode(),
            ),
            grpc.access_token_call_credentials(
                access_token=self.config.token,
            ),
        )

    @property
    def options(self):
        return [
            ("grpc.keepalive_timeout_ms", self.KEEP_ALIVE_TIMEOUT),
            ("grpc.ssl_target_name_override", self.CERT_COMMON_NAME),
            ("grpc.max_send_message_length", self.MAX_MESSAGE_LENGTH),
            ("grpc.max_receive_message_length", self.MAX_MESSAGE_LENGTH),
        ]


class SliverClient(BaseClient):

    """Asyncio client implementation"""

    beacon_event_types = ["beacon-registered"]
    session_event_types = ["session-connected", "session-disconnected"]
    job_event_types = ["job-started", "job-stopped"]
    canary_event_types = ["canary"]

    async def connect(self) -> client_pb2.Version:
        """Establish a connection to the Sliver server

        :return: Protobuf Version object, containing the server's version information
        :rtype: client_pb2.Version
        """
        self._channel = grpc.aio.secure_channel(
            target=self.target,
            credentials=self.credentials,
            options=self.options,
        )
        self._stub = SliverRPCStub(self._channel)
        return await self.version()

    async def version(self, timeout=TIMEOUT) -> client_pb2.Version:
        """Get server version information

        :param timeout: gRPC timeout, defaults to 60 seconds
        :type timeout: int, optional
        :return: Protobuf Version object
        :rtype: client_pb2.Version
        """
        return await self._stub.GetVersion(common_pb2.Empty(), timeout=timeout)

    async def loot_all(self) -> List[client_pb2.Loot]:
        """Get all loot

        :return: List of Protobuf Loot objects
        :rtype: List[client_pb2.Loot]
        """
        return (await self._stub.LootAll(common_pb2.Empty()))

    async def loot_content(self, loot: client_pb2.Loot) -> client_pb2.Loot:
        """Get loot content

        :param loot: Protobuf Loot object
        :type loot: client_pb2.Loot
        :return: Protobuf Loot object
        :rtype: client_pb2.Loot
        """
        return await self._stub.LootContent(loot)
    
    def events(self) -> AsyncGenerator[client_pb2.Event, None]:
        """Get events

        :return: AsyncGenerator of Protobuf Event objects
        :rtype: AsyncGenerator[client_pb2.Event, None]
        """
        return self._stub.Events(common_pb2.Empty())
