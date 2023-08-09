# Standard Libraries
# Standard Libraries
import socket
from argparse import ArgumentError
from contextlib import closing

# 3rd Party Libraries
import structlog
import tenacity

logger = structlog.get_logger(module=__name__)


class SocketWaiter:
    NUM_ATTEMPTS: int = 60

    def __init__(self, host: str, port: int) -> None:
        if port < 1 or port > 65535:
            raise ArgumentError("Port is not in the range of 1-65535")

        self.port = port
        self.host = host

    def __retryLog(self, retry_state: tenacity.RetryCallState) -> None:
        logger.info(
            "Retrying connection",
            host=self.host,
            port=self.port,
            attempt=retry_state.attempt_number,
            max_attempts=self.NUM_ATTEMPTS,
            elapsed_time=retry_state.seconds_since_start,
        )

    def __check_socket(self):
        with closing(socket.create_connection((self.host, self.port), timeout=1)):
            pass

    def wait(self):

        r = tenacity.Retrying(
            before_sleep=self.__retryLog,
            # wait=tenacity.wait.wait_exponential(multiplier=1, min=1),
            wait=tenacity.wait.wait_fixed(5),
            stop=tenacity.stop_after_attempt(self.NUM_ATTEMPTS),
            reraise=True,
        )

        r(self.__check_socket)
