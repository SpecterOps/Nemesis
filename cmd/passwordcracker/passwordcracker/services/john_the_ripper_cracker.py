# Standard Libraries
import subprocess
from abc import abstractmethod
from tempfile import NamedTemporaryFile
from typing import Optional

# 3rd Party Libraries
import structlog

logger = structlog.get_logger(module=__name__)


class PasswordCrackerInterface:
    @abstractmethod
    async def crack(self, hash: str, wordlist_file_path: str, format: Optional[str] = None) -> Optional[str]:
        pass


class JohnTheRipperCracker(PasswordCrackerInterface):
    temp_dir: str

    def __init__(self, temp_dir: str) -> None:
        self.temp_dir = temp_dir

    async def crack(self, hash: str, wordlist_file_path: str, format: Optional[str] = None) -> Optional[str]:
        if not hash:
            raise Exception("input hash to john cannot be empty")

        with (
            NamedTemporaryFile(dir=self.temp_dir, prefix="jtr_hash") as hash_file,
            NamedTemporaryFile(dir=self.temp_dir, prefix="jtr_pot") as pot_file,
        ):
            # write out the hash to a temporary file for JTR to process it
            with open(hash_file.name, "w") as f:
                f.write(hash)

            logger.info("Cracking hash with JohnTheRipper", format=format)

            if format:
                # TODO: convert this to using asyncio's subprocess functions
                result = subprocess.run(
                    [
                        "/john/run/john",
                        f"--format={format}",
                        f"--wordlist={wordlist_file_path}",
                        "--no-log",
                        f"--pot={pot_file.name}",
                        f"{hash_file.name}",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            else:
                result = subprocess.run(
                    [
                        "/john/run/john",
                        f"--wordlist={wordlist_file_path}",
                        "--no-log",
                        f"--pot={pot_file.name}",
                        f"{hash_file.name}",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

            return await self.get_password_from_result(result, pot_file.name)

    async def get_password_from_result(self, result: subprocess.CompletedProcess, pot_file_path: str) -> Optional[str]:
        # Check if the cracking finished successfully
        if "Session completed" not in str(result.stderr):
            logger.error("JohnTheRipper did not run successfully", stdout=result.stdout, stderr=result.stderr)
            return None

        # try to read in the temporary .pot file that contains any results
        with open(pot_file_path, "r") as f:
            pot_contents = f.read()

        return await self.parse_pot_file(pot_contents)

    async def parse_pot_file(self, pot_contents: str) -> Optional[str]:
        # We expect the pot file to end with a newline (successful run) or to be emtpy (no results)
        # If neither of those are true, then something went wrong
        if pot_contents == "":
            logger.debug("No results from JohnTheRipper")
            return None
        elif pot_contents.endswith("\n"):
            pot_contents = pot_contents[:-1]
            logger.debug("JohnTheRipper successfully cracked a hash!")
        else:
            raise Exception("pot file does not end with a newline")

        password = pot_contents.split(":")[-1]
        return password
