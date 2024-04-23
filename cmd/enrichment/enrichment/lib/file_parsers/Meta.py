# Standard Libraries
from abc import ABC, abstractmethod

# 3rd Party Libraries
# import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb


class FileType(ABC):
    def __new__(cls, *args, **kwargs):
        if cls is pb.FileDataEnriched:
            raise TypeError("TypeError: Can't instantiate abstract class %s directly".format())
        return object.__new__(cls)

    @abstractmethod
    def __init__(self, file: pb.FileDataEnriched):
        pass

    @abstractmethod
    def check_path(self) -> bool:
        """
        Returns True if the internal File path matches our target criteria.
        """
        pass

    @abstractmethod
    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria.
        """
        pass

    @abstractmethod
    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """
        pass
