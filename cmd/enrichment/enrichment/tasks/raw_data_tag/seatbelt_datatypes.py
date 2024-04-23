# Standard Libraries
import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, List, Optional

# 3rd Party Libraries
import nemesispb.nemesis_pb2 as pb
from pydantic.types import UUID4


class SeatbeltDtoTypes(Enum):
    DIRECTORY_INFO = "Seatbelt.Commands.Windows.DirectoryInfoDTO"
    FILE_INFO = "Seatbelt.Commands.Windows.FileInfoDTO"
    OS_INFO = "Seatbelt.Commands.Windows.OSInfoDTO"
    REGISTRY_VALUE = "Seatbelt.Commands.Windows.RegistryValueDTO"
    SERVICE_INFO = "Seatbelt.Commands.Windows.ServicesDTO"
    SLACK_DOWNLOADS = "Seatbelt.Commands.SlackDownloadsCommand+SlackDownloadsDTO"
    SLACK_WORKSPACES = "Seatbelt.Commands.Products.SlackWorkspacesCommand+SlackWorkspacesDTO"
    NAMED_PIPE = "Seatbelt.Commands.Windows.NamedPipesDTO"
    TCP_CONNECTION = "Seatbelt.Commands.Windows.TcpConnectionsDTO"
    UDP_CONNECTION = "Seatbelt.Commands.Windows.UdpConnectionsDTO"


class RegistryValueKindEnum(Enum):
    NONE = 0
    SZ = 1
    EXPAND_SZ = 2
    BINARY = 3
    DWORD = 4
    DWORD_BIG_ENDIAN = 5
    LINK = 6
    MULTI_SZ = 7
    RESOURCE_LIST = 8
    FULL_RESOURCE_DESCRIPTOR = 9
    RESOURCE_REQUIREMENTS_LIST = 10
    QWORD = 11


# https://github.com/GhostPack/Seatbelt/blob/071ad593bc698635e6d637c0ff69cc102ff6eebc/Seatbelt/Commands/Windows/RegistryValueCommand.cs#L181-L196
@dataclass
class SeatbeltRegistryValue:
    Key: str
    ValueName: Optional[str] = None
    Value: Optional[Any] = None
    ValueKind: Optional[RegistryValueKindEnum] = None
    SDDL: Optional[str] = None

    @staticmethod
    def from_dict(json_dict: dict):
        if "Key" not in json_dict:
            raise ValueError("Invalid SeatbeltRegistryValue: missing 'Key' field")

        if "ValueKind" in json_dict:
            json_dict["ValueKind"] = RegistryValueKindEnum(json_dict["ValueKind"])
        return SeatbeltRegistryValue(
            json_dict["Key"],
            json_dict.get("ValueName"),
            json_dict.get("Value"),
            json_dict.get("ValueKind"),
            json_dict.get("SDDL"),
        )

    def to_protobuf(self) -> pb.RegistryValueIngestion:
        """Converts a SeatbeltRegistryValue object to a RegistryValueIngestionMessage protobuf object.
        In the process, it normalizes the registry data to conform to Nemesis' format.
        Namely, is converts ValueNames of "(default)" to "", and converts binary data to base64.

        Returns:
            RegistryValueIngestion: The converted RegistryValueIngestion protobuf
        """
        # normalize registry data to Nemesis format

        # Default values in Seatbelt have name of "(default)" where as Nemesis expects ""
        if self.ValueName == "(default)":
            self.ValueName = ""

        # Convert all values to a string
        if self.Value is not None:
            if self.ValueKind is None:
                raise ValueError("Cannot deserialize registry value since the ValueKind is unknown")

            if self.ValueKind == RegistryValueKindEnum.BINARY:
                b = bytes(self.Value)
                self.Value = base64.b64encode(b).decode("utf-8")
            else:
                self.Value = str(self.Value)

        # new_data = pb.RegistryValueIngestion(data.Key, self.ValueName, self.ValueKind, self.Value, self.SDDL)
        output = pb.RegistryValueIngestion()
        output.key = self.Key

        if self.ValueName is not None:
            output.value_name = self.ValueName

        if self.ValueKind is not None:
            output.value_kind = self.ValueKind.value

        if self.Value is not None:
            output.value = self.Value

        if self.SDDL is not None:
            output.sddl = self.SDDL

        return output


# TODO: DirectoryInfoDTO
# https://github.com/GhostPack/Seatbelt/blob/071ad593bc698635e6d637c0ff69cc102ff6eebc/Seatbelt/Commands/Misc/FileInfoCommand.cs#L176-L232
@dataclass
class SeatbeltFileInfo:
    FileName: str
    Comments: Optional[str] = None
    CompanyName: Optional[str] = None
    FileDescription: Optional[str] = None
    FileVersion: Optional[str] = None
    InternalName: Optional[str] = None
    IsDebug: Optional[bool] = None
    IsDotNet: Optional[bool] = None
    IsPatched: Optional[bool] = None
    IsPreRelease: Optional[bool] = None
    IsPrivateBuild: Optional[bool] = None
    IsSpecialBuild: Optional[bool] = None
    Language: Optional[str] = None
    LegalCopyright: Optional[str] = None
    LegalTrademarks: Optional[str] = None
    OriginalFilename: Optional[str] = None
    PrivateBuild: Optional[str] = None
    ProductName: Optional[str] = None
    ProductVersion: Optional[str] = None
    SpecialBuild: Optional[str] = None
    Attributes: Optional[str] = None
    CreationTimeUtc: Optional[datetime] = None
    LastAccessTimeUtc: Optional[datetime] = None
    LastWriteTimeUtc: Optional[datetime] = None
    Length: Optional[int] = None
    SDDL: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        i = cls(**data)
        if i.CreationTimeUtc:
            i.CreationTimeUtc = parse_seatbelt_date(str(i.CreationTimeUtc))
        if i.LastAccessTimeUtc:
            i.LastAccessTimeUtc = parse_seatbelt_date(str(i.LastAccessTimeUtc))
        if i.LastWriteTimeUtc:
            i.LastWriteTimeUtc = parse_seatbelt_date(str(i.LastWriteTimeUtc))
        return i

    def to_protobuf(self) -> pb.FileInformationIngestion:
        """Converts a SeatbeltFileInfo object to a FileInformationIngestion protobuf object.

        Returns:
            FileInformationIngestion: The converted FileInformationIngestion protobuf

        nemesis.filesystem_objects (agent_id, project_id, source, timestamp, expiration, path, name, extension, type, size, access_time, creation_time, modification_time, sddl)
        """

        output = pb.FileInformationIngestion()

        output.path = self.FileName
        output.type = "file"

        if self.Length:
            output.size = self.Length
        if self.CreationTimeUtc:
            output.creation_time.FromDatetime(self.CreationTimeUtc)
        if self.LastAccessTimeUtc:
            output.access_time.FromDatetime(self.LastAccessTimeUtc)
        if self.LastWriteTimeUtc:
            output.modification_time.FromDatetime(self.LastWriteTimeUtc)
        if self.SDDL:
            output.sddl = self.SDDL

        output.version_info = (
            f"OriginalFilename: {self.OriginalFilename}\nFileDescription: {self.FileDescription}ProductName: \n{self.ProductName}\n"
            f"Comments: {self.Comments}\nCompanyName: {self.CompanyName}\nFileName: {self.FileName}\nFileVersion: {self.FileVersion}\n"
            f"ProductVersion: {self.ProductVersion}\nIsDebug: {self.IsDebug}\nIsPatched: {self.IsPatched}\nIsPreRelease: {self.IsPreRelease}\n"
            f"IsPrivateBuild: {self.IsPrivateBuild}\nIsSpecialBuild: {self.IsSpecialBuild}\nLanguage: {self.Language}\nLegalCopyright: {self.LegalCopyright}\n"
            f"LegalTrademarks: {self.LegalTrademarks}\nPrivateBuild: {self.PrivateBuild}\nSpecialBuild: {self.SpecialBuild}"
        )

        return output


# https://github.com/GhostPack/Seatbelt/blob/071ad593bc698635e6d637c0ff69cc102ff6eebc/Seatbelt/Commands/Windows/ServicesCommand.cs#L245-L278
@dataclass
class SeatbeltService:
    Name: str
    DisplayName: str
    Description: Optional[str]
    User: Optional[str]
    State: Optional[str]
    StartMode: Optional[str]
    Type: Optional[str]
    ServiceCommand: Optional[str]
    BinaryPath: Optional[str]
    BinaryPathSDDL: Optional[str]
    ServiceDll: Optional[str]
    ServiceSDDL: Optional[str]
    CompanyName: Optional[str]
    FileDescription: Optional[str]
    Version: Optional[str]
    IsDotNet: Optional[str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        return cls(**data)

    def to_protobuf(self) -> pb.ServiceIngestion:
        """Converts a SeatbeltService object to a ServiceIngestion protobuf object.

        Returns:
            ServiceIngestion: The converted ServiceIngestion protobuf
        """

        output = pb.ServiceIngestion()

        output.name = self.Name
        output.display_name = self.DisplayName

        if self.Description:
            output.description = self.Description
        if self.User:
            output.start_name = self.User
        if self.State:
            output.state = self.State
        if self.StartMode:
            output.start_mode = self.StartMode
        if self.Type:
            if self.Type.lower() == "unknown" and re.match(".*_[a-zA-Z0-9_]{5}$", self.Name):
                output.type = "Per-user"
            else:
                output.type = self.Type
        if self.ServiceCommand:
            output.service_command = self.ServiceCommand
        if self.ServiceDll:
            output.service_dll = self.ServiceDll
        if self.ServiceDll:
            output.service_sddl = self.ServiceDll

        return output


@dataclass
class SeatbeltNamedPipe:
    Name: str
    ServerProcessName: Optional[str]
    ServerProcessPID: Optional[int]
    ServerProcessPath: Optional[str]
    Sddl: Optional[str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        # transform old named pipe format
        if "OwningProcessName" in data:
            data["ServerProcessName"] = data.pop("OwningProcessName")
        if "OwningProcessPID" in data:
            data["ServerProcessPID"] = data.pop("OwningProcessPID")
        if "ServerProcessPath" not in data:
            data["ServerProcessPath"] = ""
        return cls(**data)

    def to_protobuf(self) -> pb.NamedPipeIngestion:
        """Converts a SeatbeltNamedPipe object to a NamedPipeIngestion protobuf object.

        Returns:
            NamedPipeIngestion: The converted NamedPipeIngestion protobuf
        """

        output = pb.NamedPipeIngestion()

        output.name = self.Name

        if self.ServerProcessName and self.ServerProcessName != "Unk":
            output.server_process_name = self.ServerProcessName
        if self.ServerProcessPID:
            output.server_process_id = self.ServerProcessPID
        if self.ServerProcessPath:
            output.server_process_path = self.ServerProcessPath.replace("\\", "/")
        if self.Sddl and self.Sddl != "ERROR":
            output.sddl = self.Sddl

        return output


# ref - https://github.com/GhostPack/Seatbelt/blob/e97b184755d070493a83c3af70da9417e5fd806f/Seatbelt/Commands/Windows/TCPConnectionsCommand.cs#L121-L141
@dataclass
class SeatbeltTcpConnection:
    LocalAddress: str
    LocalPort: Optional[int]
    RemoteAddress: Optional[str]
    RemotePort: Optional[int]
    State: Optional[str]
    ProcessId: Optional[int]
    ProcessName: Optional[str]
    ProcessCommandLine: Optional[str]
    ServiceName: Optional[str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        # transform old format
        if "ProcessCommandLine" not in data and "Command" in data:
            data["ProcessCommandLine"] = data.pop("Command")
        if "ProcessName" not in data:
            data["ProcessName"] = ""
        if "ServiceName" not in data and "Service" in data:
            data["ServiceName"] = data.pop("Service")
        return cls(**data)

    def to_protobuf(self) -> pb.NetworkConnectionIngestion:
        """Converts a SeatbeltTcpConnection object to a NetworkConnectionIngestion protobuf object.

        Returns:
            NetworkConnectionIngestion: The converted NetworkConnectionIngestion protobuf
        """

        output = pb.NetworkConnectionIngestion()

        tcp_states = {
            1: "CLOSED",
            2: "LISTEN",
            3: "SYN_SENT",
            4: "SYN_RCVD",
            5: "ESTABLISHED",
            6: "FIN_WAIT1",
            7: "FIN_WAIT2",
            8: "CLOSE_WAIT",
            9: "CLOSING",
            10: "LAST_ACK",
            11: "TIME_WAIT",
            12: "UNKNOWN",
        }

        output.local_address = f"{self.LocalAddress}:{self.LocalPort}"
        output.remote_address = f"{self.RemoteAddress}:{self.RemotePort}"
        output.protocol = "tcp,ipv4"
        if self.State:
            if self.State in tcp_states:
                output.state = tcp_states[self.State]
            else:
                output.state = f"{self.State}"
        if self.ProcessId:
            output.process_id = self.ProcessId
        if self.ProcessName:
            output.process_name = self.ProcessName
        if self.ServiceName:
            output.service = self.ServiceName

        return output


# ref - https://github.com/GhostPack/Seatbelt/blob/e97b184755d070493a83c3af70da9417e5fd806f/Seatbelt/Commands/Windows/UDPConnectionsCommand.cs#L117-L132
@dataclass
class SeatbeltUdpConnection:
    LocalAddress: str
    LocalPort: Optional[int]
    ProcessId: Optional[int]
    ProcessName: Optional[str]
    ProcessCommandLine: Optional[str]
    ServiceName: Optional[str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        if "ProcessCommandLine" not in data and "ProcessName" in data:
            data["ProcessCommandLine"] = data.pop("ProcessName")
        if "ProcessName" not in data:
            data["ProcessName"] = ""
        if "ServiceName" not in data and "Service" in data:
            data["ServiceName"] = data.pop("Service")
        return cls(**data)

    def to_protobuf(self) -> pb.NetworkConnectionIngestion:
        """Converts a SeatbeltUdpConnection object to a NetworkConnectionIngestion protobuf object.

        Returns:
            NetworkConnectionIngestion: The converted NetworkConnectionIngestion protobuf
        """

        output = pb.NetworkConnectionIngestion()

        output.local_address = f"{self.LocalAddress}:{self.LocalPort}"
        output.protocol = "udp,ipv4"
        if self.ProcessId:
            output.process_id = self.ProcessId
        if self.ProcessName:
            output.process_name = self.ProcessName
        if self.ServiceName:
            output.service = self.ServiceName

        return output


# https://github.com/GhostPack/Seatbelt/blob/071ad593bc698635e6d637c0ff69cc102ff6eebc/Seatbelt/Commands/Windows/OSInfoCommand.cs#L180-L230
@dataclass
class SeatbeltOSInfo:
    Hostname: str
    Domain: Optional[str]
    Username: Optional[str]
    ProductName: Optional[str]
    EditionId: Optional[str]
    ReleaseId: Optional[int]
    Build: Optional[str]
    BuildBranch: Optional[str]
    CurrentMajorVersionNumber: Optional[Decimal]
    CurrentVersion: Optional[str]
    Architecture: Optional[str]
    ProcessorCount: Optional[int]
    IsVirtualMachine: Optional[bool]
    BootTimeUtc: Optional[str]
    IsHighIntegrity: Optional[bool]
    IsLocalAdmin: Optional[bool]
    CurrentTimeUtc: Optional[datetime]
    TimeZone: Optional[str]
    TimeZoneUtcOffset: Optional[str]
    Locale: Optional[str]
    InputLanguage: Optional[str]
    InstalledInputLanguages: Optional[List[str]]
    MachineGuid: Optional[UUID4]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        return cls(**data)


# https://github.com/GhostPack/Seatbelt/blob/071ad593bc698635e6d637c0ff69cc102ff6eebc/Seatbelt/Output/Sinks/JsonFileOutputSink.cs#L36-L40
@dataclass
class SeatbeltBaseDTO:
    Type: str
    Data: Any

    @classmethod
    def from_json(cls, json_data: str):
        data = json.loads(json_data)
        if not data.get("Type") or not data.get("Data"):
            raise ValueError("Invalid SeatbeltBaseDTO: missing 'Type' or 'Data' field")
        return cls(data["Type"], data["Data"])

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        if not data.get("Type") or not data.get("Data"):
            raise ValueError("Invalid SeatbeltBaseDTO: missing 'Type' or 'Data' field")
        return cls(data["Type"], data["Data"])


SEATBELT_DATE_START_TOKEN = "/Date("
SEATBELT_DATE_END_TOKEN = ")/"


def parse_seatbelt_date(date_string: str) -> datetime:
    """Parses a Seatbelt date string into a datetime object.

    Seatbelt's date format is in the form of '/Date(1651900411539)/' , which represent 5/7/2022 5:13:31 AM UTC.

    Args:
        date_string (str): The Seatbelt date string to parse.

    Raises:
        ValueError: If the date string is not in the format of '/Date(%d)/'.

    Returns:
        datetime: The parsed datetime object.
    """
    if not date_string.startswith(SEATBELT_DATE_START_TOKEN) or not date_string.endswith(SEATBELT_DATE_END_TOKEN):
        raise ValueError(
            f"Invalid Seatbelt date string. Expected a date in the format of '/Date(%d)/' but got '{date_string}'"
        )

    num = date_string[len(SEATBELT_DATE_START_TOKEN) : -(len(SEATBELT_DATE_END_TOKEN))]
    epoch = int(num) / 1000

    return datetime.fromtimestamp(epoch, tz=timezone.utc)
