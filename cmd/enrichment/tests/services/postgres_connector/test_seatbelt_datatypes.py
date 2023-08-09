# Standard Libraries
import json

# 3rd Party Libraries
import pytest
from enrichment.tasks.raw_data_tag_service.seatbelt_datatypes import (
    SeatbeltFileInfo,
    SeatbeltOSInfo,
    parse_seatbelt_date,
)


@pytest.mark.asyncio
class TestSeatbeltOSInfo:
    fileinfoJson = r'{"Type":"Seatbelt.Commands.Windows.FileInfoDTO","Data":{"Comments":null,"CompanyName":null,"FileDescription":null,"FileName":"C:\\Windows\\win.ini","FileVersion":null,"InternalName":null,"IsDebug":false,"IsDotNet":false,"IsPatched":false,"IsPreRelease":false,"IsPrivateBuild":false,"IsSpecialBuild":false,"Language":null,"LegalCopyright":null,"LegalTrademarks":null,"OriginalFilename":null,"PrivateBuild":null,"ProductName":null,"ProductVersion":null,"SpecialBuild":null,"Attributes":32,"CreationTimeUtc":"\/Date(1651900411539)\/","LastAccessTimeUtc":"\/Date(1673040385781)\/","LastWriteTimeUtc":"\/Date(1651900356098)\/","Length":92,"SDDL":"O:SYD:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)(A;ID;0x1200a9;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)"}}'

    osinfoJson = r'{"Type":"Seatbelt.Commands.Windows.OSInfoDTO","Data":{"InputLanguage":"US","InstalledInputLanguages":["US"],"Hostname":"4182bc05-025c-40e3-a683-7f2c21fee4be","Domain":"","Username":"4182BC05-025C-4\\WDAGUtilityAccount","ProductName":"Windows 10 Enterprise","EditionId":"Enterprise","ReleaseId":"2009","Build":"22621.1105","BuildBranch":"ni_release","CurrentMajorVersionNumber":"10","CurrentVersion":"6.3","Architecture":"AMD64","ProcessorCount":"20","IsVirtualMachine":true,"BootTimeUtc":"\/Date(1677783926282)\/","IsHighIntegrity":true,"IsLocalAdmin":true,"CurrentTimeUtc":"\/Date(1677784078907)\/","TimeZone":"Pacific Standard Time","TimeZoneUtcOffset":"-08:00:00","Locale":"en-US","MachineGuid":"bf2687c7-7be3-421c-a83d-0571cc4dbfdd"}}'
    osinfoJsonWithOptionalInputLang = r'{"Type":"Seatbelt.Commands.Windows.OSInfoDTO","Data":{"InputLanguage":null,"InstalledInputLanguages":["US"],"Hostname":"4182bc05-025c-40e3-a683-7f2c21fee4be","Domain":"","Username":"4182BC05-025C-4\\WDAGUtilityAccount","ProductName":"Windows 10 Enterprise","EditionId":"Enterprise","ReleaseId":"2009","Build":"22621.1105","BuildBranch":"ni_release","CurrentMajorVersionNumber":"10","CurrentVersion":"6.3","Architecture":"AMD64","ProcessorCount":"20","IsVirtualMachine":true,"BootTimeUtc":"\/Date(1677783926282)\/","IsHighIntegrity":true,"IsLocalAdmin":true,"CurrentTimeUtc":"\/Date(1677784078907)\/","TimeZone":"Pacific Standard Time","TimeZoneUtcOffset":"-08:00:00","Locale":"en-US","MachineGuid":"bf2687c7-7be3-421c-a83d-0571cc4dbfdd"}}'
    osinfoJsonWithMissingRequiredHostname = r'{"Type":"Seatbelt.Commands.Windows.OSInfoDTO","Data":{"InputLanguage":"US","InstalledInputLanguages":null,"Domain":"","Username":"4182BC05-025C-4\\WDAGUtilityAccount","ProductName":"Windows 10 Enterprise","EditionId":"Enterprise","ReleaseId":"2009","Build":"22621.1105","BuildBranch":"ni_release","CurrentMajorVersionNumber":"10","CurrentVersion":"6.3","Architecture":"AMD64","ProcessorCount":"20","IsVirtualMachine":true,"BootTimeUtc":"\/Date(1677783926282)\/","IsHighIntegrity":true,"IsLocalAdmin":true,"CurrentTimeUtc":"\/Date(1677784078907)\/","TimeZone":"Pacific Standard Time","TimeZoneUtcOffset":"-08:00:00","Locale":"en-US","MachineGuid":"bf2687c7-7be3-421c-a83d-0571cc4dbfdd"}}'

    async def test_seatbeltFileInfo_from_json(self):
        d = json.loads(self.fileinfoJson)
        info = SeatbeltFileInfo.from_dict(d["Data"])

        assert info.FileName == "C:\\Windows\\win.ini"

    async def test_seatbeltOSInfo_from_json(self):
        d = json.loads(self.osinfoJson)
        osinfo = SeatbeltOSInfo.from_dict(d["Data"])

        assert osinfo.Hostname == "4182bc05-025c-40e3-a683-7f2c21fee4be"
        assert osinfo.Domain == ""
        assert osinfo.Username == "4182BC05-025C-4\\WDAGUtilityAccount"

    async def test_seatbeltOSInfo_from_json_with_optional_null(self):
        d = json.loads(self.osinfoJsonWithOptionalInputLang)
        osinfo = SeatbeltOSInfo.from_dict(d["Data"])

        assert osinfo.InputLanguage is None

    async def test_seatbeltOSInfo_from_json_with_missing_required_null(self):
        d = json.loads(self.osinfoJsonWithMissingRequiredHostname)

        with pytest.raises(Exception):
            SeatbeltOSInfo.from_dict(d["Data"])


@pytest.mark.asyncio
class TestSeatbeltDateParsing:
    async def test_parse_seatbelt_date(self):
        # Represents March 6, 2023 8:21:20.278 PM UTC
        datestr = "/Date(1678134080278)/"

        date = parse_seatbelt_date(datestr)

        assert date.year == 2023
        assert date.month == 3
        assert date.day == 6
        assert date.hour == 20
        assert date.minute == 21
        assert date.second == 20
        assert date.microsecond == 278000
        # assert date.tzinfo == datetime.timezone.utc
