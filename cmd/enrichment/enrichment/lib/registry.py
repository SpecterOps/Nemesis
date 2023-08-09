# Standard Libraries
import base64
import re
from enum import Enum

# 3rd Party Libraries
import nemesiscommon.constants as constants
import nemesispb.nemesis_pb2 as pb
import structlog
from nemesiscommon import helpers
from Registry import Registry
from winacl.dtyp.ace import (ACCESS_ALLOWED_CALLBACK_ACE,
                             SYSTEM_MANDATORY_LABEL_ACE, ACEType)
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

logger = structlog.get_logger(module=__name__)


registry_path_regexes = [
    # # paths that contain service information
    re.compile(r"^hklm[:]?\\system\\(currentcontrolset|controlset001|controlset002)\\services\\", re.IGNORECASE),
    # System ENV variables
    re.compile(r"^hklm[:]?\\system\\(currentcontrolset|controlset001|controlset002)\\control\\session manager\\environment", re.IGNORECASE),
    # LSA settings
    re.compile(r"^hklm[:]?\\system\\(currentcontrolset|controlset001|controlset002)\\control\\lsa", re.IGNORECASE),
    # shutdown time/etc.
    re.compile(r"hklm[:]?\\system\\(currentcontrolset|controlset001|controlset002)\\control\\windows", re.IGNORECASE),
    # SecureBoot
    re.compile(r"^hklm[:]?\\system\\(currentcontrolset|controlset001|controlset002)\\control\\secureboot\\state", re.IGNORECASE),
    # paths for autologon information
    re.compile(r"^hklm[:]?\\software\\microsoft\\windows nt\\currentversion\\winlogon", re.IGNORECASE),
    # Network profiles
    re.compile(r"hklm[:]?\\software\\microsoft\\windows nt\\currentversion\\networklist\\profiles", re.IGNORECASE),
    # autoruns
    re.compile(r"^hklm[:]?\\software\\(wow6432node\\)*microsoft\\windows\\currentversion\\(run(once)*(service)*)", re.IGNORECASE),
    # UAC settings + registry audit policies
    re.compile(r"^hklm[:]?\\software\\microsoft\\windows\\currentversion\\policies\\system", re.IGNORECASE),
    # AppLocker
    re.compile(r"^hklm[:]?\\software\\policies\\microsoft\\windows\\srpv2", re.IGNORECASE),
    # .NET versions
    re.compile(r"^hklm[:]?\\software\\microsoft\\net framework setup\\ndp", re.IGNORECASE),
    # PowerShell versions
    re.compile(r"^hklm[:]?\\software\\microsoft\\powershell\\(1|3)\\powershellengine", re.IGNORECASE),
    # PowerShell core versions
    re.compile(r"^hklm[:]?\\software\\microsoft\\powershellcore\\installedversions", re.IGNORECASE),
    # PowerShell session settings
    re.compile(r"^hklm[:]?\\software\\microsoft\\windows\\currentversion\\wsman\\plugin", re.IGNORECASE),
    # RDP client settings
    re.compile(r"^hklm[:]?\\software\\policies\\microsoft\\windows\\credentialsdelegation", re.IGNORECASE),
    # RDP server settings
    re.compile(r"^hklm[:]?\\software\\policies\\microsoft\\windows nt\\terminal services", re.IGNORECASE),
    # Internet settings (proxy + zones)
    re.compile(r"^hklm[:]?\\software\\microsoft\\windows\\currentversion\\internet settings", re.IGNORECASE),
    # Windows Firewall settings
    re.compile(r"^hklm[:]?\\software\\policies\\microsoft\\windowsfirewall", re.IGNORECASE),
    re.compile(r"^hklm[:]?\\system\\currentcontrolset\\services\\sharedaccess\\parameters\\firewallpolicy", re.IGNORECASE),
    # Windows Defender settings
    re.compile(r"^hklm[:]?\\software\\(policies\\)*microsoft\\windows defender", re.IGNORECASE),
    # Eventlog forwarding
    re.compile(r"^hklm[:]?\\software\\policies\\microsoft\\windows\\eventlog\\eventforwarding\\subscriptionmanager", re.IGNORECASE),
    # WSUS information
    re.compile(r"^hklm[:]?\\software\\policies\\microsoft\\windows\\windowsupdate", re.IGNORECASE),
    # SCCM
    re.compile(r"^hklm[:]?\\software\\microsoft\\ccmsetup", re.IGNORECASE),
    re.compile(r"^hklm[:]?\\software\\microsoft\\sms\\mobile client", re.IGNORECASE),
    # LAPS
    re.compile(r"^hklm[:]?\\Software\\Policies\\Microsoft Services\\AdmPwd", re.IGNORECASE),
    # Installed software
    re.compile(r"^hklm[:]?\\software\\(wow6432node\\)*microsoft\\windows\\currentversion\\uninstall", re.IGNORECASE),

    # User RDP saved connections
    re.compile(r"^(?!hklm).+\\software\\microsoft\\terminal server client\\servers", re.IGNORECASE),
    # User Explorer MRUs
    re.compile(r"^(?!hklm).+\\software\\microsoft\\windows\\currentversion\\explorer\\runmru", re.IGNORECASE),
    # User Putty information
    re.compile(r"^(?!hklm).+\\software\\simontatham\\putty", re.IGNORECASE),
    # User onedrive info
    re.compile(r"^(?!hklm).+\\software\\syncengines\\providers\\onedrive", re.IGNORECASE),
    # Internet Explorer typed URLs
    re.compile(r"^(?!hklm).+\\software\\microsoft\\internet explorer\\typedurls", re.IGNORECASE),

    # TODO:
    #   Office MRUs https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Commands/Products/OfficeMRUsCommand.cs
]

registry_value_regexes = [
    # privesc check
    re.compile(r"^AlwaysInstallElevated$"),
    # OS information
    # re.compile(r"^(ProductName|EditionID|ReleaseId|BuildBranch|CurrentMajorVersionNumber|CurrentVersion|CurrentBuildNumber)$"),
]


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


# these are the value types that DPAPI data can be carved from
dpapi_check_values = {
    RegistryValueKindEnum.SZ.value: "",
    RegistryValueKindEnum.EXPAND_SZ.value: "",
    RegistryValueKindEnum.BINARY.value: "",
    RegistryValueKindEnum.MULTI_SZ.value: "",
}


async def get_hive_name(hive_path: str) -> str:
    """
    Takes a registry hive path on disk and tries to determine
    the hive name (e.g., HKLM\Security).
    """
    reg = Registry.Registry(hive_path)
    if reg.hive_type() == Registry.HiveType.BCD:
        return "HKLM\\BCD00000000"
    elif reg.hive_type() == Registry.HiveType.SAM:
        return "HKLM\\SAM"
    elif reg.hive_type() == Registry.HiveType.SECURITY:
        return "HKLM\\SECURITY"
    elif reg.hive_type() == Registry.HiveType.SYSTEM:
        return "HKLM\\SYSTEM"
    elif reg.hive_type() == Registry.HiveType.SOFTWARE:
        return "HKLM\\SOFTWARE"
    elif reg.hive_type() == Registry.HiveType.NTUSER:
        # if we have a HKU user hive, since there's not an established way to recover
        #   the user's SID for the mounting point, instead enumerate all of the ALLOW
        #   ACEs on the registry root and see if we can recover the user SID from there
        sk = reg.root()._nkrecord.sk_record()
        sd_size = sk.unpack_dword(16)
        sd = SECURITY_DESCRIPTOR.from_bytes(sk.unpack_binary(20, sd_size))
        sids = [f"{ace.Sid}" for ace in sd.Dacl.aces if ace.AceType == ACEType.ACCESS_ALLOWED_ACE_TYPE and re.match("S-1-5-21-.*", f"{ace.Sid}")]
        if len(sids) < 1:
            raise Exception("Can't derive a proper user SID from the DACL on the hive root")
        elif len(sids) > 2:
            raise Exception("Derived multiple user SIDs from the DACL on the hive root")
        else:
            return f"HKU\\{sids[0]}"
    elif reg.hive_type() == Registry.HiveType.UNKNOWN:
        hive_name_lower = reg.hive_name().lower()
        if hive_name_lower.endswith("system32\\config\\drivers"):
            return "HKLM\\DRIVERS"
        # TODO: hardware hive? others?
    else:
        raise Exception(f"Can't determine naming root for hive: {hive_path}")


async def registry_recurse(key: Registry.RegistryKey, hive_root: str = "", check_values: bool = False):
    """
    Recurses a RegistryKey start, replacing ROOT with the specified hive_root.

    If check_values is false, all keys are emitted as RegistryValueIngestion protobufs.

    If check_values is true, all keys run through include_registry_value and are emitted
    as RegistryValueIngestion protobufs if the check is true.
    """

    key_path = key.path()
    sddl = ""

    try:
        # get the security record for this key
        sk = key._nkrecord.sk_record()
        # get the size of the security descriptor
        sd_size = sk.unpack_dword(16)
        # read `sd_size` bytes at the sd offset and transform to a SDDL
        sddl = SECURITY_DESCRIPTOR.from_bytes(sk.unpack_binary(20, sd_size)).to_sddl()
    except AttributeError as e:
        if e.name == "to_sddl" and type(e.obj) == ACCESS_ALLOWED_CALLBACK_ACE:
            logger.warning(
                "Data loss due to bytes-to-SDDL conversion failing due to a known bug: there's an ACCESS_ALLOWED_CALLBACK_ACE in the security descriptor (see https://github.com/skelsec/winacl/issues/10)",
                key_path=key_path,
            )
        elif e.name == "to_sddl" and type(e.obj) == SYSTEM_MANDATORY_LABEL_ACE:
            logger.warning(
                "Data loss due to bytes-to-SDDL conversion failing due to a known bug: there's an SYSTEM_MANDATORY_LABEL_ACE in the security descriptor",
                key_path=key_path,
            )
        else:
            logger.exception(
                e,
                msg="Bytes to SDDL conversion failed",
                key_path=key_path,
            )
    except ValueError as e:
        if f"{e}" == "20 is not a valid ACEType":
            logger.warning(
                "Data loss due to bytes-to-SDDL conversion failing due to a known bug: there's an ACCESS_ALLOWED_CALLBACK_ACE in the security descriptor (see https://github.com/skelsec/winacl/issues/10)",
                key_path=key_path,
            )
        else:
            logger.exception(
                e,
                msf="Bytes to SDDL conversion failed",
                key_path=key_path,
            )

    if hive_root:
        key_path = key_path.replace("ROOT", hive_root)

    for value in key.values():
        try:
            value_name = value.name()
            value_type = value.value_type()
            if value_type == RegistryValueKindEnum.BINARY.value:
                # base64 encode binary data
                value_data = base64.b64encode(value.value()).decode("utf-8")
            else:
                value_data = value.value()

            # if we're not checking registry values (targeted value extraction) or
            #   we're checking all values (mass value extraction)
            tags = await include_registry_value(key_path, value_name, value_type, value_data)
            if not check_values or tags:
                reg_key = pb.RegistryValueIngestion()
                if hive_root:
                    reg_key.key = key_path.replace("ROOT", hive_root)
                else:
                    reg_key.key = key_path
                reg_key.value_name = value_name
                reg_key.value_kind = value_type
                reg_key.value = f"{value_data}"
                reg_key.sddl = sddl
                reg_key.tags = tags
                yield reg_key
        except:
            pass
    for subkey in key.subkeys():
        async for result in registry_recurse(subkey, hive_root, check_values):
            yield result


async def get_registry_values_from_hive(hive_path: str, scan_all_values: bool = True):
    """
    If scan_all_values is true, extract all values from the hive, checking
    each against include_registry_value(). This is more complete but less performant.

    Otherwise since hive files have a _lot_ of data that need to be parsed,
    we may want to manually extract the specific keys we want instead of extracting
    _everything_ and checking for inclusion after. This is less complete but more performant.

    """

    reg = Registry.Registry(hive_path)
    # grab the root of the hive
    hive_root = await get_hive_name(hive_path)

    if scan_all_values:
        # Mass value extraction/scanning.
        try:
            async for result in registry_recurse(reg.root(), hive_root, True):
                yield result
        except Exception as e:
            await logger.aexception(e)
    else:
        # Targeted value extraction.

        # Services
        try:
            select = reg.open("Select")
            current = select.value("Current").value()
            services = reg.open("ControlSet00%d\\Services" % (current))
            async for result in registry_recurse(services, hive_root):
                yield result
        except Exception as e:
            await logger.aexception(e)


async def include_registry_value(key: str = "", value_name: str = "", value_kind=None, value=None) -> str:
    """
    Returns a REG_TAG_X value if the key (and optional value name) should be emitted
    back into the queue. This functions as the central filtering logic
    for what registry keys to include in the backend model.
    """

    # check all of our path regexes
    if key:
        for registry_path_regex in registry_path_regexes:
            if registry_path_regex.search(key):
                return constants.REG_TAG_KEY

    # check all of the value regexes
    if value_name:
        for registry_value_regex in registry_value_regexes:
            if registry_value_regex.search(value_name):
                return constants.REG_TAG_VALUE

    if value and value_kind and value_kind in dpapi_check_values:
        # check specific value types for DPAPI blobs
        if type(value) == bytes:
            if await helpers.scan_for_dpapi_blob(value):
                return constants.REG_TAG_DPAPI
        elif type(value) == str:
            try:
                if await helpers.scan_for_dpapi_blob(value.encode("utf-8")):
                    return constants.REG_TAG_DPAPI
            except:
                try:
                    if await helpers.scan_for_dpapi_blob(value.encode("ascii")):
                        return constants.REG_TAG_DPAPI
                except:
                    pass

    return ""
