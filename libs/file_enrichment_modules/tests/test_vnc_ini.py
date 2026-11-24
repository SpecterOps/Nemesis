"""Tests for the VNC ini password decryptor (audit #106)."""

import textwrap

import pytest
from Crypto.Cipher import DES
from file_enrichment_modules.vnc_ini.analyzer import VNC_DES_KEY, VncParser

from tests.harness import FileEnrichedFactory, ModuleTestHarness

# Known vector: "password" obfuscated with the standard VNC key.
PASSWORD_HEX = "dbd83cfd727a1458"


def encrypt(password: str) -> str:
    block = password.encode("latin-1").ljust(8, b"\0")[:8]
    return DES.new(VNC_DES_KEY, DES.MODE_ECB).encrypt(block).hex()


@pytest.fixture
def parser():
    return VncParser.__new__(VncParser)  # no storage needed for the pure helpers


@pytest.fixture
def parser_with_key(parser):
    parser.des_key = VNC_DES_KEY
    return parser


def test_standard_key_decrypts_known_vector(parser_with_key):
    assert parser_with_key._decrypt_password(PASSWORD_HEX) == "password"


def test_ultravnc_nine_byte_value_uses_first_block(parser_with_key):
    # UltraVNC stores 18 hex digits; the ninth byte is not part of the DES block.
    assert parser_with_key._decrypt_password(PASSWORD_HEX + "7a") == "password"


def test_short_password_null_padding_stripped(parser_with_key):
    assert parser_with_key._decrypt_password(encrypt("abc")) == "abc"


@pytest.mark.parametrize("value", ["", "zz", "dbd83cfd", "   "])
def test_invalid_or_short_values_return_none(parser_with_key, value):
    assert parser_with_key._decrypt_password(value) is None


def test_all_zero_password_returns_none(parser_with_key):
    assert parser_with_key._decrypt_password(encrypt("")) is None


def test_non_ascii_does_not_crash(parser_with_key):
    assert parser_with_key._decrypt_password(encrypt("p\xe4ss")) == "p\xe4ss"


def test_parse_skips_comments(parser):
    config = parser._parse_vnc_config("; comment\n# comment\n[Server]\nPassword=abc\n")
    assert config == {"Server": {"Password": "abc"}}


def harness_for(content: str, file_name: str) -> tuple[ModuleTestHarness, str]:
    harness = ModuleTestHarness()
    data = content.encode()
    harness.register_file_bytes(
        object_id="vnc-ini",
        data=data,
        file_enriched=FileEnrichedFactory.create_plaintext_file(
            object_id="vnc-ini", file_name=file_name, size=len(data)
        ),
    )
    return harness, "vnc-ini"


async def run(content: str, file_name: str, tmp_path):
    path = tmp_path / file_name
    path.write_text(content)
    harness, object_id = harness_for(content, file_name)
    async with harness.create_module(VncParser) as module:
        should = await module.should_process(object_id, str(path))
        return should, await module.process(object_id, str(path))


@pytest.mark.asyncio
async def test_realvnc_server_password_finding(tmp_path):
    content = textwrap.dedent(f"""\
        [Server]
        Password={PASSWORD_HEX}
        Port=5900
        """)
    should, result = await run(content, "vnc.ini", tmp_path)
    assert should is True
    assert result is not None
    assert result.results["Server"]["DecryptedPassword"] == "password"
    assert len(result.findings) == 1
    assert result.findings[0].finding_name == "vnc_password_detected"
    assert "`password`" in result.findings[0].data[0].metadata["summary"]


@pytest.mark.asyncio
async def test_ultravnc_passwd_and_passwd2(tmp_path):
    content = textwrap.dedent(f"""\
        [ultravnc]
        passwd={PASSWORD_HEX}00
        passwd2={encrypt("viewonly")}00
        [admin]
        UseRegistry=0
        """)
    should, result = await run(content, "ultravnc.ini", tmp_path)
    assert should is True
    section = result.results["ultravnc"]
    assert section["DecryptedPasswd"] == "password"
    assert section["DecryptedPasswd2"] == "viewonly"
    assert len(result.findings) == 1
    summary = result.findings[0].data[0].metadata["summary"]
    assert "**Encrypted passwd**" in summary and "**DecryptedPasswd2**: `viewonly`" in summary


@pytest.mark.asyncio
async def test_section_and_key_case_insensitive(tmp_path):
    _, result = await run(f"[server]\npassword={PASSWORD_HEX}\n", "vnc.ini", tmp_path)
    assert result.results["server"]["DecryptedPassword"] == "password"
    assert len(result.findings) == 1


@pytest.mark.asyncio
async def test_no_password_no_finding(tmp_path):
    _, result = await run("[Server]\nPort=5900\n", "vnc.ini", tmp_path)
    assert result is not None
    assert not result.findings
    assert len(result.transforms) == 1


@pytest.mark.asyncio
async def test_bad_password_value_no_finding_no_crash(tmp_path):
    _, result = await run("[Server]\nPassword=not-hex\n", "vnc.ini", tmp_path)
    assert result is not None
    assert not result.findings
    assert "DecryptedPassword" not in result.results["Server"]


@pytest.mark.asyncio
async def test_should_not_process_non_vnc_ini(tmp_path):
    should, _ = await run("[Server]\nPassword=00\n", "settings.ini", tmp_path)
    assert should is False
