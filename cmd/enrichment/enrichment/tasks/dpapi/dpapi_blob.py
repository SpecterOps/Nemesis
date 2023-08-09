# Adapted from https://github.com/fortra/impacket/blob/8799a1a2c42ad74423841d21ed5f4193ea54f3d5/examples/dpapi.py
#   Apache License Version 1.1
#   Just contains DPAPI_BLOB
#   Modifications by @harmj0y: tweaked to allow SHA1 or full keys

# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2022 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   DPAPI and Windows Vault parsing structures and manipulation
#
# Author:
#   Alberto Solino (@agsolino)
#
# References:
#   All of the work done by these guys. I just adapted their work to my needs.
#   - https://www.passcape.com/index.php?section=docsys&cmd=details&id=28
#   - https://github.com/jordanbtucker/dpapick
#   - https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials (and everything else Ben did)
#   - http://blog.digital-forensics.it/2016/01/windows-revaulting.html
#   - https://www.passcape.com/windows_password_recovery_vault_explorer
#   -  https://www.passcape.com/windows_password_recovery_dpapi_master_key
#

# Standard Libraries
from binascii import hexlify, unhexlify
from datetime import datetime
from struct import pack, unpack

# 3rd Party Libraries
from Cryptodome.Cipher import AES, DES3
from Cryptodome.Hash import HMAC, SHA1, SHA512
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.Padding import unpad
from impacket.dcerpc.v5.enum import Enum
from impacket.structure import Structure
from impacket.uuid import bin_to_string

# Algorithm classes
ALG_CLASS_ANY = 0
ALG_CLASS_SIGNATURE = 1 << 13
ALG_CLASS_MSG_ENCRYPT = 2 << 13
ALG_CLASS_DATA_ENCRYPT = 3 << 13
ALG_CLASS_HASH = 4 << 13
ALG_CLASS_KEY_EXCHANGE = 5 << 13
ALG_CLASS_ALL = 7 << 13

# Algorithm types
ALG_TYPE_ANY = 0
ALG_TYPE_DSS = 1 << 9
ALG_TYPE_RSA = 2 << 9
ALG_TYPE_BLOCK = 3 << 9
ALG_TYPE_STREAM = 4 << 9
ALG_TYPE_DH = 5 << 9
ALG_TYPE_SECURECHANNEL = 6 << 9
ALG_SID_ANY = 0
ALG_SID_RSA_ANY = 0
ALG_SID_RSA_PKCS = 1
ALG_SID_RSA_MSATWORK = 2
ALG_SID_RSA_ENTRUST = 3
ALG_SID_RSA_PGP = 4
ALG_SID_DSS_ANY = 0
ALG_SID_DSS_PKCS = 1
ALG_SID_DSS_DMS = 2
ALG_SID_ECDSA = 3

# Block cipher sub ids
ALG_SID_DES = 1
ALG_SID_3DES = 3
ALG_SID_DESX = 4
ALG_SID_IDEA = 5
ALG_SID_CAST = 6
ALG_SID_SAFERSK64 = 7
ALG_SID_SAFERSK128 = 8
ALG_SID_3DES_112 = 9
ALG_SID_CYLINK_MEK = 12
ALG_SID_RC5 = 13
ALG_SID_AES_128 = 14
ALG_SID_AES_192 = 15
ALG_SID_AES_256 = 16
ALG_SID_AES = 17
ALG_SID_SKIPJACK = 10
ALG_SID_TEK = 11

CRYPT_MODE_CBCI = 6  # ANSI CBC Interleaved
CRYPT_MODE_CFBP = 7  # ANSI CFB Pipelined
CRYPT_MODE_OFBP = 8  # ANSI OFB Pipelined
CRYPT_MODE_CBCOFM = 9  # ANSI CBC + OF Masking
CRYPT_MODE_CBCOFMI = 10  # ANSI CBC + OFM Interleaved

ALG_SID_RC2 = 2
ALG_SID_RC4 = 1
ALG_SID_SEAL = 2

# Diffie - Hellman sub - ids
ALG_SID_DH_SANDF = 1
ALG_SID_DH_EPHEM = 2
ALG_SID_AGREED_KEY_ANY = 3
ALG_SID_KEA = 4
ALG_SID_ECDH = 5

# Hash sub ids
ALG_SID_MD2 = 1
ALG_SID_MD4 = 2
ALG_SID_MD5 = 3
ALG_SID_SHA = 4
ALG_SID_SHA1 = 4
ALG_SID_MAC = 5
ALG_SID_RIPEMD = 6
ALG_SID_RIPEMD160 = 7
ALG_SID_SSL3SHAMD5 = 8
ALG_SID_HMAC = 9
ALG_SID_TLS1PRF = 10
ALG_SID_HASH_REPLACE_OWF = 11
ALG_SID_SHA_256 = 12
ALG_SID_SHA_384 = 13
ALG_SID_SHA_512 = 14

# secure channel sub ids
ALG_SID_SSL3_MASTER = 1
ALG_SID_SCHANNEL_MASTER_HASH = 2
ALG_SID_SCHANNEL_MAC_KEY = 3
ALG_SID_PCT1_MASTER = 4
ALG_SID_SSL2_MASTER = 5
ALG_SID_TLS1_MASTER = 6
ALG_SID_SCHANNEL_ENC_KEY = 7
ALG_SID_ECMQV = 1


def getFlags(myenum, flags):
    return "|".join([name for name, member in myenum.__members__.items() if member.value & flags])


class FLAGS(Enum):
    CRYPTPROTECT_UI_FORBIDDEN = 0x1
    CRYPTPROTECT_LOCAL_MACHINE = 0x4
    CRYPTPROTECT_CRED_SYNC = 0x8
    CRYPTPROTECT_AUDIT = 0x10
    CRYPTPROTECT_VERIFY_PROTECTION = 0x40
    CRYPTPROTECT_CRED_REGENERATE = 0x80
    CRYPTPROTECT_SYSTEM = 0x20000000


# algorithm identifier definitions
class ALGORITHMS(Enum):
    CALG_MD2 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD2
    CALG_MD4 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD4
    CALG_MD5 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD5
    CALG_SHA = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA
    CALG_SHA1 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA1
    CALG_RSA_SIGN = ALG_CLASS_SIGNATURE | ALG_TYPE_RSA | ALG_SID_RSA_ANY
    CALG_DSS_SIGN = ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_DSS_ANY
    CALG_NO_SIGN = ALG_CLASS_SIGNATURE | ALG_TYPE_ANY | ALG_SID_ANY
    CALG_RSA_KEYX = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_RSA | ALG_SID_RSA_ANY
    CALG_DES = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_DES
    CALG_3DES_112 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_3DES_112
    CALG_3DES = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_3DES
    CALG_DESX = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_DESX
    CALG_RC2 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_RC2
    CALG_RC4 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_STREAM | ALG_SID_RC4
    CALG_SEAL = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_STREAM | ALG_SID_SEAL
    CALG_DH_SF = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_SANDF
    CALG_DH_EPHEM = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EPHEM
    CALG_AGREEDKEY_ANY = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_AGREED_KEY_ANY
    CALG_KEA_KEYX = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_KEA
    CALG_HUGHES_MD5 = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | ALG_SID_MD5
    CALG_SKIPJACK = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_SKIPJACK
    CALG_TEK = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_TEK
    CALG_SSL3_SHAMD5 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SSL3SHAMD5
    CALG_SSL3_MASTER = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SSL3_MASTER
    CALG_SCHANNEL_MASTER_HASH = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_MASTER_HASH
    CALG_SCHANNEL_MAC_KEY = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_MAC_KEY
    CALG_SCHANNEL_ENC_KEY = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_ENC_KEY
    CALG_PCT1_MASTER = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_PCT1_MASTER
    CALG_SSL2_MASTER = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SSL2_MASTER
    CALG_TLS1_MASTER = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_TLS1_MASTER
    CALG_RC5 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_RC5
    CALG_HMAC = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HMAC
    CALG_TLS1PRF = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1PRF
    CALG_HASH_REPLACE_OWF = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HASH_REPLACE_OWF
    CALG_AES_128 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_128
    CALG_AES_192 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_192
    CALG_AES_256 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_256
    CALG_AES = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES
    CALG_SHA_256 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256
    CALG_SHA_384 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_384
    CALG_SHA_512 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_512
    CALG_ECDH = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_ECDH
    CALG_ECMQV = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | ALG_SID_ECMQV
    CALG_ECDSA = ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_ECDSA


ALGORITHMS_DATA = {
    # Algorithm: key/SaltLen, CryptHashModule, Mode, IVLen, BlockSize
    ALGORITHMS.CALG_SHA.value: (160 // 8, SHA1, None, None, 512 // 8),
    ALGORITHMS.CALG_HMAC.value: (160 // 8, SHA512, None, None, 512 // 8),
    ALGORITHMS.CALG_3DES.value: (192 // 8, DES3, DES3.MODE_CBC, 64 // 8),
    ALGORITHMS.CALG_SHA_512.value: (128 // 8, SHA512, None, None, 1024 // 8),
    ALGORITHMS.CALG_AES_256.value: (256 // 8, AES, AES.MODE_CBC, 128 // 8),
}


class DPAPI_BLOB(Structure):
    structure = (
        ("Version", "<L=0"),
        ("GuidCredential", "16s=b" ""),
        ("MasterKeyVersion", "<L=0"),
        ("GuidMasterKey", "16s=b" ""),
        ("Flags", "<L=0"),
        ("DescriptionLen", "<L=0"),
        ("_Description", "_-Description", 'self["DescriptionLen"]'),
        ("Description", ":"),
        ("CryptAlgo", "<L=0"),
        ("CryptAlgoLen", "<L=0"),
        ("SaltLen", "<L=0"),
        ("_Salt", "_-Salt", 'self["SaltLen"]'),
        ("Salt", ":"),
        ("HMacKeyLen", "<L=0"),
        ("_HMacKey", "_-HMacKey", 'self["HMacKeyLen"]'),
        ("HMacKey", ":"),
        ("HashAlgo", "<L=0"),
        ("HashAlgoLen", "<L=0"),
        ("HMac", "<L=0"),
        ("_HMac", "_-HMac", 'self["HMac"]'),
        ("HMac", ":"),
        ("DataLen", "<L=0"),
        ("_Data", "_-Data", 'self["DataLen"]'),
        ("Data", ":"),
        ("SignLen", "<L=0"),
        ("_Sign", "_-Sign", 'self["SignLen"]'),
        ("Sign", ":"),
    )

    def dump(self):
        print("[BLOB]")
        print("Version          : %8x (%d)" % (self["Version"], self["Version"]))
        print("Guid Credential  : %s" % bin_to_string(self["GuidCredential"]))
        print("MasterKeyVersion : %8x (%d)" % (self["MasterKeyVersion"], self["MasterKeyVersion"]))
        print("Guid MasterKey   : %s" % bin_to_string(self["GuidMasterKey"]))
        print("Flags            : %8x (%s)" % (self["Flags"], getFlags(FLAGS, self["Flags"])))
        print("Description      : %s" % (self["Description"].decode("utf-16le")))
        print("CryptAlgo        : %.8x (%d) (%s)" % (self["CryptAlgo"], self["CryptAlgo"], ALGORITHMS(self["CryptAlgo"]).name))
        print("Salt             : %s" % (hexlify(self["Salt"])))
        print("HMacKey          : %s" % (hexlify(self["HMacKey"])))
        print("HashAlgo         : %.8x (%d) (%s)" % (self["HashAlgo"], self["HashAlgo"], ALGORITHMS(self["HashAlgo"]).name))
        print("HMac             : %s" % (hexlify(self["HMac"])))
        print("Data             : %s" % (hexlify(self["Data"])))
        print("Sign             : %s" % (hexlify(self["Sign"])))
        print()

    def deriveKey(self, sessionKey):
        def fixparity(deskey):
            # 3rd Party Libraries
            from six import b, indexbytes

            temp = b""
            for i in range(len(deskey)):
                t = (bin(indexbytes(deskey, i))[2:]).rjust(8, "0")
                if t[:7].count("1") % 2 == 0:
                    temp += b(chr(int(t[:7] + "1", 2)))
                else:
                    temp += b(chr(int(t[:7] + "0", 2)))
            return temp

        if len(sessionKey) > ALGORITHMS_DATA[self["HashAlgo"]][4]:
            derivedKey = HMAC.new(sessionKey, digestmod=ALGORITHMS_DATA[self["HashAlgo"]][1]).digest()
        else:
            derivedKey = sessionKey

        if len(derivedKey) < ALGORITHMS_DATA[self["CryptAlgo"]][0]:
            # Extend the key
            derivedKey += b"\x00" * ALGORITHMS_DATA[self["HashAlgo"]][4]
            ipad = bytearray([i ^ 0x36 for i in bytearray(derivedKey)][: ALGORITHMS_DATA[self["HashAlgo"]][4]])
            opad = bytearray([i ^ 0x5C for i in bytearray(derivedKey)][: ALGORITHMS_DATA[self["HashAlgo"]][4]])
            derivedKey = ALGORITHMS_DATA[self["HashAlgo"]][1].new(ipad).digest() + ALGORITHMS_DATA[self["HashAlgo"]][1].new(opad).digest()
            derivedKey = fixparity(derivedKey)

        return derivedKey

    def decrypt(self, key, entropy=None):
        if len(key) == 64:
            # full key passed, so calculate the SHA1 of it
            keyHash = SHA1.new(key).digest()
        elif len(key) == 20:
            # SHA1 passed, so just use that
            keyHash = key
        else:
            return None

        sessionKey = HMAC.new(keyHash, self["Salt"], ALGORITHMS_DATA[self["HashAlgo"]][1])
        if entropy is not None:
            sessionKey.update(entropy)

        sessionKey = sessionKey.digest()

        # Derive the key
        derivedKey = self.deriveKey(sessionKey)

        cipher = ALGORITHMS_DATA[self["CryptAlgo"]][1].new(derivedKey[: ALGORITHMS_DATA[self["CryptAlgo"]][0]], mode=ALGORITHMS_DATA[self["CryptAlgo"]][2], iv=b"\x00" * ALGORITHMS_DATA[self["CryptAlgo"]][3])
        cleartext = unpad(cipher.decrypt(self["Data"]), ALGORITHMS_DATA[self["CryptAlgo"]][1].block_size)

        # Now check the signature

        # ToDo Fix this, it's just ugly, more testing so we can remove one
        toSign = self.rawData[20:][: len(self.rawData) - 20 - len(self["Sign"]) - 4]

        # Calculate the different HMACKeys
        keyHash2 = keyHash + b"\x00" * ALGORITHMS_DATA[self["HashAlgo"]][1].block_size
        ipad = bytearray([i ^ 0x36 for i in bytearray(keyHash2)][: ALGORITHMS_DATA[self["HashAlgo"]][1].block_size])
        opad = bytearray([i ^ 0x5C for i in bytearray(keyHash2)][: ALGORITHMS_DATA[self["HashAlgo"]][1].block_size])
        a = ALGORITHMS_DATA[self["HashAlgo"]][1].new(ipad)
        a.update(self["HMac"])

        hmacCalculated1 = ALGORITHMS_DATA[self["HashAlgo"]][1].new(opad)
        hmacCalculated1.update(a.digest())

        if entropy is not None:
            hmacCalculated1.update(entropy)

        hmacCalculated1.update(toSign)

        hmacCalculated3 = HMAC.new(keyHash, self["HMac"], ALGORITHMS_DATA[self["HashAlgo"]][1])
        if entropy is not None:
            hmacCalculated3.update(entropy)

        hmacCalculated3.update(toSign)

        if hmacCalculated1.digest() == self["Sign"] or hmacCalculated3.digest() == self["Sign"]:
            return cleartext
        else:
            return None
