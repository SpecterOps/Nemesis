meta:
  id: pvk_file
  title: Private Key (PVK) File Format
  file-extension: pvk
  endian: le

doc: |
  PVK (Private Key) file format used for storing cryptographic private keys.
  This format can store keys with optional password-based encryption using
  RC2-CBC or RC4 algorithms.

seq:
  - id: header
    type: file_hdr
  - id: pvk_data
    type: pvk_blob
    size: header.cb_pvk
    doc: Private key data (may be encrypted depending on header.encrypt_type)

types:
  file_hdr:
    doc: FILE_HDR structure describing the PVK file format
    seq:
      - id: magic
        type: u4
        doc: Magic number identifying PVK file format (0xb0b5f11e)
      - id: version
        type: u4
        doc: File version (should be 0 for PVK_FILE_VERSION_0)
      - id: key_spec
        type: u4
        enum: key_spec_enum
        doc: Key specification (AT_KEYEXCHANGE or AT_SIGNATURE)
      - id: encrypt_type
        type: u4
        enum: encrypt_type_enum
        doc: Encryption type used for the private key data
      - id: cb_encrypt_data
        type: u4
        doc: Size of encrypted data (should be max 4096 bytes)
      - id: cb_pvk
        type: u4
        doc: Size of private key data (should be 1-4096 bytes)

  pvk_blob:
    doc: PVK data containing blob header and key data
    seq:
      - id: blob_header
        type: publickeystruc
      - id: rsa_pubkey
        type: rsapubkey
        if: blob_header.ai_key_alg == alg_id_enum::calg_rsa_keyx or blob_header.ai_key_alg == alg_id_enum::calg_rsa_sign
      - id: rsa_key_data
        type: rsa_key_components
        if: blob_header.ai_key_alg == alg_id_enum::calg_rsa_keyx or blob_header.ai_key_alg == alg_id_enum::calg_rsa_sign
      - id: key_data_rem
        size-eos: true
        doc: Remaining key data for non-RSA keys

  publickeystruc:
    doc: BLOBHEADER / PUBLICKEYSTRUC structure
    seq:
      - id: b_type
        type: u1
        enum: blob_type_enum
        doc: Blob type (e.g., PUBLICKEYBLOB, PRIVATEKEYBLOB)
      - id: b_version
        type: u1
        doc: Version (should be 0x02 for CUR_BLOB_VERSION)
      - id: reserved
        type: u2
        doc: Reserved, should be 0
      - id: ai_key_alg
        type: u4
        enum: alg_id_enum
        doc: Algorithm ID for the key

  rsapubkey:
    doc: RSAPUBKEY structure for RSA keys
    seq:
      - id: magic
        type: u4
        doc: Magic number (RSA1 for public, RSA2 for private)
      - id: bitlen
        type: u4
        doc: Number of bits in the modulus
      - id: pubexp
        type: u4
        doc: Public exponent
    instances:
      is_private_key:
        value: magic == 0x32415352
        doc: True if magic is "RSA2" (private key)
      is_public_key:
        value: magic == 0x31415352
        doc: True if magic is "RSA1" (public key)
      modulus_bytes:
        value: bitlen / 8
        doc: Size of modulus in bytes
      half_modulus_bytes:
        value: bitlen / 16
        doc: Size of each prime in bytes

  rsa_key_components:
    doc: RSA key components following RSAPUBKEY
    seq:
      - id: modulus
        size: _parent.rsa_pubkey.modulus_bytes
        doc: RSA modulus (n = p * q)
      - id: prime1
        size: _parent.rsa_pubkey.half_modulus_bytes
        if: _parent.blob_header.b_type == blob_type_enum::privatekeyblob
        doc: First prime factor (p)
      - id: prime2
        size: _parent.rsa_pubkey.half_modulus_bytes
        if: _parent.blob_header.b_type == blob_type_enum::privatekeyblob
        doc: Second prime factor (q)
      - id: exponent1
        size: _parent.rsa_pubkey.half_modulus_bytes
        if: _parent.blob_header.b_type == blob_type_enum::privatekeyblob
        doc: d mod (p-1)
      - id: exponent2
        size: _parent.rsa_pubkey.half_modulus_bytes
        if: _parent.blob_header.b_type == blob_type_enum::privatekeyblob
        doc: d mod (q-1)
      - id: coefficient
        size: _parent.rsa_pubkey.half_modulus_bytes
        if: _parent.blob_header.b_type == blob_type_enum::privatekeyblob
        doc: (inverse of q) mod p
      - id: private_exponent
        size: _parent.rsa_pubkey.modulus_bytes
        if: _parent.blob_header.b_type == blob_type_enum::privatekeyblob
        doc: Private exponent (d)

enums:
  key_spec_enum:
    1: at_keyexchange
    2: at_signature

  encrypt_type_enum:
    0: no_encrypt
    1: rc4_password_encrypt
    2: rc2_cbc_password_encrypt

  blob_type_enum:
    0x01: simpleblob
    0x06: publickeyblob
    0x07: privatekeyblob
    0x08: plaintextkeyblob
    0x09: opaquekeyblob
    0x0a: publickeyblobex
    0x0b: symmetricwrapkeyblob
    0x0c: keystateblob

  alg_id_enum:
    0x6601: calg_des
    0x6602: calg_rc2
    0x6603: calg_3des
    0x6604: calg_desx
    0x6609: calg_3des_112
    0x660a: calg_skipjack
    0x660b: calg_tek
    0x660c: calg_cylink_mek
    0x660d: calg_rc5
    0x660e: calg_aes_128
    0x660f: calg_aes_192
    0x6610: calg_aes_256
    0x6611: calg_aes
    0x6801: calg_rc4
    0x6802: calg_seal
    0x8001: calg_md2
    0x8002: calg_md4
    0x8003: calg_md5
    0x8004: calg_sha
    0x8005: calg_mac
    0x8008: calg_ssl3_shamd5
    0x8009: calg_hmac
    0x800a: calg_tls1prf
    0x800b: calg_hash_replace_owf
    0x800c: calg_sha_256
    0x800d: calg_sha_384
    0x800e: calg_sha_512
    0x2000: calg_no_sign
    0x2200: calg_dss_sign
    0x2203: calg_ecdsa
    0x2400: calg_rsa_sign
    0xa001: calg_ecmqv
    0xa003: calg_hughes_md5
    0xa400: calg_rsa_keyx
    0xaa01: calg_dh_sf
    0xaa02: calg_dh_ephem
    0xaa03: calg_agreedkey_any
    0xaa04: calg_kea_keyx
    0xaa05: calg_ecdh
    0xae06: calg_ecdh_ephem
    0x4c01: calg_ssl3_master
    0x4c02: calg_schannel_master_hash
    0x4c03: calg_schannel_mac_key
    0x4c04: calg_pct1_master
    0x4c05: calg_ssl2_master
    0x4c06: calg_tls1_master
    0x4c07: calg_schannel_enc_key
    0xfffffffc: calg_oid_info_pq_t
    0xfffffffd: calg_oid_info_pq
    0xfffffffe: calg_oid_info_parameters
    0xffffffff: calg_oid_info_cng_only

instances:
  is_valid_magic:
    value: header.magic == 0xb0b5f11e
  is_valid_version:
    value: header.version == 0
  is_encrypted:
    value: header.encrypt_type != encrypt_type_enum::no_encrypt
  expected_file_size:
    value: 24 + header.cb_pvk
    doc: Expected total file size (24-byte header + pvk_data)
  actual_file_size:
    value: _io.size
    doc: Actual file size in bytes
  pvk_data_ends_at_eof:
    value: expected_file_size == actual_file_size
    doc: True if pvk_data extends exactly to end of file
  extra_bytes:
    value: actual_file_size - expected_file_size
    doc: Number of extra bytes after pvk_data (negative if file is truncated)