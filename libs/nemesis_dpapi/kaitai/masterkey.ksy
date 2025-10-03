meta:
  id: dpapi_masterkey
  title: DPAPI Master Key File
  endian: le
  ks-version: 0.9
doc: |
  Parser for Windows DPAPI master key files, based on the 010 Editor
  template "DPAPI-Masterkey.bt" by Jean-Michel Picod. Modified made
  Lee Chagolla-Christensen based on more recent analysis.
seq:
  - id: header
    type: masterkey_header
  # Master key blob (encrypted)
  - id: mkey
    type: mkey_blob
    if: header.cb_master_key > 0
    doc: >
      Total size of the file header, in bytes.
  # Backup key blob (encrypted)
  - id: backup_key
    type: backup_key_blob
    if: header.cb_backup_key > 0
  # Credential history reference
  - id: credhist
    type: credhist
    if: header.cb_credhist > 0
  # Domain key structure
  - id: domain_key
    type: domain_key
    if: header.cb_domain_key > 0
types:
  # ----------------------------
  # Common GUID (little-endian layout)
  # ----------------------------
  guid:
    seq:
      - id: data1      # 32-bit, little-endian
        type: u4le
      - id: data2      # 16-bit, little-endian
        type: u2le
      - id: data3      # 16-bit, little-endian
        type: u2le
      - id: data4      # 8 bytes, as-is
        size: 8
  # ----------------------------
  # MkeyHeader (32 bytes)
  # ----------------------------
  mkey_header:
    seq:
      - id: dw_revision
        type: u4
      - id: pb_iv
        size: 16
      - id: dw_rounds
        type: u4
      - id: id_hash
        type: u4
      - id: id_cipher
        type: u4
  # ----------------------------
  # Variable-length encrypted blob for master key
  # ----------------------------
  mkey_blob:
    seq:
      - id: hdr
        type: mkey_header
      - id: cipher
        size: _root.header.cb_master_key - 32  # mkey_header is 32 bytes
  # ----------------------------
  # Variable-length encrypted blob for backup key
  # ----------------------------
  backup_key_blob:
    seq:
      - id: hdr
        type: mkey_header
      - id: cipher
        size: _root.header.cb_backup_key - 32  # mkey_header is 32 bytes
  # ----------------------------
  # DomainKey (BACKUPKEY_RECOVERY_BLOB)
  # ----------------------------
  domain_key:
    seq:
      - id: dw_version
        type: u4
        doc: version of structure (BACKUPKEY_RECOVERY_BLOB_VERSION)
      - id: cb_encrypted_master_key
        type: u4
        doc: quantity of encrypted master key data following structure
      - id: cb_encrypted_payload
        type: u4
        doc: quantity of encrypted payload
      - id: guid_key
        type: guid
        doc: guid identifying backup key used
      - id: encrypted_master_key
        size: cb_encrypted_master_key
        doc: encrypted master key data
      - id: encrypted_payload
        size: cb_encrypted_payload
        doc: encrypted payload data
  # ----------------------------
  # Credhist (reference – compact version: revision + GUID)
  # ----------------------------
  credhist:
    seq:
      - id: dw_revision
        type: u4
      - id: g_cred
        type: guid
  # ----------------------------
  # MasterkeyHeader (MASTERKEY_STORED_ON_DISK)
  # ----------------------------
  masterkey_header:
    seq:
      - id: dw_revision
        type: u4
      - id: f_modified
        type: u4
      - id: sz_file_path
        type: u4
      - id: wsz_guid_master_key
        type: str
        size: 80
        encoding: UTF-16LE
      - id: dw_policy
        type: u4
      - id: cb_master_key
        type: u8
      - id: cb_backup_key
        type: u8
      - id: cb_credhist
        type: u8
      - id: cb_domain_key
        type: u8