# Authentication Data
Date type: `authentication_data`

## Overview
Data that may be used to authenticate to a resource. The resource does not need to be accessible over a network and a local resource may be specified using the `file://` scheme in the URI parameter. The type data may be anything that may be used to authenticate such as a password, certificate, JWT, SAML token, TGT, NTLM hash, private key, etc. The authentication data does not need to be additionally encoded because all ODR string parameters already support hex encoding values.

| Parameters            | Format      | Description                                                                           |
| --------------------- | ----------- | ------------------------------------------------------------------------------------- |
| data                  | string/UUID | Case sensitive data or a Nemesis UUID reference (if > 1024 bytes and is_file is True) |
| type                  | string      | Type of the auth data (defined below)                                                 |
| is_file               | bool        | True if data is a reference to a binary submission                                    |
| uri                   | string      | Location of where the data is valid                                                   |
| username              | string      | Simple or FQDN username if applicable                                                 |
| notes                 | string      | Any additional notes/context                                                          |
| originating_object_id | UUID        | The Nemesis UUID reference of the file the data was extracted from (if appliable)     |


### Supported Type values

Type values are not case-sensitive.

Any value can be submitted for the "type", however only the following values are formally supported:

| Name                   | Description                                                                    |
| ---------------------- | ------------------------------------------------------------------------------ |
| unknown                | unknown auth data type                                                         |
| password               | plaintext/decrypted password                                                   |
| dpapi_masterkey        | GUID:SHA1 of a user/machine DPAPI master key                                   |
| dpapi_system           | DPAPI_SYSTEM LSA secret                                                        |
| ntlm_hash              | Same as the RC4_HMAC_MD5 Kerberos key                                          |
| aes_128_key            | Kerberos - AES128_HMAC_SHA1 key                                                |
| aes_256_key            | Kerberos - AES256_HMAC_SHA1 key                                                |
| kerberos_ticket_kiribi | Kerberos .kirbi cred file - TGT or service ticket                              |
| kerberos_ticket_ccache | Kerberos .ccache cred file - TGT or service ticket                             |
| adcs_certificate       | Kerberos - AD CS certificate capable of authentication                         |
| saml_token             | Web - Security Assertion Markup Language (SAML) token                          |
| json_web_token         | Web - JSON Web Token (JWT)                                                     |
| api_key                | Web - key for a web API                                                        |
| private_key            | Misc - private key                                                             |
| misc                   | Misc auth data type                                                            |
| hash_ms_dcc            | Microsoft Cache/Domain Cached Credentials                                      |
| hash_krb_tgs_rep_23    | Kerberos 5, etype 23, TGS-REP (kerberoasting)                                  |
| hash_krb_as_rep_23     | Kerberos 5, etype 23, AS-REP (asrep-roasting)                                  |
| hash_krb_tgs_rep_17    | Kerberos 5, etype 17, TGS-REP (AES128-CTS-HMAC-SHA1-96) (AES128 kerberoasting) |
| hash_krb_tgs_rep_18    | Kerberos 5, etype 18, TGS-REP (AES256-CTS-HMAC-SHA1-96) (AES256 kerberoasting) |
| hash_krb_as_req_23     | Kerberos 5, etype 23, AS-REQ Pre-Auth                                          |
| hash_ms_office         | Extracted from MS Office documents with office2john                            |
| hash_zip               | Extracted from MS Office documents with zip2john                               |
| hash_pdf               | Extracted from pdf documents with pdf2john                                     |
| hash_apple_keychain    | Apple Keychain                                                                 |
| hash_crypt             | md5crypt/shacrypt/etc. from linux shadow files                                 |
| hash_mssql             | MSSQL hash formats                                                             |
| hash_cisco_ios         | Cisco-IOS (PBKDF2-SHA256/scrypt/etc.)                                          |


The `hash_<SUB_TYPE>` type values are meant for cracking, while other values are "plaintext".

## Protobuf Definition

**AuthenticationDataIngestionMessage** and **AuthenticationDataIngestion** in *nemesis.proto*

## Examples
```json
{
    "data": [
        ...
        {
            "uri": "ftp://192.168.10.10:8080",
            "username": "user",
            "type": "password",
            "is_file": false,
            "data": "pass1!",
            "notes": "found while working",
        },
        ...
    ]
    "metadata": {
        "agent_id": "339429212",
        "agent_type": "beacon",
        "automated": 1,
        "data_type": "authentication_data",
        "expiration": "2023-08-01T22:51:35",
        "source": "DC",
        "project": "ASSESS-X",
        "timestamp": "2022-08-01T22:51:35"
    }
}
```