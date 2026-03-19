# Enrichment Configuration

Several file enricment modules in Nemesis are configurable, and a few must be explicitly enabled due to the performance impact they impart. This document details all current enrichment configuration options.


## PII Detection

The [PII file enrichment module](https://github.com/SpecterOps/Nemesis/blob/main/libs/file_enrichment_modules/file_enrichment_modules/pii/analyzer.py) uses [Microsoft Presidio](https://github.com/microsoft/presidio) for PII detection across all scanned plaintext. Since this uses an English [spaCy machine learning model](https://spacy.io/models/en#en_core_web_lg), it is a performance hit, so PII scanning is disabled by default.

To enable PII scanning, run the following, uncomment the same value in the [compose.yaml](https://github.com/SpecterOps/Nemesis/blob/main/compose.yaml), or set the value in your .env :

```bash
export ENABLE_PII_DETECTION=true
```

The model takes into account context around a match, and emits a confidence score of 0.0-1.0. The default threshold is set to 0.7. To change this score, run the following, uncomment the same value in the [compose.yaml](https://github.com/SpecterOps/Nemesis/blob/main/compose.yaml), or set the value in your .env :

```bash
export PII_DETECTION_THRESHOLD=0.5
```

A higher score will return fewer false positives at the risk of increased false negatives.

Currently the PII module detects the following entity types: `CREDIT_CARD`, `US_SSN`, `UK_NINO`. To add or remove PII entity types (defined at https://microsoft.github.io/presidio/supported_entities/), modify the `PII_ENTITY_CONFIG` at the top of the [PII file enrichment module](https://github.com/SpecterOps/Nemesis/blob/main/libs/file_enrichment_modules/file_enrichment_modules/pii/analyzer.py).


## Document Conversion

### ENV Variables

The [Document Conversion service](https://github.com/SpecterOps/Nemesis/tree/main/projects/document_conversion) has several ENV variables variable that can be passed through from the environment launching Nemesis, or modified in [compose.yaml](https://github.com/SpecterOps/Nemesis/blob/main/compose.yaml):

| ENV Variable                                | Default Value | Description                                                     |
|---------------------------------------------|---------------|-----------------------------------------------------------------|
| `DOCUMENTCONVERSION_MAX_PARALLEL_WORKFLOWS` | 5             | Maxmimum number of parallel conversion workflows allows         |
| `MAX_WORKFLOW_EXECUTION_TIME`               | 300           | Maximum time (in seconds) workflows can run before being killed |
| `TIKA_USE_OCR`                              | false         | Set to `true` to enable OCR support via Tessaract               |
| `TIKA_OCR_LANGUAGES`                        | eng           | Tika/Tesseract OCR languages supported.                         |

If you want to have additional language packs supported (see https://github.com/tesseract-ocr/tessdata for a full list), run something like this before launching Nemesis or set the value in your `.env` file:

```bash
export TIKA_OCR_LANGUAGES="eng chi_sim chi_tra jpn rus deu spa"
```

**NOTE:** due to Docker's ENV variable substitution, setting `TIKA_USE_OCR=false` will be interpreted as true - either removing `TIKA_USE_OCR` from an .env file or setting `TIKA_USE_OCR=""` will disable OCR (the default). Enabling OCR significantly increases CPU as it will OCR standalone images as well as all images embedded in documents.

## Titus

### ENV Variables

The [Titus scanner service](https://github.com/SpecterOps/Nemesis/tree/main/projects/titus_scanner) has several ENV variables variable that can be passed through from the environment launching Nemesis, or modified in [compose.yaml](https://github.com/SpecterOps/Nemesis/blob/main/compose.yaml):

| ENV Variable               | Default Value | Description                                                                          |
|----------------------------|---------------|--------------------------------------------------------------------------------------|
| `SNIPPET_LENGTH`           | 512           | Bytes of context length around Titus matches to pull in for findings                 |
| `MAX_CONCURRENT_FILES`     | 2             | Maximum number of concurrent files to scan (raising increases resources needed)      |
| `MAX_FILE_SIZE_MB`         | 200           | Maximum file size to scan (in megabytes)                                             |
| `EXTRACT_ARCHIVES`         | true          | Extract+scan archive contents (zip, jar, war, ear, apk, tar, tar.gz, 7z)            |
| `EXTRACT_MAX_FILE_SIZE_MB` | 10            | Maximum per-file size within archives (in megabytes)                                 |
| `EXTRACT_MAX_TOTAL_SIZE_MB`| 1000          | Total extraction budget per archive (in megabytes)                                   |
| `EXTRACT_MAX_DEPTH`        | 2             | Maximum nesting depth for recursive archives                                         |
| `ENABLE_VALIDATION`        | false         | Whether to enable credential validation                                              |
| `VALIDATION_WORKERS`       | 4             | Concurrent validation workers (only used when validation enabled)                    |
| `DISABLED_RULES`           | (none)        | Comma-separated Titus rule IDs to exclude (e.g. `np.linkedin.3,np.generic.1`)        |

**Supported archive formats:** `.zip`, `.jar`, `.war`, `.ear`, `.apk`, `.ipa`, `.xpi`, `.crx`, `.tar`, `.tar.gz`/`.tgz`, `.7z`. Document formats (xlsx, docx, pdf, etc.) are intentionally excluded — Nemesis handles those via the document_conversion service.

### Custom Rules

Nemesis uses [Titus](https://github.com/praetorian-inc/titus) wrapped through [a customized Dapr pub/sub scanner implementation](https://github.com/SpecterOps/Nemesis/tree/main/projects/titus_scanner).

There are a number of custom rules that are specified at [projects/titus_scanner/custom_rules/rules.yaml](https://github.com/SpecterOps/Nemesis/tree/main/projects/titus_scanner/custom_rules/rules.yaml).

```yaml
rules:
  - name: sha256crypt Hash
    id: custom.sha256crypt
    pattern: '(\$5\$(?:rounds=\d+\$)?[\./A-Za-z0-9]{1,16}\$(?:(?:[\./A-Za-z0-9]{43})))'
    references:
      - https://akkadia.org/drepper/SHA-crypt.txt
      - https://hashcat.net/wiki/doku.php?id=example_hashes
    examples:
      - '$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD'
      - '$5$B7RCoZun804NXFH3$PltCS6kymC/bJTQ21oQOMCLlItYP9uXvEaCV89jl5iB'
      - '$5$JzPB.C/yL0uBMMIK$/2Jr.LeQUg0Sgbm8UhF01d1X643/YHdmRzwlVmt3ut3'
      - '$5$rounds=80000$wnsT7Yr92oJoP28r$cKhJImk5mfuSKV9b3mumNzlbstFUplKtQXXMo4G6Ep5'
      - '$5$rounds=12345$q3hvJE5mn5jKRsW.$BbbYTFiaImz9rTy03GGi.Jf9YY5bmxN0LU3p3uI1iUB'

  - name: sha512crypt Hash
    id: custom.sha512crypt
    pattern: '(\$6\$(?:rounds=\d+\$)?[\./A-Za-z0-9]{1,16}\$(?:(?:[\./A-Za-z0-9]{43})))'
    references:
      - https://akkadia.org/drepper/SHA-crypt.txt
      - https://hashcat.net/wiki/doku.php?id=example_hashes
    examples:
      - '$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/'
      - '$6$Blzt0pLMHZqPNTwR$jR4F0zo6hXipl/0Xs8do1YWRpr47mGcH49l.NCsJ6hH0VQdORfUP1K1HYar1a5XgH1/JFyTGnyrTPmKJBIoLx.'

...
```

If you want to add additional rules, just modify [rules.yaml](https://github.com/SpecterOps/Nemesis/tree/main/projects/titus_scanner/custom_rules/rules.yaml) with the new rule (or add a new rules.yaml) and restart the titus-scanner container.

### Secret Validation

Titus supports live validation of detected secrets against their source APIs (e.g., checking if an AWS key is active via STS, testing a GitHub token, etc.). This is **opt-in** and disabled by default because validation makes outbound network calls to third-party services.

To enable secret validation:

```bash
export ENABLE_VALIDATION=true
```

When enabled, each detected secret is validated and assigned one of three outcomes:

| Status | Label | Description |
|---|---|---|
| `valid` | CONFIRMED ACTIVE | The secret was verified as active against the target service |
| `invalid` | INACTIVE | The secret was tested and confirmed to be expired or revoked |
| `undetermined` | UNVERIFIED | Validation could not determine the secret's status |

Confirmed active secrets are escalated to severity 9 (from the default 7), while inactive secrets have their severity reduced. The `VALIDATION_WORKERS` variable controls the number of concurrent validation goroutines (default: 4).

Titus supports validation for 100+ secret types, including: AWS access keys, GitHub tokens, GitLab tokens, Slack tokens, Stripe API keys, PostgreSQL connection strings, Twilio credentials, SendGrid API keys, and many more. See the [Titus documentation](https://github.com/praetorian-inc/titus) for the full list.


## .NET Service

The [.NET scanning service](https://github.com/SpecterOps/Nemesis/tree/main/projects/dotnet_service) has a single ENV variable to configure.

### ENV Variables

| ENV Variable                | Default Value | Description                                   |
| --------------------------- | ------------- | --------------------------------------------- |
| `MAX_CONCURRENT_PROCESSING` | 5             | Maximum number of concurrent files to process |