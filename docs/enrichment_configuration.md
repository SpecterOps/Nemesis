# Configuration Enrichments

Several enrichments in Nemesis are configurable, and a few must be explicitly enabled due to the performance impact they impart. This document all current enrichment configuration optinos.


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

The Document Conversion service has several ENV variables variable that can be passed through from the environment launching Nemesis, or modified in [compose.yaml](https://github.com/SpecterOps/Nemesis/blob/main/compose.yaml):

| ENV Variable                  | Default Value | Description                                                     |
| ----------------------------- | ------------- | --------------------------------------------------------------- |
| `MAX_PARALLEL_WORKFLOWS`      | 5             | Maxmimum number of parallel conversion workflows allows         |
| `MAX_WORKFLOW_EXECUTION_TIME` | 300           | Maximum time (in seconds) workflows can run before being killed |
| `TIKA_OCR_LANGUAGES`          | eng           | Tika/Tesseract OCR languages supported.                         |

If you want to have additional language packs supported (see https://github.com/tesseract-ocr/tessdata for a full list), run something like this before launching Nemesis or set the value in your .env :

```bash
export TIKA_OCR_LANGUAGES="eng chi_sim chi_tra jpn rus deu spa"
```

## Nosey Parker

### ENV Variables

The Nosey Parker scanner service has several ENV variables variable that can be passed through from the environment launching Nemesis, or modified in [compose.yaml](https://github.com/SpecterOps/Nemesis/blob/main/compose.yaml):

| ENV Variable           | Default Value | Description                                                                     |
| ---------------------- | ------------- | ------------------------------------------------------------------------------- |
| `SNIPPET_LENGTH`       | 512           | Bytes of context length around Nosey Parker matches to pull in for findings     |
| `MAX_CONCURRENT_FILES` | 2             | Maximum number of concurrent files to scan (raising increases resources needed) |
| `MAX_FILE_SIZE_MB`     | 200           | Maximum file size to scan (in megabytes)                                        |
| `DECOMPRESS_ZIPS`      | true          | Whether to decompress+scan zips                                                 |
| `MAX_EXTRACT_SIZE_MB`  | 1000          | Maximum number of megabytes to extract from ZIPs (if decompressing)             |

### Custom Rules

Nemesis uses [Nosey Parker](https://github.com/praetorian-inc/noseyparker) wrapped through [an customized Dapr pub/sub scanner implementation](https://github.com/SpecterOps/Nemesis/tree/main/projects/noseyparker_scanner).

There are a number of custom rules that are specified at [projects/noseyparker_scanner/custom_rules/rules.yaml](https://github.com/SpecterOps/Nemesis/tree/main/projects/noseyparker_scanner/custom_rules/rules.yaml).

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

If you want to add additional rules, just modify [rules.yaml](https://github.com/SpecterOps/Nemesis/tree/main/projects/noseyparker_scanner/custom_rules/rules.yaml) with the new rule (or add a new rules.yaml) and restart the noseyparker-scanner container.


## .NET Service

### ENV Variables

| ENV Variable                | Default Value | Description                                   |
| --------------------------- | ------------- | --------------------------------------------- |
| `MAX_CONCURRENT_PROCESSING` | 5             | Maximum number of concurrent files to process |