## Adding Nosey Parker Rules

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