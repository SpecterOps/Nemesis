# Usage
```
docker build -t enrichments .

docker run --rm enrichments
```

# submit_to_nemesis
Usage:
```
poetry run python -m enrichment.cli.submit_to_nemesis [OPTIONS]
```

Example: Submit all files in a folder
```
poetry run python -m enrichment.cli.submit_to_nemesis --folder /code/ods/sample_files
```

Example: Submit multiple files with verbose logging
```
poetry run python -m enrichment.cli.submit_to_nemesis -f /etc/issue /etc/hosts --log_level DEBUG
```


# Yara

To post a file to the Yara endpoint, use:
```
curl -i -X POST --user 'nemesis:Password123!' -H "Content-Type: multipart/form-data" -F "file=@file.exe" http://127.0.0.1:8080/yara/file
```

# Acknowldegements
* AV product list was originally derived partially from https://github.com/kazimer/Aggressor-scripts-1/tree/master/Ps-highlight