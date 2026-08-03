# Troubleshooting

## Database Connection Issues

The most common issue is using wrong connection parameters. Use these exact values:

```bash
# Correct connection command
docker exec nemesis-postgres-1 psql -U nemesis -d enrichment -c "YOUR_QUERY"

# Common mistakes:
# - Using $(docker compose ps -q postgres) instead of nemesis-postgres-1
# - Using -d nemesis instead of -d enrichment
# - Using -U postgres instead of -U nemesis
```

To list available databases:
```bash
docker exec nemesis-postgres-1 psql -U nemesis -l
```

To check table schemas:
```bash
docker exec nemesis-postgres-1 psql -U nemesis -d enrichment -c "\d enrichments"
docker exec nemesis-postgres-1 psql -U nemesis -d enrichment -c "\d findings"
```

## Module Not Loading

1. Check for syntax errors in analyzer.py
2. Verify `create_enrichment_module()` function exists
3. Check container logs for import errors

## Detection Not Working

1. Verify file_enriched fields match expectations
2. Test YARA rules separately with yara-x
3. Add debug logging to should_process()

## Parsing Errors

1. Check library compatibility with file format variant
2. Add defensive error handling
3. Test with multiple sample files

## Tests Failing

1. Verify test file path is correct
2. Check FileEnrichedFactory fields match module expectations
3. Ensure harness is properly registering files
