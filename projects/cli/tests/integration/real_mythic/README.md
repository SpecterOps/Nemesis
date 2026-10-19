# Real Mythic fault reproduction

These opt-in tests use Mythic's Go server, its complete Hasura metadata, real
PostgreSQL and RabbitMQ, the installed Mythic Python SDK, and the CLI connector.
They do not require Nemesis or an agent/payload installation. File fixtures are
inserted into this isolated database and written to the server's isolated file
storage; completion and deletion are changed directly in PostgreSQL.

The tested source revision is `96b24b48a7f26594f1126eabef8ad00301ba28a0`
(Mythic 3.4.36), with Hasura 2.48.15 and SDK 0.2.10.

Run from `projects/cli`, with Docker access:

```bash
uv run --no-sync python tests/integration/real_mythic/setup.py ~/code/Mythic
# Once the server has initialized (Step 6/6 appears in its logs):
docker logs nemesis-real-mythic-server-1
uv run --no-sync python tests/integration/real_mythic/setup.py ~/code/Mythic --metadata-only
NEMESIS_REAL_MYTHIC_DIR=/tmp/nemesis-real-mythic \
  uv run --no-sync pytest tests/integration/test_mythic_live.py -q
```

The setup copies source into `/tmp/nemesis-real-mythic`, excluding `.env*` files,
and disables Mythic's automatic config-file loading in that copy. All test
configuration comes from explicit container environment variables. No other
Mythic source behavior is changed. The source checkout remains untouched. The
script imports both `actions.yaml` and `actions.graphql` into Hasura, reproducing
the CLI's schema conversion without its configuration loader.

Only loopback ports 18443 (Mythic HTTP/GraphQL) and 18081 (Hasura) are exposed.
The Docker Compose project is `nemesis-real-mythic`; use it only for these tests.
Its operator password and Hasura admin secret are public test values in the
Compose file. Tests restart this project's Hasura container and mutate only its
fixture records and test API token. Ordinary test runs skip the live suite.

The 11 scenarios confirm:

- The old complete-filtered ID stream misses an older file completing late.
- The fixed connector discovers and later processes that file.
- The SDK accepts an unknown-file 404 as file bytes; the connector rejects it
  before its upload callback runs.
- Invalid API tokens pass SDK login but fail the connector's GraphQL probe.
- Incorrect passwords fail authentication.
- Pending files marked deleted are retired without a successful-upload marker.
- A Hasura stop/start triggers reconnection and pending-file recovery.
- Revoked tokens fail subsequent GraphQL queries.
- A real Mythic download survives a Nemesis HTTP 503 upload failure and uploads
  the expected bytes after recovery (the Nemesis receiver is a local surrogate).
- A legitimate empty file is accepted.
- The actual CLI downloads and previews a real Mythic file with `--dry-run`, no
  Nemesis listener, and no configured persistent database created.

The cursor regression observes three Hasura polling intervals after completing
the older row. This verifies the missed-row behavior for that controlled case;
it is not an endurance or load test. Agent chunk transport, TLS/proxy failures,
full Nemesis processing, and all Mythic versions are outside this suite.

Stop the isolated deployment and delete its temporary database:

```bash
docker compose --env-file /dev/null -f /tmp/nemesis-real-mythic/compose.yaml down -v
```
