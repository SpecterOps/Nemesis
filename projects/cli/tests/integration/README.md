# CLI connector loopback integration tests

Run the Mythic fault suite without Docker or a live Nemesis deployment:

```bash
UV_CACHE_DIR=/tmp/nemesis-cli-uv-cache uv run --no-sync pytest tests/integration -q
```

The tests start ephemeral loopback `aiohttp` servers. They use Mythic's installed
SDK for login, GraphQL HTTP queries, GraphQL WebSocket subscriptions, and direct
file downloads, and use the real Nemesis HTTP client for multipart upload. No
network mocks or service containers are involved. All test databases and config
objects live in pytest's temporary directory; no environment or `.env` file is
read by these tests.

The covered faults include a legacy complete-filter cursor miss and its fixed
incomplete-file recovery, ordinary GraphQL completion and WebSocket disconnect,
Mythic server stop/restart on the same port, deletion before and during download,
missing/forbidden/truncated downloads, valid empty files, Nemesis outage and
recovery, an accepted upload with a dropped response, restart with successful
and unfinished LevelDB entries, invalid passwords and API tokens, denied
`filemeta` permissions, token revocation, and the real CLI dry run with an
untouched configured database. Server event logs and recorded byte hashes are
available on the surrogate instances for assertions.

Run a standalone Mythic protocol surrogate for manual connector work with:

```bash
uv run python -m tests.integration.mythic_surrogate
```

It listens on an ephemeral loopback port and seeds one harmless sample file. It
prints the selected URL and sample UUID. For a manual preview, copy that URL into
`settings-mythic-dry-run.yaml`:

```yaml
project: integration-test
mythic:
  url: http://127.0.0.1:PORT_FROM_SURROGATE
  credential:
    username: operator
    password: password
nemesis:
  url: http://127.0.0.1:1
  credential:
    username: unused
    password: unused
db:
  path: ./mythic-dry-run-state
networking:
  timeout_sec: 5
  validate_https_certs: false
```

Then run `uv run python -m cli connect-mythic --config settings-mythic-dry-run.yaml --dry-run`.
The CLI prints a `WOULD UPLOAD` line with the sample path, size, and SHA-256;
dry run does not contact the Nemesis URL. The printed credentials are public
test values with no access to a real deployment. The surrogate models only the
subset of Mythic/Hasura used by this CLI; it is not a conformance server for
Mythic or Hasura.

For tests against Mythic's actual Go server and Hasura, see
[the real Mythic reproduction instructions](real_mythic/README.md). These are
opt-in Docker tests and include the cursor regression, checked downloads,
authentication, deletion, reconnection, upload recovery, and the real CLI dry run.
