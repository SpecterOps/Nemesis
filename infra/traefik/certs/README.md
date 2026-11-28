# TLS certificate for Traefik

`tools/nemesis-ctl.sh start` (or `nemesis start`) creates a self-signed certificate here, `server.crt` and
`server.key`, when there is none, and renews it before it expires. It covers `localhost`, `127.0.0.1` and the host in
`NEMESIS_URL`. Nothing in this directory except this README is committed: each deployment gets its own key.

To use your own certificate, put it here as `server.crt` (with any intermediate certificates) and `server.key`. It
is never replaced; you only get a warning when it is about to expire. For Kubernetes, see `docs/kubernetes.md`
(the setup scripts read `cert.pem`/`key.pem` from this directory).

To trust the self-signed certificate in the CLI, pass `--ca-file infra/traefik/certs/server.crt` (see `docs/cli.md`).
