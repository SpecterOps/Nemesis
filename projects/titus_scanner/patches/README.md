# Titus patches

Applied to upstream `github.com/praetorian-inc/titus` (the version in `../go.mod`) by `apply.sh`,
which the Dockerfile runs before building. For local work run `./patches/apply.sh` once, then
`go build` / `go test` as usual (a gitignored `go.work` points at the patched copy).

- `0001-linear-rune-to-byte-offsets.patch`: regexp2 reports rune offsets; upstream converts each
  match by walking the buffer from the start, so scan time grows with file size x match count
  (a 32 MB file took ~50 s). A per-buffer rune index makes it linear (~1.7 s) with identical
  results, including for non-ASCII content.

When bumping Titus, re-apply each patch on the new version and refresh it, or delete it once the
change is upstream.
