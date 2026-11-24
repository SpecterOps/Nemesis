#!/usr/bin/env bash
# Tests for tools/submit.sh (issue #159). Docker is replaced by a stub that records its arguments, so
# nothing is run. Run: ./tools/tests/test_submit.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUBMIT="$(dirname "$SCRIPT_DIR")/submit.sh"
unset NEMESIS_PASSWORD

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILURES=0

check() { # check DESCRIPTION CONDITION...
  local desc=$1
  shift
  if "$@"; then
    echo "ok   - $desc"
  else
    echo "FAIL - $desc"
    FAILURES=$((FAILURES + 1))
  fi
}
has_arg() { # has_arg VALUE: VALUE is one whole docker argument
  local a
  for a in "${ARGV[@]}"; do [[ "$a" == "$1" ]] && return 0; done
  return 1
}
lacks_arg_containing() {
  local a
  for a in "${ARGV[@]}"; do [[ "$a" == *"$1"* ]] && return 1; done
  return 0
}
count_args() { # count_args PREFIX
  local a n=0
  for a in "${ARGV[@]}"; do [[ "$a" == "$1"* ]] && n=$((n + 1)); done
  echo "$n"
}
after_image() { # the arguments passed to the CLI, space-joined
  local a seen=false out=()
  for a in "${ARGV[@]}"; do
    if $seen; then out+=("$a"); fi
    [[ "$a" == "$IMAGE" ]] && seen=true
  done
  echo "${out[*]}"
}

mkdir -p "$TMP/bin"
# docker stub: one argument per line in $DOCKER_ARGV, plus whether NEMESIS_PASSWORD was in its environment
cat > "$TMP/bin/docker" << 'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$DOCKER_ARGV"
echo "${NEMESIS_PASSWORD-<unset>}" > "$DOCKER_ARGV.env"
EOF
chmod +x "$TMP/bin/docker"
export PATH="$TMP/bin:$PATH" DOCKER_ARGV="$TMP/argv" NEMESIS_CLI_IMAGE="test/cli:1"
IMAGE="test/cli:1"

run_submit() { # run_submit ARGS... -> ARGV, OUT, RC
  rm -f "$DOCKER_ARGV"
  OUT="$(cd "$TMP" && "$SUBMIT" "$@" 2>&1)" && RC=0 || RC=$?
  ARGV=()
  if [ -f "$DOCKER_ARGV" ]; then
    mapfile -t ARGV < "$DOCKER_ARGV"
  fi
}

W="$TMP/work"
mkdir -p "$W/a" "$W/b" "$W/dir with space/sub" "$W/odd,dir:x"
echo 1 > "$W/a/same.txt"
echo 2 > "$W/b/same.txt"
echo 3 > "$W/dir with space/sub/f.txt"
echo 4 > "$W/odd,dir:x/g.txt"
echo '{}' > "$W/filters.json"

# --- real paths are kept ---
run_submit "$W/a/same.txt" -h nemesis:7443
check "file: docker run invoked" [ "$RC" = 0 ]
check "file: mounted read-only at its real path" \
  has_arg "type=bind,\"source=$W/a/same.txt\",\"target=$W/a/same.txt\",readonly"
check "file: CLI receives the real path, not /data/<basename>" [ "$(after_image)" = "submit $W/a/same.txt -h nemesis:7443" ]
check "file: nothing mounted under /data" lacks_arg_containing "/data/"

# --- same basename no longer collides ---
run_submit "$W/a/same.txt" "$W/b/same.txt"
check "same basename: two separate mounts" [ "$(count_args 'type=bind')" = 2 ]
check "same basename: both real paths submitted" [ "$(after_image)" = "submit $W/a/same.txt $W/b/same.txt" ]

# --- relative paths, directories and spaces ---
run_submit "work/dir with space" -r
check "relative directory: resolved to its absolute real path" \
  has_arg "type=bind,\"source=$W/dir with space\",\"target=$W/dir with space\",readonly"
check "directory with spaces: kept as one argument" [ "$(after_image)" = "submit $W/dir with space -r" ]

# --- ':' and ',' in a path ---
run_submit "$W/odd,dir:x/g.txt"
check "path with ',' and ':': CSV-quoted --mount field" \
  has_arg "type=bind,\"source=$W/odd,dir:x/g.txt\",\"target=$W/odd,dir:x/g.txt\",readonly"

# --- the same path twice: one mount ---
run_submit "$W/a/same.txt" "work/a/same.txt"
check "duplicate path: mounted once" [ "$(count_args 'type=bind')" = 1 ]

# --- option values that are files are mounted too ---
run_submit "$W/a" --container --filters "$W/filters.json"
check "--filters: file mounted at its real path" \
  has_arg "type=bind,\"source=$W/filters.json\",\"target=$W/filters.json\",readonly"
check "--filters: CLI gets the mounted path" [ "$(after_image)" = "submit $W/a --container --filters $W/filters.json" ]
run_submit -f "$W/b/same.txt"
check "-f: file mounted and passed" [ "$(after_image)" = "submit -f $W/b/same.txt" ]
run_submit "$W/a" -j "$W/b/same.txt"
check "non-file option value that names a file: passed as-is, not mounted" [ "$(count_args 'type=bind')" = 1 ]

# --- paths that would shadow the container's own files fall back to a unique directory ---
if [ -r /etc/hostname ] || [ -r /etc/passwd ]; then
  sys_file=/etc/passwd
  [ -r /etc/hostname ] && sys_file=/etc/hostname
  run_submit "$sys_file" "$W/a/same.txt"
  check "reserved path: mounted under /nemesis-submit/<n>/" \
    has_arg "type=bind,\"source=$sys_file\",\"target=/nemesis-submit/1/$(basename "$sys_file")\",readonly"
  check "reserved path: warns" bash -c '[[ "$1" == *Warning*nemesis-submit* ]]' _ "$OUT"
  check "reserved path: other arguments keep their real path" \
    has_arg "type=bind,\"source=$W/a/same.txt\",\"target=$W/a/same.txt\",readonly"
fi

run_submit /tmp
check "a whole top-level directory like /tmp: falls back" has_arg "type=bind,\"source=/tmp\",\"target=/nemesis-submit/1/tmp\",readonly"

# --- non-existent path: passed through as an argument, not mounted ---
run_submit "$W/missing.txt"
check "missing path: not mounted" [ "$(count_args 'type=bind')" = 0 ]

# --- password from the environment stays off the command line ---
run_submit "$W/a/same.txt"
check "NEMESIS_PASSWORD unset: not forwarded" bash -c '! grep -qx NEMESIS_PASSWORD "$1"' _ "$DOCKER_ARGV"
NEMESIS_PASSWORD='s3cret' run_submit "$W/a/same.txt"
check "NEMESIS_PASSWORD set: forwarded by name with -e" has_arg NEMESIS_PASSWORD
check "NEMESIS_PASSWORD set: value not on the docker command line" lacks_arg_containing "s3cret"
check "NEMESIS_PASSWORD set: value reaches docker's environment" [ "$(< "$DOCKER_ARGV.env")" = "s3cret" ]
check "NEMESIS_IGNORE_CERT_ERRORS still forwarded" has_arg NEMESIS_IGNORE_CERT_ERRORS

if [ "$FAILURES" -ne 0 ]; then
  echo "$FAILURES test(s) failed"
  exit 1
fi
echo "All tests passed"
