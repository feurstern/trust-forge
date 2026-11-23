#!/bin/sh
# Writes the valid report fixtures, fixtures/reports/v0/valid/*.json, with
# the trustforge binary built from this tree, from fixed inputs.
# crates/trustforge-core/tests/report_compat.rs checks that each one still
# reads and is written back byte for byte.
#
# Run it from the repository root after an intended change of the report
# format, then rewrite the invalid fixtures, which are derived from these, and
# review the difference:
#
#   cargo build -p trustforge-cli && sh scripts/report-fixtures.sh
#   TRUSTFORGE_UPDATE_GOLDEN=1 cargo test -p trustforge-core --test report_compat
#
# The inputs are fixed and reports have no timestamp, so the output only
# changes when the format or the text does. The "missing" fixture records the
# operating system's message for a missing file, so run this on Linux.

set -eu
umask 022

tf=${TRUSTFORGE:-$PWD/target/debug/trustforge}
out=$PWD/fixtures/reports/v0/valid
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"
cd "$work"

zero=sha256:0000000000000000000000000000000000000000000000000000000000000000

# verify writes the report even when the result is not a success; only the
# report matters here.
report() {
    name=$1
    shift
    "$tf" verify "$@" --format json >"$out/$name.json" || true
}

printf 'hello, world\n' >app
"$tf" manifest create app -o app.manifest.json
pin=sha256:$(sha256sum app.manifest.json | cut -d' ' -f1)

cat >recipe.json <<'EOF'
{
  "buildType": "https://feurstern.github.io/trust-forge/build/cargo/v0",
  "externalParameters": {
    "bin": "application",
    "outputPath": "target/x86_64-unknown-linux-gnu/release/application",
    "source": {
      "ref": "refs/tags/v1.2.3",
      "repository": "https://github.com/example/project.git"
    },
    "target": "x86_64-unknown-linux-gnu"
  },
  "internalParameters": {
    "toolchain": "1.99.1"
  },
  "resolvedDependencies": [
    {
      "digest": {
        "gitCommit": "8c3e1f6b2a9d4e5f60718293a4b5c6d7e8f90a1b"
      },
      "uri": "git+https://github.com/example/project.git@refs/tags/v1.2.3"
    },
    {
      "digest": {
        "sha256": "5d1f3c8e9a2b4c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d"
      },
      "uri": "pkg:docker/library/rust@1.99.1-slim-bookworm?repository_url=docker.io"
    }
  ]
}
EOF
"$tf" manifest create app --build-definition recipe.json -o recipe.manifest.json

sed 's#trust-forge/manifest/v0#trust-forge/manifest/v9#' app.manifest.json >v9.json
printf '%s' '{"payload": "e30=", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "AA=="}]}' >signed.json

mkdir -p dist/bin
printf 'binary' >dist/bin/app
chmod 755 dist/bin/app
printf 'read me' >dist/README
ln -s bin/app dist/app
"$tf" manifest create dist -o dist.manifest.json
report tree-verified dist --manifest dist.manifest.json --require integrity
chmod 644 dist/bin/app
printf 'read mE' >dist/README
: >dist/extra

report verified app --manifest app.manifest.json --require integrity
report partial app --manifest app.manifest.json
report pinned app --manifest app.manifest.json --manifest-digest "$pin" --require integrity
report pin-mismatch app --manifest app.manifest.json --manifest-digest "$zero" --require integrity
report mismatch app --expect "$zero" --require integrity
report two-references app --manifest app.manifest.json --expect "sha512:$(sha512sum app | cut -d' ' -f1)" --require integrity
report missing missing --manifest app.manifest.json --require integrity
report unsupported app --manifest v9.json --require integrity
report envelope app --manifest signed.json
report recipe app --manifest recipe.manifest.json
report tree-mismatch dist --manifest dist.manifest.json --require integrity
report no-match-for-kind dist --manifest app.manifest.json --require integrity
printf 'abc' | report stream - --expect sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad --require integrity

ls "$out"
