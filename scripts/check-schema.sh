#!/bin/sh
# Checks docs/schemas/manifest-v0.schema.json against the manifest fixtures
# with ajv, the reference JSON Schema validator: every valid and created
# fixture must match the schema, and every invalid fixture must not.
#
# Needs Node.js. npx downloads ajv-cli from npm the first time. Run it from
# the repository root after changing the schema or the fixtures:
#
#   sh scripts/check-schema.sh

set -eu

schema=docs/schemas/manifest-v0.schema.json
fixtures=fixtures/manifests/v0
# Strict mode stays on, except for its check that a property listed in
# "required" inside an anyOf branch is also declared in that branch: the
# schema uses that standard pattern to require at least one digest.
ajv() {
    npx --yes ajv-cli@5.0.0 "$@" --spec=draft2020 --strict=true --strict-required=false
}

ajv compile -s "$schema" >/dev/null
status=0
for file in "$fixtures"/valid/*.json "$fixtures"/created/*.json; do
    if ajv validate -s "$schema" -d "$file" >/dev/null 2>&1; then
        echo "ok      $file matches the schema"
    else
        echo "FAILED  $file should match the schema:"
        ajv validate -s "$schema" -d "$file" --errors=text || true
        status=1
    fi
done
for file in "$fixtures"/invalid/*.json; do
    if ajv validate -s "$schema" -d "$file" >/dev/null 2>&1; then
        echo "FAILED  $file should not match the schema"
        status=1
    else
        echo "ok      $file is rejected"
    fi
done
exit "$status"
