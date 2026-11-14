// Writes reference serializations of every manifest fixture, for
// crates/trustforge-core/tests/manifest_compat.rs:
//
//   fixtures/manifests/v0/canonical/<name>.json  the RFC 8785 (JCS) form
//   fixtures/manifests/v0/pretty/<name>.json     the indented form
//
// RFC 8785 is defined in terms of ECMAScript, so this script uses only the
// engine's own JSON.parse, JSON.stringify (string and number serialization)
// and default sort (UTF-16 code unit order). Objects are serialized member
// by member, because JavaScript enumerates integer-like keys ("1", "10") in
// numeric order whatever order they were inserted in.
//
// Run with any recent Node.js, from the repository root, without packages:
//
//   node scripts/json-reference.mjs

import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const root = "fixtures/manifests/v0";

function canonical(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonical).join(",") + "]";
  }
  return (
    "{" +
    Object.keys(value)
      .sort()
      .map((key) => JSON.stringify(key) + ":" + canonical(value[key]))
      .join(",") +
    "}"
  );
}

function pretty(value, indent) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  const inner = indent + "  ";
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return "[]";
    }
    return "[\n" + value.map((item) => inner + pretty(item, inner)).join(",\n") + "\n" + indent + "]";
  }
  const keys = Object.keys(value).sort();
  if (keys.length === 0) {
    return "{}";
  }
  return (
    "{\n" +
    keys.map((key) => inner + JSON.stringify(key) + ": " + pretty(value[key], inner)).join(",\n") +
    "\n" +
    indent +
    "}"
  );
}

for (const source of ["valid", "created"]) {
  for (const file of readdirSync(join(root, source)).filter((f) => f.endsWith(".json")).sort()) {
    const value = JSON.parse(readFileSync(join(root, source, file), "utf8"));
    const name = `${source}-${file}`;
    mkdirSync(join(root, "canonical"), { recursive: true });
    mkdirSync(join(root, "pretty"), { recursive: true });
    writeFileSync(join(root, "canonical", name), canonical(value));
    writeFileSync(join(root, "pretty", name), pretty(value, "") + "\n");
    console.log(name);
  }
}
