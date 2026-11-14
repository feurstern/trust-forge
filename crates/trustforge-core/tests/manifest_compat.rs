//! Compatibility of manifest version 0 with its fixtures.
//!
//! - `fixtures/manifests/v0/valid/` holds manifests written by hand in
//!   different styles. Every published version's examples stay here
//!   permanently: they must keep parsing, with the same warnings.
//! - `fixtures/manifests/v0/created/` pins what `manifest create` writes for
//!   known artifacts.
//! - `canonical/` and `pretty/` were produced from both by
//!   `scripts/json-reference.mjs`, which uses only ECMAScript's own JSON
//!   serialization, the reference RFC 8785 is defined on. TrustForge's
//!   writers must match them byte for byte.

// clippy.toml allows unwrap and expect only inside #[test] functions; the
// helpers in this test crate panic on setup failures on purpose.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use trustforge_core::digest::{Digest, DigestAlgorithm};
use trustforge_core::inspect::{InspectOptions, inspect_reader};
use trustforge_core::json::{self, JsonLimits};
use trustforge_core::manifest::{
    BuildDefinition, Manifest, ManifestError, ParseOptions, ParsedManifest, WarningKind,
    parse_manifest,
};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/manifests/v0")
}

fn read(path: impl AsRef<Path>) -> Vec<u8> {
    fs::read(fixtures().join(path)).unwrap()
}

fn parse(bytes: &[u8]) -> ParsedManifest {
    parse_manifest(bytes, &ParseOptions::default()).unwrap()
}

/// The fixtures in `dir`, by file name.
fn fixture_names(dir: &str) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(fixtures().join(dir))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".json"))
        .collect();
    names.sort();
    names
}

#[test]
fn every_valid_fixture_parses_with_its_expected_warnings() {
    let expected: &[(&str, &[(&str, WarningKind)])] = &[
        ("directory.json", &[]),
        (
            "extensions.json",
            &[
                ("/x-note", WarningKind::UnknownField),
                ("/subject/0/uri", WarningKind::UnknownField),
                ("/subject/0/digest/md5", WarningKind::InsecureAlgorithm),
                ("/subject/0/digest/sha3-256", WarningKind::UnknownAlgorithm),
                ("/predicate/x-vendor", WarningKind::UnknownField),
                ("/predicate/artifact/x-mode", WarningKind::UnknownField),
                (
                    "/predicate/buildDefinition/buildType",
                    WarningKind::UnsupportedBuildType,
                ),
            ],
        ),
        ("file-minimal.json", &[]),
        ("file-recipe.json", &[]),
        ("unicode-name.json", &[]),
    ];
    let names: Vec<&str> = expected.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        fixture_names("valid"),
        names,
        "every fixture has expectations"
    );
    for (name, warnings) in expected {
        let bytes = read(format!("valid/{name}"));
        let parsed = parse(&bytes);
        let actual: Vec<(String, WarningKind)> = parsed
            .warnings
            .iter()
            .map(|w| (w.pointer.to_rfc6901(), w.kind.clone()))
            .collect();
        let expected: Vec<(String, WarningKind)> = warnings
            .iter()
            .map(|(p, k)| ((*p).to_owned(), k.clone()))
            .collect();
        assert_eq!(actual, expected, "{name}");
        assert_eq!(
            parsed.file_digest,
            Digest::of(DigestAlgorithm::Sha256, &bytes),
            "{name}: identity is the exact bytes"
        );
    }
}

/// The invalid fixtures, which the JSON Schema must also reject
/// (`scripts/check-schema.sh`), with where TrustForge rejects each.
#[test]
fn every_invalid_fixture_is_rejected_where_expected() {
    let expected = [
        (
            "channel-toolchain.json",
            "/predicate/buildDefinition/internalParameters/toolchain",
        ),
        ("directory-without-tree.json", "/predicate/artifact/tree"),
        (
            "environment-not-allowed.json",
            "/predicate/buildDefinition/internalParameters/env/LD_PRELOAD",
        ),
        ("file-with-tree.json", "/predicate/artifact/tree"),
        (
            "http-repository.json",
            "/predicate/buildDefinition/externalParameters/source/repository",
        ),
        ("insecure-digest-only.json", "/subject/0/digest"),
        (
            "missing-build-image.json",
            "/predicate/buildDefinition/resolvedDependencies",
        ),
        ("missing-subject.json", "/subject"),
        (
            "option-as-binary-name.json",
            "/predicate/buildDefinition/externalParameters/bin",
        ),
        (
            "option-as-output-path.json",
            "/predicate/buildDefinition/externalParameters/outputPath",
        ),
        ("other-predicate-type.json", "/predicateType"),
        ("parent-path-name.json", "/subject/0/name"),
        (
            "repository-dot-segments.json",
            "/predicate/buildDefinition/externalParameters/source/repository",
        ),
        (
            "symlink-with-digest.json",
            "/predicate/artifact/tree/3/digest",
        ),
        (
            "unknown-build-parameter.json",
            "/predicate/buildDefinition/externalParameters/rustcWrapper",
        ),
        ("uppercase-digest.json", "/subject/0/digest/sha256"),
    ];
    let names: Vec<&str> = expected.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        fixture_names("invalid"),
        names,
        "every fixture has an expectation"
    );
    for (name, pointer) in expected {
        let at = match parse_manifest(&read(format!("invalid/{name}")), &ParseOptions::default()) {
            Err(
                ManifestError::Invalid { pointer, .. } | ManifestError::Unsupported { pointer, .. },
            ) => pointer.to_rfc6901(),
            other => panic!("{name}: expected a rejection, got {other:?}"),
        };
        assert_eq!(at, pointer, "{name}");
    }
}

#[test]
fn canonical_and_pretty_forms_match_the_ecmascript_reference() {
    for dir in ["valid", "created"] {
        for name in fixture_names(dir) {
            let value =
                json::parse(&read(format!("{dir}/{name}")), &JsonLimits::default()).unwrap();
            let reference = format!("{dir}-{name}");
            assert_eq!(
                String::from_utf8(json::to_canonical(&value)).unwrap(),
                String::from_utf8(read(format!("canonical/{reference}"))).unwrap(),
                "canonical form of {dir}/{name}"
            );
            assert_eq!(
                String::from_utf8(json::to_pretty(&value)).unwrap(),
                String::from_utf8(read(format!("pretty/{reference}"))).unwrap(),
                "pretty form of {dir}/{name}"
            );
        }
    }
}

/// A manifest that uses only defined fields is written back exactly as the
/// reference serializes it: nothing is lost, added or reordered.
#[test]
fn defined_fields_round_trip_exactly() {
    for name in [
        "directory.json",
        "file-minimal.json",
        "file-recipe.json",
        "unicode-name.json",
    ] {
        let manifest = parse(&read(format!("valid/{name}"))).manifest;
        assert_eq!(
            String::from_utf8(manifest.to_canonical_json()).unwrap(),
            String::from_utf8(read(format!("canonical/valid-{name}"))).unwrap(),
            "{name}"
        );
        assert_eq!(
            manifest.to_pretty_json(),
            read(format!("pretty/valid-{name}")),
            "{name}"
        );
        assert_eq!(
            parse(&manifest.to_canonical_json()).manifest,
            manifest,
            "{name}"
        );
    }
}

/// Ignored fields are dropped when a manifest is written back; a recipe of
/// an unsupported build type is kept as written.
#[test]
fn ignored_fields_are_dropped_and_unsupported_recipes_kept() {
    let parsed = parse(&read("valid/extensions.json"));
    let Some(BuildDefinition::Unsupported { build_type, .. }) = parsed.manifest.build_definition()
    else {
        panic!("expected an unsupported build definition");
    };
    assert_eq!(build_type, "https://example.com/build/make/v1");
    let rewritten = parse(&parsed.manifest.to_pretty_json());
    let warnings: Vec<_> = rewritten
        .warnings
        .iter()
        .map(|w| (w.pointer.to_rfc6901(), w.kind.clone()))
        .collect();
    assert_eq!(
        warnings,
        [(
            "/predicate/buildDefinition/buildType".to_owned(),
            WarningKind::UnsupportedBuildType
        )]
    );
    assert_eq!(
        rewritten.manifest.subjects()[0].digest().iter().count(),
        1,
        "only sha256 is kept"
    );
}

#[test]
fn other_versions_are_unsupported_never_interpreted() {
    let text = String::from_utf8(read("valid/file-minimal.json")).unwrap();
    for (from, to) in [
        ("trust-forge/manifest/v0", "trust-forge/manifest/v1"),
        (
            "https://feurstern.github.io/trust-forge/manifest/v0",
            "https://slsa.dev/provenance/v1",
        ),
        (
            "https://in-toto.io/Statement/v1",
            "https://in-toto.io/Statement/v0.1",
        ),
    ] {
        let changed = text.replace(from, to);
        assert!(
            matches!(
                parse_manifest(changed.as_bytes(), &ParseOptions::default()),
                Err(ManifestError::Unsupported { .. })
            ),
            "{to}"
        );
    }
}

#[test]
fn a_created_file_manifest_is_stable() {
    let inspection =
        inspect_reader("-", &b"Hello, world.\n"[..], &InspectOptions::default()).unwrap();
    let manifest = Manifest::from_inspection(&inspection, Some("hello.txt")).unwrap();
    assert_eq!(manifest.to_pretty_json(), read("created/file.json"));
    assert!(parse(&manifest.to_pretty_json()).warnings.is_empty());
}

#[cfg(unix)]
#[test]
fn a_created_directory_manifest_is_stable() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    use trustforge_core::inspect::inspect_path;

    let tmp = tempfile::tempdir().unwrap();
    let dist = tmp.path().join("dist");
    fs::create_dir_all(dist.join("bin")).unwrap();
    fs::write(dist.join("README"), b"Hello, world.\n").unwrap();
    fs::set_permissions(dist.join("README"), fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(dist.join("bin/hello"), b"#!/bin/sh\necho hello\n").unwrap();
    fs::set_permissions(dist.join("bin/hello"), fs::Permissions::from_mode(0o755)).unwrap();
    symlink("/usr/lib/libexample.so.1", dist.join("libexample.so")).unwrap();

    let inspection = inspect_path(&dist, &InspectOptions::default()).unwrap();
    let manifest = Manifest::from_inspection(&inspection, None).unwrap();
    assert_eq!(manifest.to_pretty_json(), read("created/directory.json"));
    assert!(parse(&manifest.to_pretty_json()).warnings.is_empty());
}
