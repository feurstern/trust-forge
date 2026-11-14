//! Every validation rule of manifest version 0, one case at a time: each
//! case changes a valid fixture in one way and names the error expected,
//! with its location as a JSON Pointer.

// clippy.toml allows unwrap and expect only inside #[test] functions; the
// helpers in this test crate panic on setup failures on purpose.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use serde_json::{Value, json};
use trustforge_core::digest::DigestError;
use trustforge_core::json::{JsonError, Violation};
use trustforge_core::manifest::{
    BuildDefinition, ManifestError, ParseOptions, ParsedManifest, Problem, WarningKind,
    parse_manifest,
};
use trustforge_core::name::NameError;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/manifests/v0/valid")
            .join(name),
    )
    .unwrap()
}

fn document(name: &str) -> Value {
    serde_json::from_slice(&fixture(name)).unwrap()
}

/// The parent object of `pointer` and the last key.
fn parent<'v>(
    doc: &'v mut Value,
    pointer: &str,
) -> (&'v mut serde_json::Map<String, Value>, String) {
    let (parent, key) = pointer.rsplit_once('/').unwrap();
    let object = doc.pointer_mut(parent).unwrap().as_object_mut().unwrap();
    (object, key.to_owned())
}

fn set(doc: &mut Value, pointer: &str, value: Value) {
    let (object, key) = parent(doc, pointer);
    object.insert(key, value);
}

fn remove(doc: &mut Value, pointer: &str) {
    let (object, key) = parent(doc, pointer);
    assert!(object.remove(&key).is_some(), "{pointer} exists");
}

fn error(doc: &Value) -> ManifestError {
    parse_manifest(&serde_json::to_vec(doc).unwrap(), &ParseOptions::default())
        .expect_err("must be rejected")
}

/// Asserts that `doc` is rejected at `pointer` for `expected`.
#[track_caller]
fn rejects(doc: &Value, pointer: &str, expected: Problem) {
    match error(doc) {
        ManifestError::Invalid {
            pointer: at,
            problem,
        } => {
            assert_eq!((at.to_rfc6901(), problem), (pointer.to_owned(), expected));
        }
        other => panic!("expected {pointer}: {expected}, got {other}"),
    }
}

#[track_caller]
fn rule(doc: &Value, pointer: &str) {
    match error(doc) {
        ManifestError::Invalid {
            pointer: at,
            problem: Problem::Rule(_),
        } => assert_eq!(at.to_rfc6901(), pointer),
        other => panic!("expected a rule violation at {pointer}, got {other}"),
    }
}

/// Asserts that `doc` cannot be evaluated by this version, at `pointer`.
#[track_caller]
fn unsupported(doc: &Value, pointer: &str) {
    match error(doc) {
        ManifestError::Unsupported { pointer: at, .. } => assert_eq!(at.to_rfc6901(), pointer),
        other => panic!("expected UNSUPPORTED at {pointer}, got {other}"),
    }
}

fn parsed(doc: &Value) -> ParsedManifest {
    parse_manifest(&serde_json::to_vec(doc).unwrap(), &ParseOptions::default()).unwrap()
}

fn warnings(parsed: &ParsedManifest) -> Vec<(String, WarningKind)> {
    parsed
        .warnings
        .iter()
        .map(|w| (w.pointer.to_rfc6901(), w.kind.clone()))
        .collect()
}

#[track_caller]
fn name_error(doc: &Value, pointer: &str) {
    match error(doc) {
        ManifestError::Invalid {
            pointer: at,
            problem: Problem::Name(_),
        } => assert_eq!(at.to_rfc6901(), pointer),
        other => panic!("expected an invalid name at {pointer}, got {other}"),
    }
}

const SHA256: &str = "d1676dcb0cd0903841cf4953ba161eb34601a821d45ae551049318597b7aa5b9";

#[test]
fn statement_rules() {
    let base = document("file-minimal.json");
    let with = |f: &dyn Fn(&mut Value)| {
        let mut doc = base.clone();
        f(&mut doc);
        doc
    };
    rejects(&with(&|d| remove(d, "/_type")), "/_type", Problem::Missing);
    rejects(
        &with(&|d| set(d, "/predicateType", json!(1))),
        "/predicateType",
        Problem::WrongType("a string"),
    );
    rejects(
        &with(&|d| set(d, "/Subject", json!([]))),
        "/Subject",
        Problem::CaseVariant("subject"),
    );
    rejects(
        &with(&|d| set(d, "/\u{17f}ubject", json!([]))),
        "/\u{17f}ubject",
        Problem::CaseVariant("subject"),
    );
    rejects(
        &with(&|d| set(d, "/PREDICATE", json!({}))),
        "/PREDICATE",
        Problem::CaseVariant("predicate"),
    );
    rule(&with(&|d| set(d, "/subject", json!([]))), "/subject");
    rejects(
        &with(&|d| set(d, "/subject", json!({}))),
        "/subject",
        Problem::WrongType("an array"),
    );
    rejects(
        &with(&|d| remove(d, "/predicate")),
        "/predicate",
        Problem::Missing,
    );
    rejects(
        &with(&|d| remove(d, "/predicate/artifact")),
        "/predicate/artifact",
        Problem::Missing,
    );
    assert!(matches!(
        error(&with(&|d| set(
            d,
            "/_type",
            json!("https://in-toto.io/Statement/v0.1")
        ))),
        ManifestError::Unsupported { .. }
    ));
}

#[test]
fn subject_rules() {
    let base = document("file-minimal.json");
    let with = |f: &dyn Fn(&mut Value)| {
        let mut doc = base.clone();
        f(&mut doc);
        doc
    };
    name_error(
        &with(&|d| set(d, "/subject/0/name", json!("../tool"))),
        "/subject/0/name",
    );
    name_error(
        &with(&|d| set(d, "/subject/0/name", json!("a/../b"))),
        "/subject/0/name",
    );
    name_error(
        &with(&|d| set(d, "/subject/0/name", json!("back\\slash"))),
        "/subject/0/name",
    );
    rejects(
        &with(&|d| set(d, "/subject/0/digest/sha256", json!(SHA256.to_uppercase()))),
        "/subject/0/digest/sha256",
        Problem::Digest(DigestError::InvalidHex {
            algorithm: trustforge_core::digest::DigestAlgorithm::Sha256,
        }),
    );
    // Nothing left to compare is not a broken document but one this version
    // cannot evaluate.
    unsupported(
        &with(&|d| {
            set(
                d,
                "/subject/0/digest",
                json!({ "md5": "0123456789abcdef0123456789abcdef" }),
            )
        }),
        "/subject/0/digest",
    );
    rule(
        &with(&|d| set(d, "/subject/0/digest", json!({}))),
        "/subject/0/digest",
    );
    rejects(
        &with(&|d| set(d, "/subject/0/digest/SHA256", json!(SHA256))),
        "/subject/0/digest/SHA256",
        Problem::CaseVariant("sha256"),
    );
    // Two subjects with one name, and a file artifact with two subjects.
    let two = |second_name: &str| {
        with(&|d| {
            let subject = d["subject"][0].clone();
            let mut second = subject.clone();
            second["name"] = json!(second_name);
            d["subject"] = json!([subject, second]);
        })
    };
    rule(&two("tool"), "/subject/1/name");
    rule(&two("other"), "/subject");
}

#[test]
fn artifact_rules() {
    let base = document("file-minimal.json");
    let with = |f: &dyn Fn(&mut Value)| {
        let mut doc = base.clone();
        f(&mut doc);
        doc
    };
    rule(
        &with(&|d| set(d, "/predicate/artifact/kind", json!("folder"))),
        "/predicate/artifact/kind",
    );
    rejects(
        &with(&|d| set(d, "/predicate/artifact/size", json!("26"))),
        "/predicate/artifact/size",
        Problem::WrongType("an integer"),
    );
    rule(
        &with(&|d| set(d, "/predicate/artifact/tree", json!([]))),
        "/predicate/artifact/tree",
    );
    rule(
        &with(&|d| set(d, "/predicate/artifact/treeDigest", json!({}))),
        "/predicate/artifact/treeDigest",
    );
}

#[test]
fn directory_rules() {
    let base = document("directory.json");
    let with = |f: &dyn Fn(&mut Value)| {
        let mut doc = base.clone();
        f(&mut doc);
        doc
    };
    let tree = "/predicate/artifact/tree";
    // Entries: 0 README, 1 bin, 2 bin/hello, 3 libexample.so.
    rule(
        &with(&|d| {
            d["predicate"]["artifact"]["tree"]
                .as_array_mut()
                .unwrap()
                .swap(0, 1)
        }),
        "/predicate/artifact/tree/1/path",
    );
    rule(
        &with(&|d| {
            d["predicate"]["artifact"]["tree"]
                .as_array_mut()
                .unwrap()
                .remove(1);
        }),
        "/predicate/artifact/tree/1/path",
    );
    rule(
        &with(&|d| set(d, "/subject/1/digest/sha256", json!(SHA256))),
        "/subject/1",
    );
    rule(
        &with(&|d| {
            d["subject"].as_array_mut().unwrap().remove(1);
        }),
        tree,
    );
    rule(
        &with(&|d| set(d, "/predicate/artifact/size", json!(36))),
        "/predicate/artifact/size",
    );
    rejects(
        &with(&|d| remove(d, "/predicate/artifact/treeDigest")),
        "/predicate/artifact/treeDigest",
        Problem::Missing,
    );
    // A content digest key is not a tree digest key.
    unsupported(
        &with(&|d| {
            set(
                d,
                "/predicate/artifact/treeDigest",
                json!({ "sha256": SHA256 }),
            )
        }),
        "/predicate/artifact/treeDigest",
    );
    rule(
        &with(&|d| set(d, "/predicate/artifact/treeDigest", json!({}))),
        "/predicate/artifact/treeDigest",
    );
    rule(
        &with(&|d| set(d, "/predicate/artifact/tree/1/type", json!("socket"))),
        "/predicate/artifact/tree/1/type",
    );
    rejects(
        &with(&|d| remove(d, "/predicate/artifact/tree/0/executable")),
        "/predicate/artifact/tree/0/executable",
        Problem::Missing,
    );
    rule(
        &with(&|d| set(d, "/predicate/artifact/tree/3/size", json!(1))),
        "/predicate/artifact/tree/3/size",
    );
    rejects(
        &with(&|d| set(d, "/predicate/artifact/tree/3/target", json!(""))),
        "/predicate/artifact/tree/3/target",
        Problem::Name(NameError::Empty),
    );
    name_error(
        &with(&|d| set(d, "/predicate/artifact/tree/2/path", json!("bin/../x"))),
        "/predicate/artifact/tree/2/path",
    );
}

#[test]
fn cargo_recipe_rules() {
    let base = document("file-recipe.json");
    let with = |f: &dyn Fn(&mut Value)| {
        let mut doc = base.clone();
        f(&mut doc);
        doc
    };
    let ext = "/predicate/buildDefinition/externalParameters";
    let int = "/predicate/buildDefinition/internalParameters";
    let deps = "/predicate/buildDefinition/resolvedDependencies";

    rejects(
        &with(&|d| set(d, &format!("{ext}/rustcWrapper"), json!("x"))),
        &format!("{ext}/rustcWrapper"),
        Problem::UnknownField,
    );
    rejects(
        &with(&|d| set(d, &format!("{ext}/Bin"), json!("x"))),
        &format!("{ext}/Bin"),
        Problem::CaseVariant("bin"),
    );
    for bad in ["--config=evil", "-x", "1app", "app name", ""] {
        rule(
            &with(&|d| set(d, &format!("{ext}/bin"), json!(bad))),
            &format!("{ext}/bin"),
        );
    }
    rule(
        &with(&|d| set(d, &format!("{ext}/package"), json!("-p"))),
        &format!("{ext}/package"),
    );
    rule(
        &with(&|d| set(d, &format!("{ext}/profile"), json!("--release"))),
        &format!("{ext}/profile"),
    );
    for bad in [
        "http://github.com/example/project.git",
        "https://user:pw@github.com/x",
        "ssh://github.com/x",
        "file:///repo",
        "https://github.com/example/../other/project.git",
        "https://github.com/example/%2e%2e/project.git",
        "https://github.com/example/project.git/",
    ] {
        rule(
            &with(&|d| set(d, &format!("{ext}/source/repository"), json!(bad))),
            &format!("{ext}/source/repository"),
        );
    }
    for bad in ["v1.2.3", "refs/tags/v1@x", "refs/heads/x.lock/y"] {
        rule(
            &with(&|d| set(d, &format!("{ext}/source/ref"), json!(bad))),
            &format!("{ext}/source/ref"),
        );
    }
    rejects(
        &with(&|d| set(d, &format!("{ext}/source/branch"), json!("main"))),
        &format!("{ext}/source/branch"),
        Problem::UnknownField,
    );
    rule(
        &with(&|d| {
            set(
                d,
                &format!("{ext}/target"),
                json!("x86_64-unknown-custom.json"),
            )
        }),
        &format!("{ext}/target"),
    );
    rule(
        &with(&|d| set(d, &format!("{ext}/features"), json!(["tls", "cli"]))),
        &format!("{ext}/features/1"),
    );
    rule(
        &with(&|d| set(d, &format!("{ext}/features"), json!(["cli", "cli"]))),
        &format!("{ext}/features/1"),
    );
    rule(
        &with(&|d| set(d, &format!("{ext}/features"), json!(["-x"]))),
        &format!("{ext}/features/0"),
    );
    rejects(
        &with(&|d| set(d, &format!("{ext}/defaultFeatures"), json!("no"))),
        &format!("{ext}/defaultFeatures"),
        Problem::WrongType("true or false"),
    );
    name_error(
        &with(&|d| set(d, &format!("{ext}/outputPath"), json!("../application"))),
        &format!("{ext}/outputPath"),
    );
    name_error(
        &with(&|d| set(d, &format!("{ext}/workspacePath"), json!("/abs"))),
        &format!("{ext}/workspacePath"),
    );
    // Paths are passed to Cargo: no component may read as an option.
    for bad in ["-o", "target/--config=x", "target/a b", ".hidden/app"] {
        rule(
            &with(&|d| set(d, &format!("{ext}/outputPath"), json!(bad))),
            &format!("{ext}/outputPath"),
        );
    }
    rule(
        &with(&|d| set(d, &format!("{ext}/workspacePath"), json!("-Zunstable"))),
        &format!("{ext}/workspacePath"),
    );

    rule(
        &with(&|d| set(d, &format!("{int}/toolchain"), json!("stable"))),
        &format!("{int}/toolchain"),
    );
    rejects(
        &with(&|d| remove(d, &format!("{int}/toolchain"))),
        &format!("{int}/toolchain"),
        Problem::Missing,
    );
    rule(
        &with(&|d| set(d, &format!("{int}/workdir"), json!("build/src"))),
        &format!("{int}/workdir"),
    );
    for bad in [
        "/build/../root",
        "/root/.cargo",
        "/build",
        "/build/src/",
        "/build/a,dst=/etc",
        "/build/-v",
    ] {
        rule(
            &with(&|d| set(d, &format!("{int}/cargoHome"), json!(bad))),
            &format!("{int}/cargoHome"),
        );
    }
    // Neither directory may contain the other, defaults included: the
    // repository's files would become Cargo's own, trusted state.
    for (workdir, cargo_home) in [
        ("/build/src", "/build/src/cargo"),
        ("/build/src", "/build/src"),
        ("/build/cargo-home/registry", "/build/cargo-home"),
    ] {
        rule(
            &with(&|d| {
                set(d, &format!("{int}/workdir"), json!(workdir));
                set(d, &format!("{int}/cargoHome"), json!(cargo_home));
            }),
            &format!("{int}/cargoHome"),
        );
    }
    rule(
        &with(&|d| {
            remove(d, &format!("{int}/cargoHome"));
            set(d, &format!("{int}/workdir"), json!("/build/cargo-home/src"));
        }),
        &format!("{int}/workdir"),
    );
    rule(
        &with(&|d| {
            remove(d, &format!("{int}/workdir"));
            set(d, &format!("{int}/cargoHome"), json!("/build/src/cargo"));
        }),
        &format!("{int}/cargoHome"),
    );
    assert!(
        parsed(&with(&|d| {
            set(d, &format!("{int}/workdir"), json!("/build/srcx"));
            set(d, &format!("{int}/cargoHome"), json!("/build/src"));
        }))
        .warnings
        .is_empty()
    );
    rule(
        &with(&|d| set(d, &format!("{int}/env/LD_PRELOAD"), json!("/tmp/x.so"))),
        &format!("{int}/env/LD_PRELOAD"),
    );
    rule(
        &with(&|d| set(d, &format!("{int}/env/SOURCE_DATE_EPOCH"), json!("-1"))),
        &format!("{int}/env/SOURCE_DATE_EPOCH"),
    );
    rejects(
        &with(&|d| set(d, &format!("{int}/linker"), json!("cc"))),
        &format!("{int}/linker"),
        Problem::UnknownField,
    );

    let deps_array =
        |d: &mut Value| -> Vec<Value> { d.pointer(deps).unwrap().as_array().unwrap().clone() };
    rule(
        &with(&|d| {
            let only_source = vec![deps_array(d)[0].clone()];
            set(d, deps, json!(only_source));
        }),
        deps,
    );
    rule(
        &with(&|d| {
            let mut all = deps_array(d);
            all.push(all[0].clone());
            set(d, deps, json!(all));
        }),
        deps,
    );
    rule(
        &with(&|d| {
            set(
                d,
                &format!("{deps}/0/uri"),
                json!("git+https://github.com/example/project.git@refs/tags/v9"),
            )
        }),
        &format!("{deps}/0/uri"),
    );
    rule(
        &with(&|d| set(d, &format!("{deps}/0/digest/gitCommit"), json!("8c3e1f6"))),
        &format!("{deps}/0/digest/gitCommit"),
    );
    rule(
        &with(&|d| {
            set(
                d,
                &format!("{deps}/1/digest"),
                json!({ "sha512": "0".repeat(128) }),
            )
        }),
        &format!("{deps}/1/digest/sha256"),
    );

    // A case variant of a digest name could be read as that digest by
    // another tool.
    for (key, name) in [("GitCommit", "gitCommit"), ("SHA256", "sha256")] {
        let index = usize::from(name == "sha256");
        rejects(
            &with(&|d| {
                set(
                    d,
                    &format!("{deps}/{index}/digest/{key}"),
                    json!("0".repeat(64)),
                )
            }),
            &format!("{deps}/{index}/digest/{key}"),
            Problem::CaseVariant(name),
        );
    }
    // Insecure digests are dropped with a warning, as in subjects.
    let with_md5 = parsed(&with(&|d| {
        set(
            d,
            &format!("{deps}/1/digest/md5"),
            json!("0123456789abcdef0123456789abcdef"),
        )
    }));
    assert_eq!(
        warnings(&with_md5),
        [(
            format!("{deps}/1/digest/md5"),
            WarningKind::InsecureAlgorithm
        )]
    );
    rule(
        &with(&|d| set(d, &format!("{deps}/1/digest/md5"), json!(""))),
        &format!("{deps}/1/digest/md5"),
    );
    let with_sha1 = parsed(&with(&|d| {
        set(d, &format!("{deps}/0/digest/SHA1"), json!("0".repeat(40)));
    }));
    assert_eq!(
        warnings(&with_sha1),
        [(
            format!("{deps}/0/digest/SHA1"),
            WarningKind::InsecureAlgorithm
        )]
    );
    let Some(BuildDefinition::Cargo(recipe)) = with_md5.manifest.build_definition() else {
        panic!("expected a cargo recipe");
    };
    assert_eq!(
        recipe.resolved_dependencies()[1]
            .digest()
            .keys()
            .collect::<Vec<_>>(),
        ["sha256"]
    );

    // Letter case cannot hide a second source or image entry, and the one
    // entry of each kind must be written in lowercase.
    for extra in [
        "GIT+https://github.com/example/other.git@refs/heads/main",
        "PKG:DOCKER/library/rust@1.99.1",
    ] {
        rule(
            &with(&|d| {
                let mut all = deps_array(d);
                all.push(json!({ "uri": extra, "digest": { "sha256": SHA256 } }));
                set(d, deps, json!(all));
            }),
            deps,
        );
    }
    rule(
        &with(&|d| {
            set(
                d,
                &format!("{deps}/0/uri"),
                json!("GIT+https://github.com/example/project.git@refs/tags/v1.2.3"),
            )
        }),
        &format!("{deps}/0/uri"),
    );
    rule(
        &with(&|d| {
            set(
                d,
                &format!("{deps}/1/uri"),
                json!("pkg:Docker/library/rust@1.99.1-slim-bookworm"),
            )
        }),
        &format!("{deps}/1/uri"),
    );
}

#[test]
fn strict_mode_turns_warnings_into_errors() {
    let mut opts = ParseOptions::default();
    opts.strict = true;
    match parse_manifest(&fixture("extensions.json"), &opts) {
        Err(ManifestError::Invalid { pointer, problem }) => {
            assert_eq!(pointer.to_rfc6901(), "/x-note");
            assert_eq!(problem, Problem::Strict(WarningKind::UnknownField));
        }
        other => panic!("expected a strict-mode error, got {other:?}"),
    }
    assert!(parse_manifest(&fixture("file-recipe.json"), &opts).is_ok());
}

/// Rules of the strict JSON layer, applied before any field is read.
#[test]
fn documents_that_are_not_strict_json() {
    let text = String::from_utf8(fixture("file-minimal.json")).unwrap();
    let strict = |bytes: &[u8]| match parse_manifest(bytes, &ParseOptions::default()) {
        Err(ManifestError::Json(e)) => e,
        other => panic!("expected a JSON error, got {other:?}"),
    };
    let violation = |bytes: &[u8]| match strict(bytes) {
        JsonError::Strict { pointer, violation } => (pointer.to_rfc6901(), violation),
        other => panic!("expected a strict violation, got {other}"),
    };

    let duplicated = text.replacen("{\"_type\"", "{\"_type\":\"x\",\"_type\"", 1);
    assert_eq!(
        violation(duplicated.as_bytes()),
        (
            "/_type".to_owned(),
            Violation::DuplicateKey("_type".to_owned())
        )
    );
    let escaped = text.replacen(
        "{\"sha256\"",
        "{\"sha\\u0032\\u0035\\u0036\":\"x\",\"sha256\"",
        1,
    );
    assert_eq!(
        violation(escaped.as_bytes()).1,
        Violation::DuplicateKey("sha256".to_owned())
    );
    let mut with_bom = b"\xef\xbb\xbf".to_vec();
    with_bom.extend_from_slice(text.as_bytes());
    assert_eq!(strict(&with_bom), JsonError::ByteOrderMark);
    assert!(matches!(
        strict(format!("{text}{{}}").as_bytes()),
        JsonError::Syntax { .. }
    ));
    let sized = |size: &str| {
        text.replace(
            "{\"kind\":\"file\"}",
            &format!("{{\"kind\":\"file\",\"size\":{size}}}"),
        )
    };
    assert_eq!(
        violation(sized("26.0").as_bytes()),
        (
            "/predicate/artifact/size".to_owned(),
            Violation::NotAnInteger
        )
    );
    assert_eq!(
        violation(sized("-26").as_bytes()).1,
        Violation::NegativeNumber
    );
    assert_eq!(
        violation(sized("9007199254740992").as_bytes()).1,
        Violation::IntegerTooLarge
    );
    let named = text.replace("\"tool\"", "\"to\\u001bol\"");
    assert_eq!(
        violation(named.as_bytes()),
        (
            "/subject/0/name".to_owned(),
            Violation::ForbiddenCharacter { code: 0x1b }
        )
    );
    let deep = text.replacen(
        '{',
        &format!("{{\"x\":{}0{},", "[".repeat(70), "]".repeat(70)),
        1,
    );
    assert!(matches!(
        violation(deep.as_bytes()).1,
        Violation::TooDeep { max: 64 }
    ));

    let mut small = ParseOptions::default();
    small.limits.max_bytes = 16;
    assert!(matches!(
        parse_manifest(text.as_bytes(), &small),
        Err(ManifestError::Json(JsonError::TooLarge { max: 16, .. }))
    ));
}
