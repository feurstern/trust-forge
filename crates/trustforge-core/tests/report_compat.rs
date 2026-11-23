//! Compatibility of report version 0 with its fixtures.
//!
//! - `fixtures/reports/v0/valid/` holds reports written by `trustforge verify
//!   --format json` from fixed inputs (`scripts/report-fixtures.sh`). Each one
//!   must keep reading, and be written back byte for byte: a change to the
//!   report format shows up here first.
//! - `fixtures/reports/v0/invalid/` holds forgeries, each derived here from a
//!   valid fixture by changing one thing. Each must be refused, at the place
//!   given. After the valid fixtures change, rewrite these with
//!   `TRUSTFORGE_UPDATE_GOLDEN=1 cargo test -p trustforge-core --test
//!   report_compat` and review the difference.

// clippy.toml allows unwrap and expect only inside #[test] functions; the
// helpers in this test crate panic on setup failures on purpose.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use trustforge_core::json::{self, JsonError, JsonLimits, StrictValue};
use trustforge_core::report::{ReportError, read_report};
use trustforge_core::verify::OverallStatus;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/reports/v0")
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

fn read(dir: &str, name: &str) -> Vec<u8> {
    fs::read(fixtures().join(dir).join(name)).unwrap()
}

#[test]
fn every_valid_fixture_reads_and_is_written_back_unchanged() {
    use OverallStatus::*;
    let expected = [
        ("envelope.json", Unverified),
        ("mismatch.json", Mismatch),
        ("missing.json", VerificationFailed),
        ("no-match-for-kind.json", Mismatch),
        ("partial.json", PartiallyVerified),
        ("pin-mismatch.json", Mismatch),
        ("pinned.json", Verified),
        ("recipe.json", PartiallyVerified),
        ("stream.json", Verified),
        ("tree-mismatch.json", Mismatch),
        ("tree-verified.json", Verified),
        ("two-references.json", Verified),
        ("unsupported.json", Unverified),
        ("verified.json", Verified),
    ];
    let names: Vec<&str> = expected.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        fixture_names("valid"),
        names,
        "every fixture has expectations"
    );
    for (name, overall) in expected {
        let bytes = read("valid", name);
        let report =
            read_report(&bytes, &JsonLimits::default()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(report.overall(), overall, "{name}");
        assert_eq!(
            String::from_utf8(report.to_pretty_json()).unwrap(),
            String::from_utf8(bytes).unwrap(),
            "{name}: written back byte for byte"
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    Json,
    Invalid,
    Unsupported,
    Inconsistent,
}

/// How a forgery changes its valid fixture.
enum Forge {
    Value(fn(&mut StrictValue)),
    Text(fn(String) -> String),
}

/// A forgery: its file name, the valid fixture it changes, how, and where it
/// must be refused.
struct Forgery {
    name: &'static str,
    base: &'static str,
    forge: Forge,
    refusal: Refusal,
    pointer: &'static str,
}

/// The member at `path`: object keys, or array indices.
fn at<'v>(mut value: &'v mut StrictValue, path: &[&str]) -> &'v mut StrictValue {
    for step in path {
        value = match value {
            StrictValue::Object(members) => members.get_mut(*step).unwrap(),
            StrictValue::Array(items) => items.get_mut(step.parse::<usize>().unwrap()).unwrap(),
            _ => panic!("no {step}"),
        };
    }
    value
}

fn text(s: &str) -> StrictValue {
    StrictValue::String(s.to_owned())
}

/// Removes every check result with the identifier `id`.
fn remove_checks(value: &mut StrictValue, id: &str) {
    let StrictValue::Array(checks) = at(value, &["checks"]) else {
        panic!("checks is an array")
    };
    let before = checks.len();
    checks.retain(|check| match check {
        StrictValue::Object(members) => members.get("id") != Some(&text(id)),
        _ => true,
    });
    assert!(checks.len() < before, "there was a {id} result");
}

/// The index of the first check result with the identifier `id`.
fn check_index(value: &mut StrictValue, id: &str) -> String {
    let StrictValue::Array(checks) = at(value, &["checks"]) else {
        panic!("checks is an array")
    };
    checks
        .iter()
        .position(|check| matches!(check, StrictValue::Object(m) if m.get("id") == Some(&text(id))))
        .unwrap()
        .to_string()
}

fn forgeries() -> Vec<Forgery> {
    use Refusal::*;
    let forgery = |name, base, forge, refusal, pointer| Forgery {
        name,
        base,
        forge,
        refusal,
        pointer,
    };
    vec![
        forgery(
            "authenticated-origin.json",
            "verified.json",
            Forge::Value(|v| *at(v, &["references", "0", "origin"]) = text("authenticated")),
            Unsupported,
            "/references/0/origin",
        ),
        forgery(
            // Parsers disagree on which of two values for one key wins.
            "duplicate-key.json",
            "verified.json",
            Forge::Text(|t| {
                t.replacen(
                    "\"status\": \"VERIFIED\",\n    \"summary\": \"policy",
                    "\"status\": \"MISMATCH\",\n    \"status\": \"VERIFIED\",\n    \"summary\": \"policy",
                    1,
                )
            }),
            Json,
            "/overall/status",
        ),
        forgery(
            "forged-artifact-digest.json",
            "mismatch.json",
            Forge::Value(|v| {
                let claimed = at(v, &["checks", "0", "evidence", "expected"]).clone();
                *at(v, &["artifact", "digest"]) = claimed;
            }),
            Inconsistent,
            "/checks/0/evidence",
        ),
        forgery(
            "forged-check-status.json",
            "mismatch.json",
            Forge::Value(|v| *at(v, &["checks", "0", "status"]) = text("PASSED")),
            Inconsistent,
            "/checks/0/status",
        ),
        forgery(
            "forged-dimension.json",
            "mismatch.json",
            Forge::Value(|v| {
                *at(v, &["dimensions", "integrity", "status"]) = text("VERIFIED");
                *at(v, &["dimensions", "integrity", "reason"]) = StrictValue::Null;
            }),
            Inconsistent,
            "/dimensions/integrity/status",
        ),
        forgery(
            // The evidence made to agree with the claim, and every verdict
            // with it.
            "forged-evidence.json",
            "mismatch.json",
            Forge::Value(|v| {
                let claimed = at(v, &["checks", "0", "evidence", "expected"]).clone();
                *at(v, &["checks", "0", "evidence", "actual"]) = claimed;
                *at(v, &["checks", "0", "status"]) = text("PASSED");
                *at(v, &["dimensions", "integrity", "status"]) = text("VERIFIED");
                *at(v, &["dimensions", "integrity", "reason"]) = StrictValue::Null;
                *at(v, &["overall", "status"]) = text("VERIFIED");
            }),
            Inconsistent,
            "/checks/0/evidence",
        ),
        forgery(
            "forged-overall.json",
            "mismatch.json",
            Forge::Value(|v| *at(v, &["overall", "status"]) = text("VERIFIED")),
            Inconsistent,
            "/overall/status",
        ),
        forgery(
            "forged-pin.json",
            "pin-mismatch.json",
            Forge::Value(|v| {
                let actual = at(v, &["references", "0", "source", "sha256"]).clone();
                let mut pinned = std::collections::BTreeMap::new();
                pinned.insert("sha256".to_owned(), actual);
                *at(v, &["checks", "0", "evidence", "pinned"]) = StrictValue::Object(pinned);
                *at(v, &["checks", "0", "status"]) = text("PASSED");
            }),
            Inconsistent,
            "/checks/0/evidence",
        ),
        forgery(
            // A listing comparison that claims more entries than there are.
            "forged-tree-entries.json",
            "tree-verified.json",
            Forge::Value(|v| {
                let i = check_index(v, "integrity.tree");
                *at(v, &["checks", &i, "evidence", "entries"]) = StrictValue::Integer(1000);
            }),
            Inconsistent,
            "/checks/2/evidence",
        ),
        forgery(
            // A passing comparison of a listing with another number of
            // entries than the artifact has.
            "forged-tree-listing.json",
            "tree-verified.json",
            Forge::Value(|v| {
                *at(v, &["references", "0", "claim", "entries"]) = StrictValue::Integer(1000);
            }),
            Inconsistent,
            "/checks/2/evidence",
        ),
        forgery(
            "missing-digest-result.json",
            "verified.json",
            Forge::Value(|v| remove_checks(v, "integrity.digest")),
            Inconsistent,
            "/checks",
        ),
        forgery(
            // The result for an unverifiable signature, removed.
            "missing-envelope-result.json",
            "envelope.json",
            Forge::Value(|v| remove_checks(v, "authenticity.signature")),
            Inconsistent,
            "/checks",
        ),
        forgery(
            // The result for an unrebuildable recipe, removed.
            "missing-recipe-result.json",
            "recipe.json",
            Forge::Value(|v| remove_checks(v, "reproducibility.rebuild")),
            Inconsistent,
            "/checks",
        ),
        forgery(
            "missing-size-result.json",
            "verified.json",
            Forge::Value(|v| remove_checks(v, "integrity.size")),
            Inconsistent,
            "/checks",
        ),
        forgery(
            // A failed listing comparison, removed, and the verdicts raised.
            "missing-tree-result.json",
            "tree-mismatch.json",
            Forge::Value(|v| {
                remove_checks(v, "integrity.tree");
                *at(v, &["dimensions", "integrity", "status"]) = text("VERIFIED");
                *at(v, &["overall", "status"]) = text("VERIFIED");
            }),
            Inconsistent,
            "/checks",
        ),
        forgery(
            "other-tool.json",
            "verified.json",
            Forge::Value(|v| *at(v, &["tool", "name"]) = text("other-tool")),
            Unsupported,
            "/tool/name",
        ),
        forgery(
            "other-version.json",
            "verified.json",
            Forge::Value(|v| {
                *at(v, &["_type"]) = text("https://feurstern.github.io/trust-forge/report/v1");
            }),
            Unsupported,
            "/_type",
        ),
        forgery(
            "policy-name.json",
            "verified.json",
            Forge::Value(|v| *at(v, &["policy", "name"]) = text("full")),
            Inconsistent,
            "/policy/name",
        ),
        forgery(
            "reference-out-of-range.json",
            "verified.json",
            Forge::Value(|v| *at(v, &["checks", "0", "reference"]) = StrictValue::Integer(3)),
            Invalid,
            "/checks/0/reference",
        ),
        forgery(
            "unknown-check.json",
            "verified.json",
            Forge::Value(|v| *at(v, &["checks", "0", "id"]) = text("integrity.signature")),
            Unsupported,
            "/checks/0/id",
        ),
        forgery(
            "unknown-field.json",
            "verified.json",
            Forge::Value(|v| {
                let StrictValue::Object(members) = v else {
                    panic!()
                };
                members.insert("signature".to_owned(), text("MEUCIQ…"));
            }),
            Unsupported,
            "/signature",
        ),
        forgery(
            // A reason this version writes without a value, given one.
            "unsupported-reason-with-text.json",
            "envelope.json",
            Forge::Value(|v| {
                *at(v, &["references", "0", "claim", "value"]) =
                    text("signature verified by TrustForge");
            }),
            Unsupported,
            "/references/0/claim/reason",
        ),
        forgery(
            "wrong-dimension.json",
            "verified.json",
            Forge::Value(|v| *at(v, &["checks", "0", "dimension"]) = text("authenticity")),
            Inconsistent,
            "/checks/0/dimension",
        ),
    ]
}

fn forged_bytes(forgery: &Forgery) -> Vec<u8> {
    let base = read("valid", forgery.base);
    match forgery.forge {
        Forge::Value(change) => {
            let mut value = json::parse(&base, &JsonLimits::default()).unwrap();
            change(&mut value);
            json::to_pretty(&value)
        }
        Forge::Text(change) => {
            let changed = change(String::from_utf8(base.clone()).unwrap());
            assert_ne!(changed.as_bytes(), base, "{}: forged", forgery.name);
            changed.into_bytes()
        }
    }
}

#[test]
fn every_invalid_fixture_is_a_forgery_of_a_valid_one() {
    let forgeries = forgeries();
    let update = std::env::var_os("TRUSTFORGE_UPDATE_GOLDEN").is_some();
    if update {
        for name in fixture_names("invalid") {
            fs::remove_file(fixtures().join("invalid").join(name)).unwrap();
        }
    }
    for forgery in &forgeries {
        let bytes = forged_bytes(forgery);
        let path = fixtures().join("invalid").join(forgery.name);
        if update {
            fs::write(&path, &bytes).unwrap();
        } else {
            assert_eq!(
                fs::read(&path).unwrap_or_default(),
                bytes,
                "{} is not derived from {}: run with TRUSTFORGE_UPDATE_GOLDEN=1",
                forgery.name,
                forgery.base
            );
        }
    }
    let names: Vec<&str> = forgeries.iter().map(|f| f.name).collect();
    assert_eq!(fixture_names("invalid"), names, "every fixture is derived");
}

#[test]
fn every_invalid_fixture_is_refused_where_expected() {
    for forgery in forgeries() {
        let name = forgery.name;
        let error = read_report(&read("invalid", name), &JsonLimits::default()).expect_err(name);
        let (kind, at) = match &error {
            ReportError::Json(JsonError::Strict { pointer, .. }) => {
                (Refusal::Json, pointer.to_rfc6901())
            }
            ReportError::Invalid { pointer, .. } => (Refusal::Invalid, pointer.to_rfc6901()),
            ReportError::Unsupported { pointer, .. } => {
                (Refusal::Unsupported, pointer.to_rfc6901())
            }
            ReportError::Inconsistent { pointer, .. } => {
                (Refusal::Inconsistent, pointer.to_rfc6901())
            }
            other => panic!("{name}: {other}"),
        };
        assert_eq!(
            (kind, at.as_str()),
            (forgery.refusal, forgery.pointer),
            "{name}: {error}"
        );
    }
}
