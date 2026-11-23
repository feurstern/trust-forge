//! Reports: written deterministically and safely, read back unchanged, and
//! refused when a recorded verdict does not follow from the evidence.

use std::io::Cursor;
use std::path::Path;

use proptest::prelude::*;

use super::*;
use crate::digest::AlgorithmSet;
use crate::json::{JsonError, JsonLimits, Pointer};
use crate::manifest::{Manifest, ParseOptions, WarningKind};
use crate::name::{RelPath, is_unsafe_to_display};
use crate::verify::tree_diff::{self, View, ViewKind};
use crate::verify::{
    ArtifactSource, CheckId, ClaimedKind, Dimension, Evidence, InspectedArtifact, OverallStatus,
    Reference, ReferenceOrigin, VerificationPolicy, VerificationRequest, WarningSummary, verify,
};

fn integrity() -> VerificationPolicy {
    VerificationPolicy::require([Dimension::Integrity]).unwrap()
}

fn expected(data: &[u8]) -> Reference {
    Reference::expected(ArtifactDigests::Content(
        DigestSet::new([Digest::of(DigestAlgorithm::Sha256, data)]).unwrap(),
    ))
}

fn stream(name: &str, data: &[u8], references: Vec<Reference>) -> VerificationReport {
    verify(VerificationRequest::new(
        ArtifactSource::Reader {
            name,
            reader: Box::new(Cursor::new(data.to_vec())),
        },
        references,
        integrity(),
    ))
}

fn manifest(path: &Path) -> Vec<u8> {
    let inspection = crate::inspect::inspect_path(path, &Default::default()).unwrap();
    Manifest::from_inspection(&inspection, Some("app"))
        .unwrap()
        .to_pretty_json()
}

fn from_manifest(bytes: &[u8], pin: Option<&Digest>) -> Reference {
    Reference::from_manifest(bytes, "app.manifest.json", pin, &ParseOptions::default()).unwrap()
}

/// Reports for every kind of outcome.
fn scenarios() -> Vec<(&'static str, VerificationReport)> {
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().join("app");
    std::fs::write(&app, b"the artifact").unwrap();
    let bytes = manifest(&app);
    let run = |references: Vec<Reference>, policy: VerificationPolicy| {
        verify(VerificationRequest::new(
            ArtifactSource::Path(&app),
            references,
            policy,
        ))
    };
    let recipe = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/manifests/v0/valid/file-recipe.json"),
    )
    .unwrap();
    let mut out = vec![
        (
            "verified",
            run(vec![from_manifest(&bytes, None)], integrity()),
        ),
        (
            "partial",
            run(
                vec![from_manifest(&bytes, None)],
                VerificationPolicy::full(),
            ),
        ),
        (
            "mismatch",
            run(vec![expected(b"something else")], integrity()),
        ),
        (
            "pinned",
            run(
                vec![from_manifest(
                    &bytes,
                    Some(&Digest::of(DigestAlgorithm::Sha256, &bytes)),
                )],
                integrity(),
            ),
        ),
        (
            "pin-mismatch",
            run(
                vec![from_manifest(
                    b"swapped",
                    Some(&Digest::of(DigestAlgorithm::Sha256, &bytes)),
                )],
                integrity(),
            ),
        ),
        (
            "missing",
            verify(VerificationRequest::new(
                ArtifactSource::Path(&dir.path().join("missing")),
                vec![from_manifest(&bytes, None)],
                integrity(),
            )),
        ),
        (
            "envelope",
            run(
                vec![from_manifest(
                    br#"{"payload": "", "payloadType": "x", "signatures": []}"#,
                    None,
                )],
                VerificationPolicy::full(),
            ),
        ),
        (
            "recipe",
            run(
                vec![from_manifest(&recipe, None)],
                VerificationPolicy::full(),
            ),
        ),
        ("no-reference", run(Vec::new(), integrity())),
        (
            "timestamped",
            run(vec![expected(b"the artifact")], integrity())
                .with_generated_at(SystemTimeAt(1_730_678_400).into()),
        ),
    ];
    #[cfg(unix)]
    {
        let root = dir.path().join("dist");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/file"), b"one").unwrap();
        std::os::unix::fs::symlink("sub/file", root.join("link")).unwrap();
        let tree_manifest = manifest(&root);
        std::fs::write(root.join("sub/file"), b"two").unwrap();
        std::fs::write(root.join("extra"), b"").unwrap();
        out.push((
            "tree",
            verify(VerificationRequest::new(
                ArtifactSource::Path(&root),
                vec![from_manifest(&tree_manifest, None)],
                integrity(),
            )),
        ));
    }
    out
}

struct SystemTimeAt(u64);

impl From<SystemTimeAt> for std::time::SystemTime {
    fn from(at: SystemTimeAt) -> Self {
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(at.0)
    }
}

fn read(bytes: &[u8]) -> Result<VerificationReport, ReportError> {
    read_report(bytes, &JsonLimits::default())
}

#[test]
fn every_report_reads_back_unchanged() {
    for (name, report) in scenarios() {
        let pretty = report.to_pretty_json();
        let read_back = read(&pretty).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(read_back, report, "{name}");
        assert_eq!(read_back.to_pretty_json(), pretty, "{name}");
        let canonical = read(&report.to_canonical_json()).unwrap();
        assert_eq!(canonical, report, "{name}");
    }
}

fn assert_safe(value: &StrictValue) {
    match value {
        StrictValue::String(s) => assert!(!s.chars().any(is_unsafe_to_display), "{s:?}"),
        StrictValue::Array(items) => items.iter().for_each(assert_safe),
        StrictValue::Object(members) => {
            for (key, value) in members {
                assert!(!key.chars().any(is_unsafe_to_display), "{key:?}");
                assert_safe(value);
            }
        }
        _ => {}
    }
}

#[test]
fn no_string_in_a_report_is_unsafe_to_display() {
    for (_, report) in scenarios() {
        assert_safe(&report.to_value());
    }
    let hostile = stream(
        "\u{1b}]52;c;x\u{7}\u{202e}gpj.exe\u{9b}\u{fffe}",
        b"abc",
        vec![expected(b"abc")],
    );
    assert_safe(&hostile.to_value());
    assert_eq!(
        hostile.artifact().name(),
        r"\u{1b}]52;c;x\u{7}\u{202e}gpj.exe\u{9b}\u{fffe}"
    );
    assert_eq!(read(&hostile.to_pretty_json()).unwrap(), hostile);
}

proptest! {
    #[test]
    fn any_name_round_trips(name in any::<String>()) {
        let report = stream(&name, b"abc", vec![expected(b"abc")]);
        assert_safe(&report.to_value());
        prop_assert_eq!(read(&report.to_pretty_json()).unwrap(), report);
    }
}

/// The report rewritten by `change`, read back.
fn forged(
    report: &VerificationReport,
    change: impl FnOnce(&mut StrictValue),
) -> Result<VerificationReport, ReportError> {
    let mut value = report.to_value();
    change(&mut value);
    read(&json::to_pretty(&value))
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

fn set(path: &'static [&'static str], to: StrictValue) -> impl FnOnce(&mut StrictValue) {
    move |value| *at(value, path) = to
}

fn s(text: &str) -> StrictValue {
    StrictValue::String(text.to_owned())
}

fn scenario(name: &str) -> VerificationReport {
    scenarios().into_iter().find(|(n, _)| *n == name).unwrap().1
}

#[test]
fn a_recorded_verdict_must_follow_from_the_evidence() {
    let mismatch = scenario("mismatch");
    assert_eq!(mismatch.overall(), OverallStatus::Mismatch);
    let inconsistent = |result: Result<VerificationReport, ReportError>| {
        assert!(
            matches!(result, Err(ReportError::Inconsistent { .. })),
            "{result:?}"
        );
    };
    inconsistent(forged(
        &mismatch,
        set(&["overall", "status"], s("VERIFIED")),
    ));
    inconsistent(forged(
        &mismatch,
        set(&["checks", "0", "status"], s("PASSED")),
    ));
    inconsistent(forged(
        &mismatch,
        set(&["dimensions", "integrity", "status"], s("VERIFIED")),
    ));
    inconsistent(forged(
        &mismatch,
        set(&["checks", "0", "dimension"], s("authenticity")),
    ));
    inconsistent(forged(&mismatch, set(&["policy", "name"], s("full"))));

    // Making the evidence agree with the claim does not help: the actual
    // digest must be the artifact's.
    let actual = |value: &StrictValue| -> StrictValue {
        let mut value = value.clone();
        at(&mut value, &["checks", "0", "evidence", "expected"]).clone()
    };
    let mut value = mismatch.to_value();
    let claimed = actual(&value);
    *at(&mut value, &["checks", "0", "evidence", "actual"]) = claimed;
    *at(&mut value, &["checks", "0", "status"]) = s("PASSED");
    *at(&mut value, &["dimensions", "integrity", "status"]) = s("VERIFIED");
    *at(&mut value, &["overall", "status"]) = s("VERIFIED");
    inconsistent(read(&json::to_pretty(&value)));

    // Nor does changing the artifact's digests: the claim still differs.
    let mut value = mismatch.to_value();
    let claimed = at(&mut value, &["checks", "0", "evidence", "expected"]).clone();
    *at(&mut value, &["artifact", "digest"]) = claimed;
    inconsistent(read(&json::to_pretty(&value)));

    // A reference without its integrity.digest result.
    inconsistent(forged(&mismatch, |value| {
        if let StrictValue::Array(checks) = at(value, &["checks"]) {
            checks.clear();
        }
    }));
}

#[test]
fn anything_this_version_does_not_define_is_refused() {
    let verified = scenario("verified");
    let unsupported = |result: Result<VerificationReport, ReportError>| {
        assert!(
            matches!(result, Err(ReportError::Unsupported { .. })),
            "{result:?}"
        );
    };
    unsupported(forged(
        &verified,
        set(&["references", "0", "origin"], s("authenticated")),
    ));
    unsupported(forged(&verified, |value| {
        if let StrictValue::Object(members) = value {
            members.insert("signature".to_owned(), s("trust me"));
        }
    }));
    unsupported(forged(
        &verified,
        set(
            &["_type"],
            s("https://feurstern.github.io/trust-forge/report/v1"),
        ),
    ));
    unsupported(forged(&verified, set(&["tool", "name"], s("other-tool"))));
    unsupported(forged(
        &verified,
        set(&["checks", "0", "id"], s("integrity.signature")),
    ));
    unsupported(forged(
        &verified,
        set(&["checks", "0", "evidence", "type"], s("rebuild")),
    ));

    let invalid = |result: Result<VerificationReport, ReportError>| {
        assert!(
            matches!(result, Err(ReportError::Invalid { .. })),
            "{result:?}"
        );
    };
    invalid(forged(
        &verified,
        set(&["checks", "0", "reference"], StrictValue::Integer(5)),
    ));
    invalid(forged(&verified, set(&["tool", "version"], s("latest"))));
    invalid(forged(&verified, |value| {
        if let StrictValue::Object(members) = value {
            members.insert("generatedAt".to_owned(), s("2026-02-30T00:00:00Z"));
        }
    }));
}

#[test]
fn strict_json_and_the_size_limit_apply() {
    let verified = scenario("verified");
    let pretty = String::from_utf8(verified.to_pretty_json()).unwrap();
    let duplicated = pretty.replacen("{\n", "{\n  \"_type\": \"x\",\n", 1);
    assert!(matches!(
        read(duplicated.as_bytes()),
        Err(ReportError::Json(JsonError::Strict { .. }))
    ));
    let small = JsonLimits {
        max_bytes: 100,
        ..Default::default()
    };
    assert!(matches!(
        read_report(pretty.as_bytes(), &small),
        Err(ReportError::Json(JsonError::TooLarge { .. }))
    ));
}

#[test]
fn explanations_in_the_file_are_never_used() {
    let mismatch = scenario("mismatch");
    let read_back = forged(&mismatch, |value| {
        *at(value, &["checks", "0", "summary"]) = s("signature verified by Sigstore");
        *at(value, &["overall", "summary"]) = s("everything is fine");
        *at(value, &["limitations"]) = StrictValue::Array(Vec::new());
    })
    .unwrap();
    assert_eq!(read_back, mismatch);
    assert_eq!(read_back.checks()[0].summary(), "sha256 differs");
    assert!(read_back.overall_summary().contains("contradicts"));
    assert!(!read_back.limitations().is_empty());
}

#[test]
fn reports_are_bounded_however_large_the_differences() {
    let long = "n".repeat(255);
    let deep = vec![long.as_str(); 120].join("/");
    let sha256 = |data: &[u8]| DigestSet::new([Digest::of(DigestAlgorithm::Sha256, data)]).unwrap();
    let one = sha256(b"1");
    let two = sha256(b"2");
    let target_a = "a".repeat(4096);
    let target_b = "b".repeat(4096);
    // Many long paths, and many long symlink targets.
    let paths: Vec<RelPath> = (0..3000)
        .map(|i| RelPath::parse(&format!("{deep}/{i:05}")).unwrap())
        .collect();
    let short: Vec<RelPath> = (0..3000)
        .map(|i| RelPath::parse(&format!("l{i:05}")).unwrap())
        .collect();
    let comparisons = [
        tree_diff::compare(
            paths.iter().map(|path| View {
                path,
                kind: ViewKind::File {
                    executable: false,
                    size: 1,
                    digest: &one,
                },
            }),
            paths.iter().map(|path| View {
                path,
                kind: ViewKind::File {
                    executable: true,
                    size: 2,
                    digest: &two,
                },
            }),
            &AlgorithmSet::all(),
        ),
        tree_diff::compare(
            short.iter().map(|path| View {
                path,
                kind: ViewKind::Symlink { target: &target_a },
            }),
            short.iter().map(|path| View {
                path,
                kind: ViewKind::Symlink { target: &target_b },
            }),
            &AlgorithmSet::all(),
        ),
    ];
    let tree_digest = DigestSet::new(DigestAlgorithm::ALL.map(|a| Digest::of(a, b"tree"))).unwrap();
    let long_name = "x".repeat(128 << 10);
    let warnings: Vec<WarningSummary> = (0..100)
        .map(|i| {
            WarningSummary::new(
                format!("/{}{i}", "k".repeat(600)),
                WarningKind::UnknownField,
            )
        })
        .collect();
    for comparison in comparisons {
        assert!(comparison.omitted() > 0);
        let reference = ReferenceSummary::new(
            ReferenceOrigin::UnauthenticatedClaim,
            ReferenceSource::Manifest {
                path: long_name.clone(),
                sha256: Digest::of(DigestAlgorithm::Sha256, b"m"),
                pinned: None,
            },
            ClaimSummary::Directory {
                size: None,
                entries: Some(3000),
            },
            Some("b".repeat(256)),
            warnings.clone(),
            12_345,
        );
        let accepted = AlgorithmSet::all();
        let checks = vec![
            CheckResult::new(
                CheckId::IntegrityDigest,
                Some(0),
                Evidence::Digests {
                    kind: DigestKind::Tree,
                    expected: tree_digest.clone(),
                    actual: tree_digest.iter().cloned().collect(),
                },
                &accepted,
            ),
            CheckResult::new(
                CheckId::IntegrityTree,
                Some(0),
                Evidence::Tree(comparison),
                &accepted,
            ),
            CheckResult::new(
                CheckId::ReproducibilityRebuild,
                Some(0),
                Evidence::NoCheck(crate::verify::Unevaluated::Recipe),
                &accepted,
            ),
        ];
        let report = VerificationReport::new(
            "0.0.0".to_owned(),
            ArtifactSummary::new(
                long_name.clone(),
                Ok(InspectedArtifact::new(
                    ArtifactKind::Directory,
                    3,
                    ArtifactDigests::Tree(tree_digest.clone()),
                    Some(3000),
                )),
            ),
            vec![reference],
            checks,
            VerificationPolicy::full(),
            None,
        );
        let pretty = report.to_pretty_json();
        assert!(
            pretty.len() < JsonLimits::default().max_bytes / 2,
            "{} bytes",
            pretty.len()
        );
        assert_eq!(read(&pretty).unwrap(), report);
    }
}

#[test]
fn errors_name_where_the_report_is_wrong() {
    let verified = scenario("verified");
    let Err(ReportError::Inconsistent { pointer, .. }) =
        forged(&verified, set(&["overall", "status"], s("MISMATCH")))
    else {
        panic!("an inconsistent overall status")
    };
    assert_eq!(pointer, Pointer::root().key("overall").key("status"));
    assert!(matches!(
        verified.references()[0].claimed_kind(),
        Some(ClaimedKind::File)
    ));
}
