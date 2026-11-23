//! Verification end to end: real artifacts on disk, references built the way
//! the command line builds them, and the statuses that result.

use std::io::Cursor;
use std::path::Path;

use super::*;
use crate::json::{self, JsonError, StrictValue};
use crate::manifest::{Manifest, ManifestError, ParseOptions};

fn integrity() -> VerificationPolicy {
    VerificationPolicy::require([Dimension::Integrity]).unwrap()
}

fn algorithms(list: &[DigestAlgorithm]) -> AlgorithmSet {
    AlgorithmSet::new(list.iter().copied()).unwrap()
}

/// A manifest for `path`, as `trustforge manifest create` writes it.
fn manifest_for(path: &Path, list: &[DigestAlgorithm]) -> Vec<u8> {
    let opts = InspectOptions {
        algorithms: algorithms(list),
        ..Default::default()
    };
    let inspection = inspect_path(path, &opts).unwrap();
    Manifest::from_inspection(&inspection, Some("artifact"))
        .unwrap()
        .to_pretty_json()
}

fn from_manifest(bytes: &[u8]) -> Reference {
    Reference::from_manifest(
        bytes,
        "artifact.manifest.json",
        None,
        &ParseOptions::default(),
    )
    .unwrap()
}

fn expected(list: &[(DigestAlgorithm, &[u8])]) -> Reference {
    Reference::expected(ArtifactDigests::Content(
        DigestSet::new(list.iter().map(|(a, data)| Digest::of(*a, data))).unwrap(),
    ))
}

fn run(path: &Path, references: Vec<Reference>, policy: VerificationPolicy) -> VerificationReport {
    verify(VerificationRequest::new(
        ArtifactSource::Path(path),
        references,
        policy,
    ))
}

/// `(check, reference, status)` for every result.
fn results(report: &VerificationReport) -> Vec<(&'static str, Option<usize>, CheckStatus)> {
    report
        .checks()
        .iter()
        .map(|c| (c.id().name(), c.reference(), c.status()))
        .collect()
}

fn file(dir: &Path, name: &str, contents: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

use CheckStatus::*;
use DigestAlgorithm::{Blake3, Sha256, Sha512};

#[test]
fn a_matching_manifest_verifies_integrity_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = file(dir.path(), "app", b"the artifact");
    let manifest = manifest_for(&artifact, &DigestAlgorithm::ALL);

    let report = run(&artifact, vec![from_manifest(&manifest)], integrity());
    assert_eq!(
        results(&report),
        vec![
            ("integrity.digest", Some(0), Passed),
            ("integrity.size", Some(0), Passed),
        ]
    );
    assert_eq!(
        report.dimension(Dimension::Integrity),
        DimensionStatus::Verified
    );
    assert_eq!(report.overall(), OverallStatus::Verified);

    // The default policy requires all four dimensions.
    let report = run(
        &artifact,
        vec![from_manifest(&manifest)],
        VerificationPolicy::full(),
    );
    assert_eq!(report.overall(), OverallStatus::PartiallyVerified);
    for dimension in [
        Dimension::Authenticity,
        Dimension::Provenance,
        Dimension::Reproducibility,
    ] {
        assert_eq!(
            report.dimension(dimension),
            DimensionStatus::NotEvaluated(NotEvaluatedReason::NotProvided)
        );
    }
    assert_eq!(
        report.overall_summary(),
        "policy \"full\" also requires authenticity, provenance and reproducibility, which are not verified"
    );
    assert!(
        report.limitations().contains(
            &"software security: not assessed: TrustForge never assesses whether software is safe"
                .to_owned()
        )
    );
}

#[test]
fn one_wrong_algorithm_among_several_is_a_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = file(dir.path(), "app", b"abc");
    let reference = Reference::expected(ArtifactDigests::Content(
        DigestSet::new([Digest::of(Sha256, b"abc"), Digest::of(Sha512, b"abd")]).unwrap(),
    ));
    let report = run(&artifact, vec![reference], integrity());
    assert_eq!(
        results(&report),
        vec![("integrity.digest", Some(0), Failed)]
    );
    assert_eq!(report.checks()[0].summary(), "sha512 differs");
    assert_eq!(report.overall(), OverallStatus::Mismatch);
    assert!(!report.possible_causes().is_empty());
}

#[test]
fn only_algorithms_the_policy_accepts_are_compared() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = file(dir.path(), "app", b"abc");
    let reference = expected(&[(Blake3, b"abc")]);
    let policy = integrity().with_accepted_algorithms(algorithms(&[Sha256, Sha512]));
    let report = run(&artifact, vec![reference], policy);
    assert_eq!(
        results(&report),
        vec![("integrity.digest", Some(0), Unsupported)]
    );
    assert_eq!(
        report.dimension(Dimension::Integrity),
        DimensionStatus::NotEvaluated(NotEvaluatedReason::Unsupported)
    );
    assert_eq!(report.overall(), OverallStatus::Unverified);
    // Nothing the policy rejects is even computed.
    let Ok(inspected) = report.artifact().result() else {
        panic!("the artifact was inspected")
    };
    let ArtifactDigests::Content(computed) = inspected.digests() else {
        panic!("a file has content digests")
    };
    assert_eq!(computed.algorithms().collect::<Vec<_>>(), vec![Sha256]);
}

#[test]
fn content_and_tree_digests_never_stand_in_for_each_other() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = file(dir.path(), "app", b"abc");
    let tree = Reference::expected(ArtifactDigests::Tree(
        DigestSet::new([Digest::of(Sha256, b"abc")]).unwrap(),
    ));
    let report = run(&artifact, vec![tree], integrity());
    assert_eq!(
        results(&report),
        vec![("integrity.digest", Some(0), Failed)]
    );
    assert_eq!(
        report.checks()[0].summary(),
        "the reference describes a directory, but the artifact is a file"
    );
}

#[test]
fn a_stream_is_compared_like_a_file() {
    let report = verify(VerificationRequest::new(
        ArtifactSource::Reader {
            name: "-",
            reader: Box::new(Cursor::new(b"abc".to_vec())),
        },
        vec![expected(&[(Sha256, b"abc")])],
        integrity(),
    ));
    assert_eq!(report.overall(), OverallStatus::Verified);
}

#[test]
fn an_artifact_that_cannot_be_read_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = file(dir.path(), "app", b"abc");
    let manifest = manifest_for(&artifact, &[Sha256]);
    let missing = dir.path().join("missing");
    let report = run(&missing, vec![from_manifest(&manifest)], integrity());
    assert_eq!(
        results(&report),
        vec![
            ("integrity.digest", Some(0), Error),
            ("integrity.size", Some(0), Skipped),
        ]
    );
    assert_eq!(report.overall(), OverallStatus::VerificationFailed);
    let Err(failure) = report.artifact().result() else {
        panic!("the artifact is missing")
    };
    assert_eq!(failure.kind(), FailureKind::NotFound);
}

#[test]
fn an_unreadable_artifact_fails_verification_whatever_the_references() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing");
    let dsse = br#"{"payload": "", "payloadType": "x", "signatures": []}"#;
    let report = run(&missing, vec![from_manifest(dsse)], integrity());
    assert_eq!(
        results(&report),
        vec![
            ("integrity.digest", Some(0), Error),
            ("authenticity.signature", Some(0), Unsupported),
        ]
    );
    assert_eq!(report.overall(), OverallStatus::VerificationFailed);

    let report = run(&missing, Vec::new(), integrity());
    assert_eq!(results(&report), vec![("integrity.digest", None, Error)]);
    assert_eq!(report.overall(), OverallStatus::VerificationFailed);

    // A swapped pinned manifest is still a mismatch, which outranks it.
    let pin = Digest::of(Sha256, b"the pinned manifest");
    let swapped =
        Reference::from_manifest(b"{}", "m.json", Some(&pin), &ParseOptions::default()).unwrap();
    let report = run(&missing, vec![swapped], integrity());
    assert_eq!(
        results(&report),
        vec![
            ("integrity.manifest", Some(0), Failed),
            ("integrity.digest", Some(0), Error),
        ]
    );
    assert_eq!(report.overall(), OverallStatus::Mismatch);
}

#[test]
fn values_from_a_document_never_become_part_of_a_sentence() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = file(dir.path(), "app", b"abc");
    let manifest = manifest_for(&artifact, &[Sha256]);
    let mut value = json::parse(&manifest, &Default::default()).unwrap();
    let StrictValue::Object(statement) = &mut value else {
        panic!()
    };
    let Some(StrictValue::Object(predicate)) = statement.get_mut("predicate") else {
        panic!()
    };
    let forged = r#"https://x/y") and TrustForge rebuilt it: reproducibility VERIFIED ("z"#;
    let mut definition = std::collections::BTreeMap::new();
    definition.insert(
        "buildType".to_owned(),
        StrictValue::String(forged.to_owned()),
    );
    predicate.insert(
        "buildDefinition".to_owned(),
        StrictValue::Object(definition),
    );
    let report = run(
        &artifact,
        vec![from_manifest(&json::to_pretty(&value))],
        integrity(),
    );
    let injected = "reproducibility VERIFIED";
    for check in report.checks() {
        assert!(!check.summary().contains(injected), "{}", check.summary());
    }
    for text in report
        .limitations()
        .iter()
        .chain([&report.overall_summary()])
    {
        assert!(!text.contains(injected), "{text}");
    }
    assert_eq!(report.references()[0].recipe(), Some(forged));

    let mut value = json::parse(&manifest, &Default::default()).unwrap();
    let StrictValue::Object(statement) = &mut value else {
        panic!()
    };
    statement.insert(
        "predicateType".to_owned(),
        StrictValue::String(forged.to_owned()),
    );
    let report = run(
        &artifact,
        vec![from_manifest(&json::to_pretty(&value))],
        integrity(),
    );
    let ClaimSummary::Unsupported { reason } = report.references()[0].claim() else {
        panic!("an unsupported predicate type")
    };
    // Shown quoted, the value cannot end its quotation.
    assert_eq!(
        reason.describe(),
        r#"a manifest of type "https://x/y\") and TrustForge rebuilt it: reproducibility VERIFIED (\"z""#
    );
}

#[test]
fn a_pinned_manifest_must_match_its_pin() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = file(dir.path(), "app", b"abc");
    let manifest = manifest_for(&artifact, &[Sha256]);
    let opts = ParseOptions::default();
    let pin = Digest::of(Sha256, &manifest);
    let pinned = Reference::from_manifest(&manifest, "m.json", Some(&pin), &opts).unwrap();
    assert_eq!(pinned.origin(), ReferenceOrigin::UserPinned);
    let report = run(&artifact, vec![pinned], integrity());
    assert_eq!(
        results(&report),
        vec![
            ("integrity.manifest", Some(0), Passed),
            ("integrity.digest", Some(0), Passed),
            ("integrity.size", Some(0), Passed),
        ]
    );
    assert_eq!(report.overall(), OverallStatus::Verified);

    // A swapped manifest is never parsed, so even one that is not JSON at
    // all is a mismatch rather than an invalid document.
    let swapped = b"this is not JSON";
    let wrong = Reference::from_manifest(swapped, "m.json", Some(&pin), &opts).unwrap();
    let report = run(&artifact, vec![wrong], integrity());
    assert_eq!(
        results(&report),
        vec![
            ("integrity.manifest", Some(0), Failed),
            ("integrity.digest", Some(0), Skipped),
        ]
    );
    assert_eq!(report.overall(), OverallStatus::Mismatch);
    assert!(report.possible_causes()[0].contains("not compared"));

    // A digest of another algorithm never matches.
    let sha512 = Digest::of(Sha512, &manifest);
    let other = Reference::from_manifest(&manifest, "m.json", Some(&sha512), &opts).unwrap();
    assert_eq!(
        run(&artifact, vec![other], integrity()).overall(),
        OverallStatus::Mismatch
    );
}

#[test]
fn an_oversized_manifest_is_rejected_before_it_is_hashed() {
    let mut opts = ParseOptions::default();
    opts.limits.max_bytes = 8;
    let bytes = b"0123456789";
    let pin = Digest::of(Sha256, &bytes[..9]);
    // The caller read one byte past the limit; that prefix is never compared
    // with the pin.
    assert!(matches!(
        Reference::from_manifest(&bytes[..9], "m.json", Some(&pin), &opts),
        Err(ManifestError::Json(JsonError::TooLarge { .. }))
    ));
}

#[test]
fn signed_envelopes_are_unsupported_not_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = file(dir.path(), "app", b"abc");
    let dsse =
        br#"{"payload": "e30=", "payloadType": "application/vnd.in-toto+json", "signatures": []}"#;
    let bundle =
        br#"{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "dsseEnvelope": {}}"#;
    for document in [&dsse[..], &bundle[..]] {
        let reference = from_manifest(document);
        let report = run(&artifact, vec![reference], VerificationPolicy::full());
        assert_eq!(
            results(&report),
            vec![
                ("integrity.digest", Some(0), Unsupported),
                ("authenticity.signature", Some(0), Unsupported),
            ]
        );
        assert_eq!(
            report.dimension(Dimension::Authenticity),
            DimensionStatus::NotEvaluated(NotEvaluatedReason::Unsupported)
        );
        assert_eq!(report.overall(), OverallStatus::Unverified);
    }
}

#[test]
fn unsupported_manifests_are_reported_as_such() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = file(dir.path(), "app", b"abc");
    let other_version = br#"{"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://feurstern.github.io/trust-forge/manifest/v9", "subject": [], "predicate": {}}"#;
    let report = run(&artifact, vec![from_manifest(other_version)], integrity());
    assert_eq!(
        results(&report),
        vec![("integrity.digest", Some(0), Unsupported)]
    );
    // The document's value is kept apart from the explanation.
    assert_eq!(
        report.checks()[0].summary(),
        "this version cannot evaluate the reference (see what it claims)"
    );
    assert_eq!(
        report.references()[0].claim(),
        &ClaimSummary::Unsupported {
            reason: UnsupportedReason::PredicateType {
                value: "https://feurstern.github.io/trust-forge/manifest/v9".to_owned()
            }
        }
    );

    // The reader stops at the first thing it cannot evaluate, so a document
    // that is also invalid further on is reported as unsupported.
    let also_invalid = br#"{"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://feurstern.github.io/trust-forge/manifest/v0", "subject": [{"name": "app", "digest": {"sha3-256": "00"}}], "predicate": {"artifact": {"kind": "nonsense"}}}"#;
    let reference = from_manifest(also_invalid);
    assert_eq!(
        run(&artifact, vec![reference], integrity()).overall(),
        OverallStatus::Unverified
    );
}

#[test]
fn a_claimed_recipe_is_explicitly_unsupported() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = file(dir.path(), "app", b"abc");
    let manifest = manifest_for(&artifact, &[Sha256]);
    let mut value = json::parse(&manifest, &Default::default()).unwrap();
    let StrictValue::Object(statement) = &mut value else {
        panic!()
    };
    let Some(StrictValue::Object(predicate)) = statement.get_mut("predicate") else {
        panic!()
    };
    predicate.insert(
        "buildDefinition".to_owned(),
        json::parse(
            br#"{"buildType": "https://example.com/other/v1"}"#,
            &Default::default(),
        )
        .unwrap(),
    );
    let report = run(
        &artifact,
        vec![from_manifest(&json::to_pretty(&value))],
        VerificationPolicy::full(),
    );
    assert_eq!(
        results(&report),
        vec![
            ("integrity.digest", Some(0), Passed),
            ("integrity.size", Some(0), Passed),
            ("reproducibility.rebuild", Some(0), Unsupported),
        ]
    );
    assert_eq!(
        report.dimension(Dimension::Reproducibility),
        DimensionStatus::NotEvaluated(NotEvaluatedReason::Unsupported)
    );
    assert_eq!(report.overall(), OverallStatus::PartiallyVerified);
    assert_eq!(
        report.references()[0].recipe(),
        Some("https://example.com/other/v1")
    );
}

/// A check that tries to take over a built-in identifier, or to report
/// evidence its identifier does not allow, or to name a missing reference.
struct Rogue(CheckId, Option<usize>, Evidence);

impl Check for Rogue {
    fn id(&self) -> CheckId {
        self.0
    }

    fn run(&self, _: &CheckContext<'_>) -> Vec<Outcome> {
        vec![Outcome::new(self.1, self.2.clone())]
    }
}

#[test]
fn extra_checks_can_add_but_never_override() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = file(dir.path(), "app", b"abc");
    let rogues = [
        // A second integrity.digest that "passes" a reference.
        Rogue(
            CheckId::IntegrityDigest,
            Some(0),
            Evidence::Size {
                expected: 1,
                actual: 1,
            },
        ),
        // Evidence its identifier does not allow, which would pass.
        Rogue(
            CheckId::AuthenticitySignature,
            Some(0),
            Evidence::Size {
                expected: 1,
                actual: 1,
            },
        ),
        // A reference that does not exist.
        Rogue(
            CheckId::ReproducibilityRebuild,
            Some(7),
            Evidence::NoCheck(Unevaluated::Recipe),
        ),
    ];
    for rogue in rogues {
        let mut request = VerificationRequest::new(
            ArtifactSource::Path(&artifact),
            vec![expected(&[(Sha256, b"abc")])],
            integrity(),
        );
        request.extra_checks.push(Box::new(rogue));
        let report = verify(request);
        assert_eq!(report.overall(), OverallStatus::VerificationFailed);
        assert!(
            report
                .checks()
                .iter()
                .any(|c| c.status() == Error && c.reference().is_none())
        );
    }
}

/// An added check in another dimension, reporting what `outcomes` says.
struct Added(CheckId, Vec<Outcome>);

impl Check for Added {
    fn id(&self) -> CheckId {
        self.0
    }

    fn run(&self, _: &CheckContext<'_>) -> Vec<Outcome> {
        self.1.clone()
    }
}

fn with_checks(artifact: &Path, manifest: &[u8], checks: Vec<Added>) -> VerificationReport {
    let mut request = VerificationRequest::new(
        ArtifactSource::Path(artifact),
        vec![from_manifest(manifest)],
        VerificationPolicy::full(),
    );
    for check in checks {
        request.extra_checks.push(Box::new(check));
    }
    verify(request)
}

#[test]
fn evidence_that_no_check_evaluated_is_always_unsupported() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = file(dir.path(), "app", b"abc");
    let manifest = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/manifests/v0/valid/file-recipe.json"),
    )
    .unwrap();
    let rebuilds = |report: &VerificationReport| {
        report
            .checks()
            .iter()
            .filter(|c| c.id() == CheckId::ReproducibilityRebuild)
            .map(|c| (c.reference(), c.status()))
            .collect::<Vec<_>>()
    };
    // No check for the recipe: an explicit UNSUPPORTED result.
    let report = with_checks(&artifact, &manifest, Vec::new());
    assert_eq!(rebuilds(&report), vec![(Some(0), Unsupported)]);
    // A registered check that says nothing about the recipe does not make
    // it disappear.
    let silent = Added(CheckId::ReproducibilityRebuild, Vec::new());
    let report = with_checks(&artifact, &manifest, vec![silent]);
    assert_eq!(rebuilds(&report), vec![(Some(0), Unsupported)]);
    // A check that reports on it replaces the engine's own result.
    let reporting = Added(
        CheckId::ReproducibilityRebuild,
        vec![Outcome::new(
            Some(0),
            Evidence::NoCheck(Unevaluated::Recipe),
        )],
    );
    let report = with_checks(&artifact, &manifest, vec![reporting]);
    assert_eq!(rebuilds(&report), vec![(Some(0), Unsupported)]);
}

#[test]
fn every_outcome_must_agree_with_the_reference_it_names() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = file(dir.path(), "app", b"abc");
    // A manifest without a recipe, and a check that reports one anyway.
    let manifest = manifest_for(&artifact, &[Sha256]);
    let inventing = Added(
        CheckId::ReproducibilityRebuild,
        vec![
            Outcome::new(Some(0), Evidence::NoCheck(Unevaluated::Recipe)),
            Outcome::new(None, Evidence::NoCheck(Unevaluated::Recipe)),
        ],
    );
    let report = with_checks(&artifact, &manifest, vec![inventing]);
    assert_eq!(report.overall(), OverallStatus::VerificationFailed);
    let rebuild: Vec<_> = report
        .checks()
        .iter()
        .filter(|c| c.id() == CheckId::ReproducibilityRebuild)
        .map(|c| (c.reference(), c.evidence().clone()))
        .collect();
    assert_eq!(
        rebuild,
        vec![
            (None, Evidence::InvalidEvidence),
            (None, Evidence::InvalidEvidence)
        ]
    );
    // Whatever a check reports, the report it ends up in reads back.
    let read = crate::report::read_report(&report.to_pretty_json(), &Default::default());
    assert_eq!(read.as_ref(), Ok(&report));
}

#[test]
fn a_duplicate_check_without_references_still_makes_a_readable_report() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = file(dir.path(), "app", b"abc");
    let mut request = VerificationRequest::new(
        ArtifactSource::Path(&artifact),
        Vec::new(),
        VerificationPolicy::full(),
    );
    request
        .extra_checks
        .push(Box::new(Added(CheckId::IntegrityDigest, Vec::new())));
    let report = verify(request);
    assert_eq!(report.overall(), OverallStatus::VerificationFailed);
    let read = crate::report::read_report(&report.to_pretty_json(), &Default::default());
    assert_eq!(read.as_ref(), Ok(&report));
}

#[test]
fn several_references_must_all_match() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = file(dir.path(), "app", b"abc");
    let report = run(
        &artifact,
        vec![expected(&[(Sha256, b"abc")]), expected(&[(Blake3, b"abc")])],
        integrity(),
    );
    assert_eq!(report.overall(), OverallStatus::Verified);
    assert_eq!(
        report.origins(),
        "reference 1: user-supplied; reference 2: user-supplied"
    );
    let report = run(
        &artifact,
        vec![expected(&[(Sha256, b"abc")]), expected(&[(Blake3, b"xyz")])],
        integrity(),
    );
    assert_eq!(report.overall(), OverallStatus::Mismatch);
}

#[test]
fn no_reference_verifies_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = file(dir.path(), "app", b"abc");
    let report = run(&artifact, Vec::new(), integrity());
    assert_eq!(
        results(&report),
        vec![("integrity.digest", None, NotProvided)]
    );
    assert_eq!(report.overall(), OverallStatus::Unverified);
}

#[test]
fn identical_runs_write_identical_reports() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = file(dir.path(), "app", b"abc");
    let manifest = manifest_for(&artifact, &DigestAlgorithm::ALL);
    let write = || {
        run(
            &artifact,
            vec![from_manifest(&manifest)],
            VerificationPolicy::full(),
        )
        .to_pretty_json()
    };
    assert_eq!(write(), write());
}

#[test]
fn a_report_records_no_time_unless_asked() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = file(dir.path(), "app", b"abc");
    let report = run(&artifact, vec![expected(&[(Sha256, b"abc")])], integrity());
    assert_eq!(report.generated_at(), None);
    let at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_730_678_400);
    assert_eq!(
        report.with_generated_at(at).generated_at().as_deref(),
        Some("2024-11-04T00:00:00Z")
    );
}

#[cfg(unix)]
mod trees {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn tree(dir: &Path) -> std::path::PathBuf {
        let root = dir.join("dist");
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join("bin/app"), b"binary").unwrap();
        std::fs::set_permissions(root.join("bin/app"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        std::fs::write(root.join("README"), b"read me").unwrap();
        symlink("bin/app", root.join("app")).unwrap();
        root
    }

    fn verify_tree(root: &Path, manifest: &[u8]) -> VerificationReport {
        run(root, vec![from_manifest(manifest)], integrity())
    }

    fn tree_changes(report: &VerificationReport) -> Vec<(String, &'static str)> {
        report
            .checks()
            .iter()
            .find_map(|c| match c.evidence() {
                Evidence::Tree(t) => Some(
                    t.differences()
                        .iter()
                        .map(|d| (d.path().to_string(), d.change().code()))
                        .collect(),
                ),
                _ => None,
            })
            .unwrap()
    }

    #[test]
    fn a_tree_matches_its_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let root = tree(dir.path());
        let manifest = manifest_for(&root, &DigestAlgorithm::ALL);
        let report = verify_tree(&root, &manifest);
        assert_eq!(
            results(&report),
            vec![
                ("integrity.digest", Some(0), Passed),
                ("integrity.size", Some(0), Passed),
                ("integrity.tree", Some(0), Passed),
            ]
        );
        assert_eq!(report.checks()[2].summary(), "all 4 entries match");
        assert_eq!(report.overall(), OverallStatus::Verified);
    }

    #[test]
    fn every_change_to_a_tree_is_a_mismatch() {
        type Change = fn(&Path);
        let changes: [(Change, Vec<(&str, &str)>); 4] = [
            (
                |root| std::fs::write(root.join("README"), b"read mE").unwrap(),
                vec![("README", "digest")],
            ),
            (
                |root| {
                    std::fs::set_permissions(
                        root.join("bin/app"),
                        std::fs::Permissions::from_mode(0o644),
                    )
                    .unwrap();
                },
                vec![("bin/app", "executable")],
            ),
            (
                |root| std::fs::write(root.join("extra"), b"").unwrap(),
                vec![("extra", "unexpected")],
            ),
            (
                |root| {
                    std::fs::remove_file(root.join("app")).unwrap();
                    symlink("README", root.join("app")).unwrap();
                },
                vec![("app", "target")],
            ),
        ];
        for (change, expected) in changes {
            let dir = tempfile::tempdir().unwrap();
            let root = tree(dir.path());
            let manifest = manifest_for(&root, &DigestAlgorithm::ALL);
            change(&root);
            let report = verify_tree(&root, &manifest);
            assert_eq!(report.overall(), OverallStatus::Mismatch);
            let expected: Vec<(String, &str)> = expected
                .into_iter()
                .map(|(p, c)| (p.to_owned(), c))
                .collect();
            assert_eq!(tree_changes(&report), expected);
        }
    }

    #[test]
    fn a_size_claim_is_not_checked_against_the_wrong_kind() {
        let dir = tempfile::tempdir().unwrap();
        let root = tree(dir.path());
        let manifest = manifest_for(&root, &[Sha256]);
        // A file whose size equals the directory's total.
        let total: u64 = 6 + 7;
        let file = super::file(dir.path(), "lookalike", &vec![b'x'; total as usize]);
        let report = verify_tree(&file, &manifest);
        assert_eq!(
            results(&report),
            vec![
                ("integrity.digest", Some(0), Failed),
                ("integrity.size", Some(0), Skipped),
                ("integrity.tree", Some(0), Skipped),
            ]
        );
    }

    /// Rewrites a manifest so that its files keep only SHA-256 while its
    /// tree digest keeps SHA-256 and SHA-512: a valid, hand-written mix.
    fn mixed_algorithms(manifest: &[u8]) -> Vec<u8> {
        fn keep(value: &mut StrictValue, keys: &[&str]) {
            if let StrictValue::Object(members) = value {
                members.retain(|k, _| keys.contains(&k.as_str()));
            }
        }
        let mut value = json::parse(manifest, &Default::default()).unwrap();
        let StrictValue::Object(statement) = &mut value else {
            panic!()
        };
        if let Some(StrictValue::Array(subjects)) = statement.get_mut("subject") {
            for subject in subjects {
                if let StrictValue::Object(s) = subject {
                    keep(s.get_mut("digest").unwrap(), &["sha256"]);
                }
            }
        }
        let Some(StrictValue::Object(predicate)) = statement.get_mut("predicate") else {
            panic!()
        };
        let Some(StrictValue::Object(artifact)) = predicate.get_mut("artifact") else {
            panic!()
        };
        keep(
            artifact.get_mut("treeDigest").unwrap(),
            &["narSha256", "narSha512"],
        );
        if let Some(StrictValue::Array(entries)) = artifact.get_mut("tree") {
            for entry in entries {
                if let StrictValue::Object(e) = entry
                    && let Some(digest) = e.get_mut("digest")
                {
                    keep(digest, &["sha256"]);
                }
            }
        }
        json::to_pretty(&value)
    }

    #[test]
    fn listings_and_tree_digests_may_use_different_algorithms() {
        let dir = tempfile::tempdir().unwrap();
        let root = tree(dir.path());
        let manifest = mixed_algorithms(&manifest_for(&root, &DigestAlgorithm::ALL));
        let report = verify_tree(&root, &manifest);
        assert_eq!(report.overall(), OverallStatus::Verified, "{report:#?}");

        // A user-supplied BLAKE3 tree digest next to a SHA-256-only manifest:
        // both are computed, and both compared.
        let sha256_only = manifest_for(&root, &[Sha256]);
        let opts = InspectOptions {
            algorithms: algorithms(&[Blake3]),
            ..Default::default()
        };
        let ArtifactDigests::Tree(blake3) = inspect_path(&root, &opts).unwrap().digests().clone()
        else {
            panic!()
        };
        let report = run(
            &root,
            vec![
                from_manifest(&sha256_only),
                Reference::expected(ArtifactDigests::Tree(blake3)),
            ],
            integrity(),
        );
        assert_eq!(report.overall(), OverallStatus::Verified, "{report:#?}");
    }
}
