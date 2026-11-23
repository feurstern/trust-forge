//! Reading a saved report strictly, and refusing one that claims more than
//! its own evidence supports.
//!
//! A saved report is untrusted input: anyone can write one. Reading fails
//! closed on anything this version does not define (fields, statuses,
//! evidence types, check identifiers, origins, report versions). Then:
//! - every check's status is recomputed from its evidence, every dimension's
//!   from the checks, and the overall status from those and the policy; a
//!   recorded status that differs makes the report inconsistent;
//! - every piece of evidence must agree with the artifact and reference it
//!   refers to (the digests computed, the size, the pinned digest);
//! - explanations (summaries, possible causes, limitations) must be text,
//!   but are never used: they are regenerated from the structured data.
//!
//! What this cannot detect is a forgery that is consistent throughout: a
//! report invented as a whole reads exactly like a genuine one. Reports are
//! unsigned, and they are never evidence.

use std::collections::BTreeMap;

use super::{REPORT_TYPE_V0, TOOL_NAME, digest_set_of, key_algorithm};
use crate::digest::{AlgorithmSet, Digest, DigestAlgorithm};
use crate::inspect::{ArtifactDigests, ArtifactKind, time};
use crate::json::{self, JsonError, JsonLimits, Pointer, StrictValue};
use crate::manifest::WarningKind;
use crate::name::{RelPath, validate_symlink_target};
use crate::verify::{
    ArtifactFailure, ArtifactSummary, Change, CheckId, CheckResult, CheckStatus, ClaimSummary,
    ClaimedKind, Difference, DigestKind, Dimension, DimensionStatus, EntryType, Evidence,
    FailureKind, InspectedArtifact, NotEvaluatedReason, OverallStatus, ReferenceOrigin,
    ReferenceSource, ReferenceSummary, SkipReason, TreeComparison, TreeProblem, Unevaluated,
    UnsupportedReason, VerificationPolicy, VerificationReport, WarningSummary, consistency,
    evidence_allowed, limits,
};

/// Why a saved report was not accepted.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReportError {
    /// The document is not strict JSON, or is too large.
    #[error("{0}")]
    Json(#[from] JsonError),
    /// The document is not a valid report of this version.
    #[error("{pointer}: {problem}")]
    Invalid {
        /// Where.
        pointer: Pointer,
        /// What is wrong.
        problem: String,
    },
    /// Another report type, version or tool, or something this version does
    /// not define.
    #[error("{pointer}: {what} is not supported by this version of TrustForge")]
    Unsupported {
        /// Where.
        pointer: Pointer,
        /// What.
        what: String,
    },
    /// A recorded status or value that does not follow from the report's own
    /// evidence.
    #[error("{pointer}: {problem}; the report is inconsistent")]
    Inconsistent {
        /// Where.
        pointer: Pointer,
        /// What does not follow.
        problem: String,
    },
}

fn invalid(at: &Pointer, problem: impl Into<String>) -> ReportError {
    ReportError::Invalid {
        pointer: at.clone(),
        problem: problem.into(),
    }
}

fn unsupported(at: &Pointer, what: impl Into<String>) -> ReportError {
    ReportError::Unsupported {
        pointer: at.clone(),
        what: what.into(),
    }
}

fn inconsistent(at: &Pointer, problem: impl Into<String>) -> ReportError {
    ReportError::Inconsistent {
        pointer: at.clone(),
        problem: problem.into(),
    }
}

/// Quotes a value from the document in errors, shortened.
fn quoted(value: &str) -> String {
    format!(
        "\"{}\"",
        crate::verify::display_text(value, limits::MAX_QUOTED_CHARS)
    )
}

/// Reads a saved report and checks that every recorded status follows from
/// its evidence.
pub fn read_report(bytes: &[u8], limits: &JsonLimits) -> Result<VerificationReport, ReportError> {
    let value = json::parse(bytes, limits)?;
    let root = Pointer::root();
    let fields = Fields::new(
        &value,
        &root,
        &[
            "_type",
            "artifact",
            "checks",
            "dimensions",
            "limitations",
            "overall",
            "policy",
            "references",
            "tool",
        ],
        &["generatedAt"],
    )?;
    // The type and version are checked before anything else is read.
    let (report_type, at) = fields.get("_type")?;
    let report_type = string(report_type, &at)?;
    if report_type != REPORT_TYPE_V0 {
        return Err(unsupported(
            &at,
            format!("report type {}", quoted(report_type)),
        ));
    }
    let tool_version = tool(fields.get("tool")?)?;
    let policy = policy(fields.get("policy")?)?;
    let artifact = artifact(fields.get("artifact")?)?;
    let references = references(fields.get("references")?)?;
    let (checks_value, checks_at) = fields.get("checks")?;
    let checks = checks(checks_value, &checks_at, &policy, &artifact, &references)?;
    let generated_at = match fields.opt("generatedAt") {
        Some((value, at)) => Some(
            time::parse_rfc3339_utc(string(value, &at)?)
                .ok_or_else(|| invalid(&at, "must be a UTC time such as 2026-11-23T12:00:00Z"))?,
        ),
        None => None,
    };
    let report = VerificationReport::new(
        tool_version,
        artifact,
        references,
        checks,
        policy,
        generated_at,
    );
    dimensions(fields.get("dimensions")?, &report)?;
    overall(fields.get("overall")?, &report)?;
    let (limitations, at) = fields.get("limitations")?;
    texts(limitations, &at)?;
    Ok(report)
}

/// An object whose keys have been checked: no unknown field, and every
/// required one present.
struct Fields<'v> {
    members: &'v BTreeMap<String, StrictValue>,
    at: Pointer,
}

impl<'v> Fields<'v> {
    fn new(
        value: &'v StrictValue,
        at: &Pointer,
        required: &[&str],
        optional: &[&str],
    ) -> Result<Self, ReportError> {
        let StrictValue::Object(members) = value else {
            return Err(invalid(at, "must be an object"));
        };
        for key in members.keys() {
            if !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
                return Err(unsupported(&at.key(key), "the field"));
            }
        }
        for key in required {
            if !members.contains_key(*key) {
                return Err(invalid(&at.key(key), "required field is missing"));
            }
        }
        Ok(Self {
            members,
            at: at.clone(),
        })
    }

    fn get(&self, key: &str) -> Result<(&'v StrictValue, Pointer), ReportError> {
        self.opt(key)
            .ok_or_else(|| invalid(&self.at.key(key), "required field is missing"))
    }

    fn opt(&self, key: &str) -> Option<(&'v StrictValue, Pointer)> {
        self.members.get(key).map(|value| (value, self.at.key(key)))
    }
}

fn string<'v>(value: &'v StrictValue, at: &Pointer) -> Result<&'v str, ReportError> {
    match value {
        StrictValue::String(s) => Ok(s),
        _ => Err(invalid(at, "must be a string")),
    }
}

fn integer(value: &StrictValue, at: &Pointer) -> Result<u64, ReportError> {
    match value {
        StrictValue::Integer(n) => Ok(*n),
        _ => Err(invalid(at, "must be an integer")),
    }
}

fn boolean(value: &StrictValue, at: &Pointer) -> Result<bool, ReportError> {
    match value {
        StrictValue::Bool(b) => Ok(*b),
        _ => Err(invalid(at, "must be true or false")),
    }
}

fn array<'v>(value: &'v StrictValue, at: &Pointer) -> Result<&'v [StrictValue], ReportError> {
    match value {
        StrictValue::Array(items) => Ok(items),
        _ => Err(invalid(at, "must be an array")),
    }
}

/// `None` for `null`.
fn nullable(value: &StrictValue) -> Option<&StrictValue> {
    match value {
        StrictValue::Null => None,
        other => Some(other),
    }
}

/// Explanations: they must be text, but they are regenerated, never used.
fn texts(value: &StrictValue, at: &Pointer) -> Result<(), ReportError> {
    for (i, item) in array(value, at)?.iter().enumerate() {
        string(item, &at.index(i))?;
    }
    Ok(())
}

/// A display string that this version cut to `max` characters plus `…`.
fn bounded(value: &StrictValue, at: &Pointer, max: usize) -> Result<String, ReportError> {
    let text = string(value, at)?;
    if text.chars().count() > max.saturating_add(1) {
        return Err(invalid(at, "is longer than this version writes"));
    }
    Ok(text.to_owned())
}

fn code<T>(
    value: &StrictValue,
    at: &Pointer,
    what: &str,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<T, ReportError> {
    let text = string(value, at)?;
    parse(text).ok_or_else(|| unsupported(at, format!("{what} {}", quoted(text))))
}

fn tool((value, at): (&StrictValue, Pointer)) -> Result<String, ReportError> {
    let fields = Fields::new(value, &at, &["name", "version"], &[])?;
    let (name, name_at) = fields.get("name")?;
    let name = string(name, &name_at)?;
    if name != TOOL_NAME {
        return Err(unsupported(
            &name_at,
            format!("a report written by {}", quoted(name)),
        ));
    }
    let (version, version_at) = fields.get("version")?;
    let version = string(version, &version_at)?;
    if !is_version(version) {
        return Err(invalid(&version_at, "must be a version such as 0.1.0"));
    }
    Ok(version.to_owned())
}

/// `MAJOR.MINOR.PATCH`, optionally followed by `-` or `+` and ASCII letters,
/// digits, `.`, `-` or `+`; at most 64 characters.
fn is_version(text: &str) -> bool {
    let (core, suffix) = match text.find(['-', '+']) {
        Some(at) => text.split_at(at),
        None => (text, ""),
    };
    let numbers: Vec<&str> = core.split('.').collect();
    text.len() <= 64
        && numbers.len() == 3
        && numbers
            .iter()
            .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        && suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
        && suffix.len() != 1
}

fn policy((value, at): (&StrictValue, Pointer)) -> Result<VerificationPolicy, ReportError> {
    let fields = Fields::new(value, &at, &["acceptedAlgorithms", "name", "require"], &[])?;
    let (require, require_at) = fields.get("require")?;
    let mut dimensions = Vec::new();
    for (i, item) in array(require, &require_at)?.iter().enumerate() {
        let at = require_at.index(i);
        let dimension = code(item, &at, "dimension", Dimension::from_name)?;
        if dimensions.last().is_some_and(|last| *last >= dimension) {
            return Err(invalid(
                &at,
                "dimensions must be unique and in report order",
            ));
        }
        dimensions.push(dimension);
    }
    let (accepted, accepted_at) = fields.get("acceptedAlgorithms")?;
    let mut algorithms = Vec::new();
    for (i, item) in array(accepted, &accepted_at)?.iter().enumerate() {
        let at = accepted_at.index(i);
        let algorithm = code(item, &at, "digest algorithm", |s| {
            s.parse::<DigestAlgorithm>().ok()
        })?;
        if algorithms.last().is_some_and(|last| *last >= algorithm) {
            return Err(invalid(&at, "algorithms must be unique and in name order"));
        }
        algorithms.push(algorithm);
    }
    let algorithms = AlgorithmSet::new(algorithms)
        .map_err(|_| invalid(&accepted_at, "must name at least one algorithm"))?;
    let policy = VerificationPolicy::require(dimensions)
        .map_err(|_| invalid(&require_at, "must name at least one dimension"))?
        .with_accepted_algorithms(algorithms);
    let (name, name_at) = fields.get("name")?;
    if string(name, &name_at)? != policy.name() {
        return Err(inconsistent(
            &name_at,
            format!(
                "the policy that requires these dimensions is \"{}\"",
                policy.name()
            ),
        ));
    }
    Ok(policy)
}

fn artifact_kind(text: &str) -> Option<ArtifactKind> {
    match text {
        "file" => Some(ArtifactKind::File),
        "directory" => Some(ArtifactKind::Directory),
        "stream" => Some(ArtifactKind::Stream),
        _ => None,
    }
}

fn artifact((value, at): (&StrictValue, Pointer)) -> Result<ArtifactSummary, ReportError> {
    let StrictValue::Object(members) = value else {
        return Err(invalid(&at, "must be an object"));
    };
    if members.contains_key("error") {
        let fields = Fields::new(value, &at, &["error", "name"], &[])?;
        let (name, name_at) = fields.get("name")?;
        let (error, error_at) = fields.get("error")?;
        let error = Fields::new(error, &error_at, &["kind", "message"], &[])?;
        let (kind, kind_at) = error.get("kind")?;
        let kind = code(kind, &kind_at, "failure kind", FailureKind::from_code)?;
        let (message, message_at) = error.get("message")?;
        let message = bounded(message, &message_at, crate::verify::MAX_MESSAGE_CHARS)?;
        return Ok(ArtifactSummary::new(
            string(name, &name_at)?.to_owned(),
            Err(ArtifactFailure::read(kind, message)),
        ));
    }
    let kind_text = match members.get("kind") {
        Some(StrictValue::String(kind)) => kind.as_str(),
        _ => "",
    };
    let digest_key = if kind_text == "directory" {
        "treeDigest"
    } else {
        "digest"
    };
    let fields = Fields::new(
        value,
        &at,
        &["entries", "kind", "name", "size", digest_key],
        &[],
    )?;
    let (name, name_at) = fields.get("name")?;
    let (kind, kind_at) = fields.get("kind")?;
    let kind = code(kind, &kind_at, "artifact kind", artifact_kind)?;
    let (size, size_at) = fields.get("size")?;
    let size = integer(size, &size_at)?;
    let (digests, digests_at) = fields.get(digest_key)?;
    let digests = if kind == ArtifactKind::Directory {
        ArtifactDigests::Tree(digest_set(digests, &digests_at, DigestKind::Tree)?)
    } else {
        ArtifactDigests::Content(digest_set(digests, &digests_at, DigestKind::Content)?)
    };
    let (entries, entries_at) = fields.get("entries")?;
    let entries = match nullable(entries) {
        Some(entries) => Some(integer(entries, &entries_at)?),
        None => None,
    };
    if entries.is_some() != (kind == ArtifactKind::Directory) {
        return Err(invalid(
            &entries_at,
            "a directory, and only a directory, has a number of entries",
        ));
    }
    Ok(ArtifactSummary::new(
        string(name, &name_at)?.to_owned(),
        Ok(InspectedArtifact::new(kind, size, digests, entries)),
    ))
}

/// The digests of a digest-set value with `kind` keys, in algorithm order.
fn digests(
    value: &StrictValue,
    at: &Pointer,
    kind: DigestKind,
) -> Result<Vec<Digest>, ReportError> {
    let StrictValue::Object(members) = value else {
        return Err(invalid(at, "must be an object"));
    };
    let mut digests = Vec::with_capacity(members.len());
    for (key, value) in members {
        let key_at = at.key(key);
        let algorithm = key_algorithm(key, kind)
            .ok_or_else(|| unsupported(&key_at, format!("digest key {}", quoted(key))))?;
        let digest = Digest::from_hex(algorithm, string(value, &key_at)?)
            .map_err(|e| invalid(&key_at, e.to_string()))?;
        digests.push(digest);
    }
    digests.sort_by_key(Digest::algorithm);
    Ok(digests)
}

fn digest_set(
    value: &StrictValue,
    at: &Pointer,
    kind: DigestKind,
) -> Result<crate::digest::DigestSet, ReportError> {
    digest_set_of(digests(value, at, kind)?)
        .ok_or_else(|| invalid(at, "must contain at least one digest"))
}

/// A digest object with exactly one entry, such as `{"sha256": "…"}`.
fn single_digest(value: &StrictValue, at: &Pointer) -> Result<Digest, ReportError> {
    match digests(value, at, DigestKind::Content)?.as_slice() {
        [digest] => Ok(digest.clone()),
        _ => Err(invalid(at, "must contain exactly one digest")),
    }
}

fn references((value, at): (&StrictValue, Pointer)) -> Result<Vec<ReferenceSummary>, ReportError> {
    array(value, &at)?
        .iter()
        .enumerate()
        .map(|(i, item)| reference(item, &at.index(i)))
        .collect()
}

fn reference(value: &StrictValue, at: &Pointer) -> Result<ReferenceSummary, ReportError> {
    let fields = Fields::new(
        value,
        at,
        &[
            "claim",
            "origin",
            "recipe",
            "source",
            "warnings",
            "warningsOmitted",
        ],
        &[],
    )?;
    let (origin, origin_at) = fields.get("origin")?;
    let origin = code(
        origin,
        &origin_at,
        "reference origin",
        ReferenceOrigin::from_code,
    )?;

    let (source, source_at) = fields.get("source")?;
    let source = match source {
        StrictValue::Object(members)
            if members.get("type") == Some(&StrictValue::String("manifest".to_owned())) =>
        {
            let source = Fields::new(
                source,
                &source_at,
                &["path", "pinned", "sha256", "type"],
                &[],
            )?;
            let (path, path_at) = source.get("path")?;
            let (sha256, sha256_at) = source.get("sha256")?;
            let sha256 = Digest::from_hex(DigestAlgorithm::Sha256, string(sha256, &sha256_at)?)
                .map_err(|e| invalid(&sha256_at, e.to_string()))?;
            let (pinned, pinned_at) = source.get("pinned")?;
            let pinned = match nullable(pinned) {
                Some(pinned) => Some(single_digest(pinned, &pinned_at)?),
                None => None,
            };
            ReferenceSource::Manifest {
                path: string(path, &path_at)?.to_owned(),
                sha256,
                pinned,
            }
        }
        _ => {
            let source = Fields::new(source, &source_at, &["type"], &[])?;
            let (kind, kind_at) = source.get("type")?;
            code(kind, &kind_at, "reference source", |s| {
                (s == "expected").then_some(ReferenceSource::Expected)
            })?
        }
    };
    let expected_origin = match &source {
        ReferenceSource::Expected => ReferenceOrigin::UserSupplied,
        ReferenceSource::Manifest {
            pinned: Some(_), ..
        } => ReferenceOrigin::UserPinned,
        ReferenceSource::Manifest { pinned: None, .. } => ReferenceOrigin::UnauthenticatedClaim,
    };
    if origin != expected_origin {
        return Err(inconsistent(
            &origin_at,
            format!("a reference from this source is {}", expected_origin.code()),
        ));
    }

    let (claim, claim_at) = fields.get("claim")?;
    let claim = claim_summary(claim, &claim_at)?;
    let unusable = matches!(
        &source,
        ReferenceSource::Manifest { sha256, pinned: Some(pinned), .. } if pinned != sha256
    );
    if unusable != (claim == ClaimSummary::Unusable) {
        return Err(inconsistent(
            &claim_at,
            "a manifest's claims are unusable exactly when it does not match its pinned digest",
        ));
    }
    let directly_given = source == ReferenceSource::Expected;
    if directly_given
        && !matches!(
            claim,
            ClaimSummary::File { size: None }
                | ClaimSummary::Directory {
                    size: None,
                    entries: None
                }
        )
    {
        return Err(inconsistent(
            &claim_at,
            "digests given directly claim no size and no listing",
        ));
    }

    let (recipe, recipe_at) = fields.get("recipe")?;
    let recipe = match nullable(recipe) {
        Some(recipe) => Some(bounded(recipe, &recipe_at, limits::MAX_QUOTED_CHARS)?),
        None => None,
    };
    let (warnings, warnings_at) = fields.get("warnings")?;
    let warnings = array(warnings, &warnings_at)?;
    if warnings.len() > limits::MAX_WARNINGS {
        return Err(invalid(
            &warnings_at,
            "has more warnings than this version keeps",
        ));
    }
    let warnings = warnings
        .iter()
        .enumerate()
        .map(|(i, item)| warning(item, &warnings_at.index(i)))
        .collect::<Result<Vec<_>, _>>()?;
    let (omitted, omitted_at) = fields.get("warningsOmitted")?;
    let omitted = integer(omitted, &omitted_at)?;
    // A recipe and warnings come from reading a manifest to the end.
    let manifest_read = matches!(
        claim,
        ClaimSummary::File { .. } | ClaimSummary::Directory { .. }
    ) && !directly_given;
    if !manifest_read && (recipe.is_some() || !warnings.is_empty() || omitted > 0) {
        return Err(inconsistent(
            &recipe_at,
            "only a manifest that was read to the end has a recipe or warnings",
        ));
    }
    Ok(ReferenceSummary::new(
        origin, source, claim, recipe, warnings, omitted,
    ))
}

fn claim_summary(value: &StrictValue, at: &Pointer) -> Result<ClaimSummary, ReportError> {
    let kind = match value {
        StrictValue::Object(members) => match members.get("kind") {
            Some(StrictValue::String(kind)) => kind.as_str(),
            _ => "",
        },
        _ => "",
    };
    let optional_integer = |fields: &Fields<'_>, key: &str| -> Result<Option<u64>, ReportError> {
        let (value, at) = fields.get(key)?;
        match nullable(value) {
            Some(value) => Ok(Some(integer(value, &at)?)),
            None => Ok(None),
        }
    };
    match kind {
        "file" => {
            let fields = Fields::new(value, at, &["kind", "size"], &[])?;
            Ok(ClaimSummary::File {
                size: optional_integer(&fields, "size")?,
            })
        }
        "directory" => {
            let fields = Fields::new(value, at, &["entries", "kind", "size"], &[])?;
            Ok(ClaimSummary::Directory {
                size: optional_integer(&fields, "size")?,
                entries: optional_integer(&fields, "entries")?,
            })
        }
        "unsupported" => {
            let fields = Fields::new(value, at, &["kind", "pointer", "reason", "value"], &[])?;
            let (reason, reason_at) = fields.get("reason")?;
            let (text, text_at) = fields.get("value")?;
            let (pointer, pointer_at) = fields.get("pointer")?;
            let text = match nullable(text) {
                Some(text) => Some(bounded(text, &text_at, limits::MAX_QUOTED_CHARS)?),
                None => None,
            };
            let pointer = match nullable(pointer) {
                Some(pointer) => {
                    let pointer = bounded(pointer, &pointer_at, limits::MAX_QUOTED_CHARS)?;
                    if !is_pointer(&pointer) {
                        return Err(invalid(&pointer_at, "must be a JSON Pointer (RFC 6901)"));
                    }
                    Some(pointer)
                }
                None => None,
            };
            let reason = match (string(reason, &reason_at)?, text, pointer) {
                ("statement-type", Some(value), None) => UnsupportedReason::StatementType { value },
                ("predicate-type", Some(value), None) => UnsupportedReason::PredicateType { value },
                ("no-accepted-algorithm", None, Some(pointer)) => {
                    UnsupportedReason::NoAcceptedAlgorithm { pointer }
                }
                ("dsse-envelope", None, None) => UnsupportedReason::DsseEnvelope,
                ("sigstore-bundle", None, None) => UnsupportedReason::SigstoreBundle,
                (other, ..) => {
                    return Err(unsupported(
                        &reason_at,
                        format!("reason {} with these fields", quoted(other)),
                    ));
                }
            };
            Ok(ClaimSummary::Unsupported { reason })
        }
        "unusable" => {
            Fields::new(value, at, &["kind"], &[])?;
            Ok(ClaimSummary::Unusable)
        }
        other => Err(unsupported(
            &at.key("kind"),
            format!("claim kind {}", quoted(other)),
        )),
    }
}

/// An RFC 6901 pointer: empty, or `/` before each step, with `~` only in
/// `~0` and `~1`.
fn is_pointer(text: &str) -> bool {
    (text.is_empty() || text.starts_with('/'))
        && text
            .split('~')
            .skip(1)
            .all(|rest| rest.starts_with('0') || rest.starts_with('1'))
}

fn warning(value: &StrictValue, at: &Pointer) -> Result<WarningSummary, ReportError> {
    let fields = Fields::new(value, at, &["kind", "message", "pointer"], &[])?;
    let (kind, kind_at) = fields.get("kind")?;
    let kind = code(kind, &kind_at, "warning kind", WarningKind::from_code)?;
    let (message, message_at) = fields.get("message")?;
    string(message, &message_at)?;
    let (pointer, pointer_at) = fields.get("pointer")?;
    let pointer = string(pointer, &pointer_at)?;
    if !is_pointer(pointer) {
        return Err(invalid(&pointer_at, "must be a JSON Pointer (RFC 6901)"));
    }
    Ok(WarningSummary::new(pointer.to_owned(), kind))
}

fn checks(
    value: &StrictValue,
    at: &Pointer,
    policy: &VerificationPolicy,
    artifact: &ArtifactSummary,
    references: &[ReferenceSummary],
) -> Result<Vec<CheckResult>, ReportError> {
    let accepted = policy.accepted_algorithms();
    let mut checks = Vec::new();
    for (i, item) in array(value, at)?.iter().enumerate() {
        let at = at.index(i);
        let fields = Fields::new(
            item,
            &at,
            &[
                "dimension",
                "evidence",
                "id",
                "reference",
                "status",
                "summary",
            ],
            &[],
        )?;
        let (id, id_at) = fields.get("id")?;
        let id = code(id, &id_at, "check", CheckId::from_name)?;
        let (dimension, dimension_at) = fields.get("dimension")?;
        if string(dimension, &dimension_at)? != id.dimension().name() {
            return Err(inconsistent(
                &dimension_at,
                format!("{} belongs to {}", id.name(), id.dimension().name()),
            ));
        }
        let (reference, reference_at) = fields.get("reference")?;
        let reference = match nullable(reference) {
            Some(index) => {
                let index = integer(index, &reference_at)?;
                match usize::try_from(index) {
                    Ok(index) if index < references.len() => Some(index),
                    _ => return Err(invalid(&reference_at, "names no reference of the report")),
                }
            }
            None => None,
        };
        let (evidence, evidence_at) = fields.get("evidence")?;
        let evidence = self::evidence(evidence, &evidence_at)?;
        if !evidence_allowed(id, &evidence) {
            return Err(inconsistent(
                &evidence_at,
                format!("{} never reports this evidence", id.name()),
            ));
        }
        consistency::evidence_agrees(&evidence, reference, artifact, references)
            .map_err(|problem| inconsistent(&evidence_at, problem))?;
        let (summary, summary_at) = fields.get("summary")?;
        string(summary, &summary_at)?;
        let result = CheckResult::new(id, reference, evidence, accepted);
        let (status, status_at) = fields.get("status")?;
        let status = code(status, &status_at, "check status", CheckStatus::from_code)?;
        if status != result.status() {
            return Err(inconsistent(
                &status_at,
                format!(
                    "the evidence supports {}, not {}",
                    result.status().code(),
                    status.code()
                ),
            ));
        }
        checks.push(result);
    }
    consistency::required_results(&checks, references)
        .map_err(|problem| inconsistent(at, problem))?;
    Ok(checks)
}

fn evidence(value: &StrictValue, at: &Pointer) -> Result<Evidence, ReportError> {
    let kind = match value {
        StrictValue::Object(members) => match members.get("type") {
            Some(StrictValue::String(kind)) => kind.as_str(),
            _ => "",
        },
        _ => "",
    };
    let fields = |required: &[&str]| Fields::new(value, at, required, &[]);
    Ok(match kind {
        "no-reference" => {
            fields(&["type"])?;
            Evidence::NoReference
        }
        "digests" => {
            let f = fields(&["actual", "expected", "type"])?;
            let (expected, expected_at) = f.get("expected")?;
            let digest_kind = match expected {
                StrictValue::Object(members)
                    if members
                        .keys()
                        .next()
                        .is_some_and(|k| key_algorithm(k, DigestKind::Tree).is_some()) =>
                {
                    DigestKind::Tree
                }
                _ => DigestKind::Content,
            };
            let expected = digest_set(expected, &expected_at, digest_kind)?;
            let (actual, actual_at) = f.get("actual")?;
            Evidence::Digests {
                kind: digest_kind,
                expected,
                actual: digests(actual, &actual_at, digest_kind)?,
            }
        }
        "kind-mismatch" => {
            let f = fields(&["actual", "expected", "type"])?;
            let (expected, expected_at) = f.get("expected")?;
            let (actual, actual_at) = f.get("actual")?;
            Evidence::KindMismatch {
                expected: code(
                    expected,
                    &expected_at,
                    "claimed kind",
                    ClaimedKind::from_code,
                )?,
                actual: code(actual, &actual_at, "artifact kind", artifact_kind)?,
            }
        }
        "not-inspected" => {
            let f = fields(&["type", "unsupported"])?;
            let (unsupported, unsupported_at) = f.get("unsupported")?;
            Evidence::NotInspected {
                unsupported: boolean(unsupported, &unsupported_at)?,
            }
        }
        "skipped" => {
            let f = fields(&["reason", "type"])?;
            let (reason, reason_at) = f.get("reason")?;
            Evidence::Skipped(code(reason, &reason_at, "reason", SkipReason::from_code)?)
        }
        "unsupported-reference" => {
            fields(&["type"])?;
            Evidence::UnsupportedReference
        }
        "size" => {
            let f = fields(&["actual", "expected", "type"])?;
            let (expected, expected_at) = f.get("expected")?;
            let (actual, actual_at) = f.get("actual")?;
            Evidence::Size {
                expected: integer(expected, &expected_at)?,
                actual: integer(actual, &actual_at)?,
            }
        }
        "tree" => {
            let f = fields(&[
                "differences",
                "differencesOmitted",
                "entries",
                "problem",
                "type",
            ])?;
            Evidence::Tree(tree_comparison(&f)?)
        }
        "pin" => {
            let f = fields(&["actual", "pinned", "type"])?;
            let (pinned, pinned_at) = f.get("pinned")?;
            let (actual, actual_at) = f.get("actual")?;
            let actual = single_digest(actual, &actual_at)?;
            if actual.algorithm() != DigestAlgorithm::Sha256 {
                return Err(invalid(
                    &actual_at,
                    "a manifest is identified by its SHA-256",
                ));
            }
            Evidence::Pin {
                pinned: single_digest(pinned, &pinned_at)?,
                actual,
            }
        }
        "no-check" => {
            let claim = match value {
                StrictValue::Object(members) => match members.get("claim") {
                    Some(StrictValue::String(claim)) => claim.as_str(),
                    _ => "",
                },
                _ => "",
            };
            match claim {
                "recipe" => {
                    fields(&["claim", "type"])?;
                    Evidence::NoCheck(Unevaluated::Recipe)
                }
                "envelope" => {
                    fields(&["claim", "type"])?;
                    Evidence::NoCheck(Unevaluated::Envelope)
                }
                other => {
                    return Err(unsupported(
                        &at.key("claim"),
                        format!("unevaluated claim {}", quoted(other)),
                    ));
                }
            }
        }
        "duplicate-check" => {
            fields(&["type"])?;
            Evidence::DuplicateCheck
        }
        "invalid-evidence" => {
            fields(&["type"])?;
            Evidence::InvalidEvidence
        }
        other => {
            return Err(unsupported(
                &at.key("type"),
                format!("evidence type {}", quoted(other)),
            ));
        }
    })
}

fn tree_comparison(fields: &Fields<'_>) -> Result<TreeComparison, ReportError> {
    let (differences, differences_at) = fields.get("differences")?;
    let items = array(differences, &differences_at)?;
    if items.len() > limits::MAX_DIFFERENCES {
        return Err(invalid(
            &differences_at,
            "has more differences than this version keeps",
        ));
    }
    let differences = items
        .iter()
        .enumerate()
        .map(|(i, item)| difference(item, &differences_at.index(i)))
        .collect::<Result<Vec<_>, _>>()?;
    let (omitted, omitted_at) = fields.get("differencesOmitted")?;
    let (entries, entries_at) = fields.get("entries")?;
    let (problem, problem_at) = fields.get("problem")?;
    let problem = match nullable(problem) {
        None => None,
        Some(problem) => {
            let f = Fields::new(problem, &problem_at, &["kind", "path"], &[])?;
            let (kind, kind_at) = f.get("kind")?;
            let (path, path_at) = f.get("path")?;
            let path = match nullable(path) {
                Some(path) => Some(rel_path(path, &path_at)?),
                None => None,
            };
            Some(match (string(kind, &kind_at)?, path) {
                ("unordered", None) => TreeProblem::Unordered,
                ("not-computed", Some(path)) => TreeProblem::NotComputed { path },
                ("not-comparable", Some(path)) => TreeProblem::NotComparable { path },
                (kind, _) => {
                    return Err(unsupported(
                        &kind_at,
                        format!("listing problem {}", quoted(kind)),
                    ));
                }
            })
        }
    };
    Ok(TreeComparison::new(
        integer(entries, &entries_at)?,
        differences,
        integer(omitted, &omitted_at)?,
        problem,
    ))
}

fn rel_path(value: &StrictValue, at: &Pointer) -> Result<RelPath, ReportError> {
    RelPath::parse(string(value, at)?).map_err(|e| invalid(at, format!("invalid path: {e}")))
}

fn entry_type(value: &StrictValue, at: &Pointer) -> Result<EntryType, ReportError> {
    code(value, at, "entry type", EntryType::from_code)
}

fn target(value: &StrictValue, at: &Pointer) -> Result<String, ReportError> {
    let text = string(value, at)?;
    validate_symlink_target(text.as_bytes())
        .map_err(|e| invalid(at, format!("invalid target: {e}")))?;
    Ok(text.to_owned())
}

/// The `expected` and `actual` members.
type Pair<'v> = ((&'v StrictValue, Pointer), (&'v StrictValue, Pointer));

fn both<'v>(fields: &Fields<'v>) -> Result<Pair<'v>, ReportError> {
    Ok((fields.get("expected")?, fields.get("actual")?))
}

fn difference(value: &StrictValue, at: &Pointer) -> Result<Difference, ReportError> {
    let change = match value {
        StrictValue::Object(members) => match members.get("change") {
            Some(StrictValue::String(change)) => change.as_str(),
            _ => "",
        },
        _ => "",
    };
    let fields = |required: &[&str]| Fields::new(value, at, required, &[]);
    let (path, change) = match change {
        "missing" | "unexpected" => {
            let f = fields(&["change", "path", "type"])?;
            let (kind, kind_at) = f.get("type")?;
            let kind = entry_type(kind, &kind_at)?;
            (
                f.get("path")?,
                if change == "missing" {
                    Change::Missing(kind)
                } else {
                    Change::Unexpected(kind)
                },
            )
        }
        "type" => {
            let f = fields(&["actual", "change", "expected", "path"])?;
            let ((e, e_at), (a, a_at)) = both(&f)?;
            (
                f.get("path")?,
                Change::Type {
                    expected: entry_type(e, &e_at)?,
                    actual: entry_type(a, &a_at)?,
                },
            )
        }
        "executable" => {
            let f = fields(&["actual", "change", "expected", "path"])?;
            let ((e, e_at), (a, a_at)) = both(&f)?;
            (
                f.get("path")?,
                Change::Executable {
                    expected: boolean(e, &e_at)?,
                    actual: boolean(a, &a_at)?,
                },
            )
        }
        "size" => {
            let f = fields(&["actual", "change", "expected", "path"])?;
            let ((e, e_at), (a, a_at)) = both(&f)?;
            (
                f.get("path")?,
                Change::Size {
                    expected: integer(e, &e_at)?,
                    actual: integer(a, &a_at)?,
                },
            )
        }
        "digest" => {
            let f = fields(&["algorithms", "change", "path"])?;
            let (algorithms, algorithms_at) = f.get("algorithms")?;
            let mut list: Vec<DigestAlgorithm> = Vec::new();
            for (i, item) in array(algorithms, &algorithms_at)?.iter().enumerate() {
                let at = algorithms_at.index(i);
                let algorithm = code(item, &at, "digest algorithm", |s| {
                    s.parse::<DigestAlgorithm>().ok()
                })?;
                if list.last().is_some_and(|last| *last >= algorithm) {
                    return Err(invalid(&at, "algorithms must be unique and in name order"));
                }
                list.push(algorithm);
            }
            if list.is_empty() {
                return Err(invalid(&algorithms_at, "must name at least one algorithm"));
            }
            (f.get("path")?, Change::Digest(list))
        }
        "target" => {
            let f = fields(&["actual", "change", "expected", "path"])?;
            let ((e, e_at), (a, a_at)) = both(&f)?;
            (
                f.get("path")?,
                Change::Target {
                    expected: target(e, &e_at)?,
                    actual: target(a, &a_at)?,
                },
            )
        }
        other => {
            return Err(unsupported(
                &at.key("change"),
                format!("change {}", quoted(other)),
            ));
        }
    };
    let (path, path_at) = path;
    Ok(Difference::new(rel_path(path, &path_at)?, change))
}

fn dimensions(
    (value, at): (&StrictValue, Pointer),
    report: &VerificationReport,
) -> Result<(), ReportError> {
    let names: Vec<&str> = Dimension::ALL.iter().map(|d| d.name()).collect();
    let fields = Fields::new(value, &at, &names, &[])?;
    for &(dimension, status) in report.dimensions() {
        let (entry, entry_at) = fields.get(dimension.name())?;
        let entry = Fields::new(entry, &entry_at, &["reason", "status", "summary"], &[])?;
        let (recorded, recorded_at) = entry.get("status")?;
        let recorded = string(recorded, &recorded_at)?;
        let (reason, reason_at) = entry.get("reason")?;
        let reason = match nullable(reason) {
            Some(reason) => Some(code(
                reason,
                &reason_at,
                "reason",
                NotEvaluatedReason::from_code,
            )?),
            None => None,
        };
        let expected_reason = match status {
            DimensionStatus::NotEvaluated(reason) => Some(reason),
            _ => None,
        };
        if recorded != status.code() || reason != expected_reason {
            return Err(inconsistent(
                &recorded_at,
                format!(
                    "the checks support {} for {}",
                    status.code(),
                    dimension.name()
                ),
            ));
        }
        let (summary, summary_at) = entry.get("summary")?;
        string(summary, &summary_at)?;
    }
    Ok(())
}

fn overall(
    (value, at): (&StrictValue, Pointer),
    report: &VerificationReport,
) -> Result<(), ReportError> {
    let fields = Fields::new(value, &at, &["possibleCauses", "status", "summary"], &[])?;
    let (status, status_at) = fields.get("status")?;
    let status = code(
        status,
        &status_at,
        "overall status",
        OverallStatus::from_code,
    )?;
    if status != report.overall() {
        return Err(inconsistent(
            &status_at,
            format!(
                "the checks and the policy support {}, not {}",
                report.overall().code(),
                status.code()
            ),
        ));
    }
    let (causes, causes_at) = fields.get("possibleCauses")?;
    texts(causes, &causes_at)?;
    let (summary, summary_at) = fields.get("summary")?;
    string(summary, &summary_at)?;
    Ok(())
}
