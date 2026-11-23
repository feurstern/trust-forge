//! Verification: comparing an artifact with references, and reporting what
//! that establishes and what it does not (`docs/verification-semantics.md`).
//!
//! [`verify`] inspects an artifact once, runs every [`Check`] against the
//! [`Reference`]s supplied, and computes a status for each [`Dimension`] and
//! an [`OverallStatus`] under a [`VerificationPolicy`]. It always returns a
//! [`VerificationReport`]: an artifact that cannot be read becomes an `ERROR`
//! result inside the report, never a missing report.
//!
//! - A check's status is a pure function of its [`Evidence`], and the
//!   statuses of dimensions and the overall status are pure functions of the
//!   checks' statuses. The report reader ([`crate::report`]) recomputes every
//!   one of them, so a saved report cannot claim more than its own evidence.
//! - The built-in integrity checks always run. Other checks can be added
//!   ([`VerificationRequest::extra_checks`]), never removed or replaced.
//! - Evidence that no registered check can evaluate, such as a claimed
//!   recipe, gets an explicit `UNSUPPORTED` result (`docs/architecture.md`,
//!   decision 7).
//!
//! This version can establish **integrity** only. Authenticity and
//! provenance need references whose signatures were verified under a trust
//! policy, and reproducibility needs a rebuild; neither exists yet, so those
//! dimensions are never verified.

pub(crate) mod consistency;
mod digests;
mod integrity;
mod policy;
mod reference;
mod status;
mod text;
pub(crate) mod tree_diff;

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;
use std::time::SystemTime;

use crate::digest::{AlgorithmSet, Digest, DigestAlgorithm, DigestSet};
use crate::inspect::{
    ArtifactDigests, ArtifactKind, EntryKind, InspectError, InspectOptions, Inspection, Limits,
    inspect_path, inspect_reader, time,
};
use crate::name::{EscapedBytes, Quoted};

pub use policy::{PolicyError, VerificationPolicy};
pub use reference::{ClaimSummary, Reference, ReferenceSource, ReferenceSummary, WarningSummary};
pub use tree_diff::{Change, Difference, EntryType, TreeComparison, TreeProblem};

pub(crate) use tree_diff::View;

/// The version of TrustForge that produces reports.
pub(crate) const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// One of the four guarantees TrustForge evaluates separately.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Dimension {
    /// Are these exactly the bytes the reference describes?
    Integrity,
    /// Did an identity accepted by the trust policy vouch for these bytes?
    Authenticity,
    /// Was the artifact built the way an accepted builder attests?
    Provenance,
    /// Did this run rebuild the claimed source into identical bytes?
    Reproducibility,
}

impl Dimension {
    /// Every dimension, in report order.
    pub const ALL: [Dimension; 4] = [
        Self::Integrity,
        Self::Authenticity,
        Self::Provenance,
        Self::Reproducibility,
    ];

    /// The name used in policies and reports: `integrity`, `authenticity`,
    /// `provenance` or `reproducibility`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Integrity => "integrity",
            Self::Authenticity => "authenticity",
            Self::Provenance => "provenance",
            Self::Reproducibility => "reproducibility",
        }
    }

    /// The dimension whose [name](Self::name) is `name`.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.name() == name)
    }
}

/// The status of one check result.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CheckStatus {
    /// The evidence supports the claim.
    Passed,
    /// The evidence contradicts the claim.
    Failed,
    /// The evidence the check needs was not supplied.
    NotProvided,
    /// Evidence was supplied, but this version cannot evaluate it.
    Unsupported,
    /// Not run: a prerequisite failed.
    Skipped,
    /// The check started but could not complete.
    Error,
}

impl CheckStatus {
    const ALL: [CheckStatus; 6] = [
        Self::Passed,
        Self::Failed,
        Self::NotProvided,
        Self::Unsupported,
        Self::Skipped,
        Self::Error,
    ];

    /// The spelling in JSON reports: `PASSED`, `FAILED`, `NOT_PROVIDED`,
    /// `UNSUPPORTED`, `SKIPPED` or `ERROR`.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Passed => "PASSED",
            Self::Failed => "FAILED",
            Self::NotProvided => "NOT_PROVIDED",
            Self::Unsupported => "UNSUPPORTED",
            Self::Skipped => "SKIPPED",
            Self::Error => "ERROR",
        }
    }

    /// The spelling in text output: the code with spaces.
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotProvided => "NOT PROVIDED",
            other => other.code(),
        }
    }

    pub(crate) fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.code() == code)
    }
}

/// Why a dimension was not evaluated.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NotEvaluatedReason {
    /// The evidence it needs was not supplied.
    NotProvided,
    /// Evidence was supplied that this version cannot evaluate.
    Unsupported,
    /// A prerequisite failed.
    Skipped,
}

impl NotEvaluatedReason {
    const ALL: [NotEvaluatedReason; 3] = [Self::NotProvided, Self::Unsupported, Self::Skipped];

    /// The spelling in JSON reports: `not-provided`, `unsupported` or
    /// `skipped`.
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotProvided => "not-provided",
            Self::Unsupported => "unsupported",
            Self::Skipped => "skipped",
        }
    }

    pub(crate) fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.code() == code)
    }
}

/// The status of one dimension.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DimensionStatus {
    /// Every check passed, including the checks that decide the dimension.
    Verified,
    /// Some check failed: evidence contradicts a claim.
    Failed,
    /// Some check could not complete.
    Error,
    /// Not evaluated, for the reason given.
    NotEvaluated(NotEvaluatedReason),
}

impl DimensionStatus {
    /// The spelling in JSON reports: `VERIFIED`, `FAILED`, `ERROR` or
    /// `NOT_EVALUATED`.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Verified => "VERIFIED",
            Self::Failed => "FAILED",
            Self::Error => "ERROR",
            Self::NotEvaluated(_) => "NOT_EVALUATED",
        }
    }

    /// The spelling in text output: the code with spaces.
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotEvaluated(_) => "NOT EVALUATED",
            other => other.code(),
        }
    }
}

/// The overall result of a verification, by the precedence in
/// `docs/verification-semantics.md`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OverallStatus {
    /// Some check failed: evidence contradicts a claim.
    Mismatch,
    /// Some check could not complete. TrustForge fails closed.
    VerificationFailed,
    /// Every dimension the policy requires is verified.
    Verified,
    /// At least one dimension is verified, but the policy is not satisfied.
    PartiallyVerified,
    /// No dimension is verified.
    Unverified,
}

impl OverallStatus {
    const ALL: [OverallStatus; 5] = [
        Self::Mismatch,
        Self::VerificationFailed,
        Self::Verified,
        Self::PartiallyVerified,
        Self::Unverified,
    ];

    /// The spelling in JSON reports: `MISMATCH`, `VERIFICATION_FAILED`,
    /// `VERIFIED`, `PARTIALLY_VERIFIED` or `UNVERIFIED`.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Mismatch => "MISMATCH",
            Self::VerificationFailed => "VERIFICATION_FAILED",
            Self::Verified => "VERIFIED",
            Self::PartiallyVerified => "PARTIALLY_VERIFIED",
            Self::Unverified => "UNVERIFIED",
        }
    }

    /// The spelling in text output: the code with spaces.
    pub const fn label(self) -> &'static str {
        match self {
            Self::VerificationFailed => "VERIFICATION FAILED",
            Self::PartiallyVerified => "PARTIALLY VERIFIED",
            other => other.code(),
        }
    }

    pub(crate) fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.code() == code)
    }
}

/// The stable identifier of a check. Each identifier belongs to exactly one
/// dimension, fixed here: a check cannot choose its own dimension.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CheckId {
    /// The manifest's SHA-256 matches the digest the user pinned.
    IntegrityManifest,
    /// The artifact's digests match the reference's.
    IntegrityDigest,
    /// The artifact's size matches the reference's.
    IntegritySize,
    /// Every entry of a directory matches the reference's listing.
    IntegrityTree,
    /// A signature over the reference (used in this version only to report
    /// signed envelopes as unsupported).
    AuthenticitySignature,
    /// A rebuild of the claimed recipe (used in this version only to report
    /// claimed recipes as unsupported).
    ReproducibilityRebuild,
}

impl CheckId {
    const ALL: [CheckId; 6] = [
        Self::IntegrityManifest,
        Self::IntegrityDigest,
        Self::IntegritySize,
        Self::IntegrityTree,
        Self::AuthenticitySignature,
        Self::ReproducibilityRebuild,
    ];

    /// The identifier, such as `integrity.digest`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::IntegrityManifest => "integrity.manifest",
            Self::IntegrityDigest => "integrity.digest",
            Self::IntegritySize => "integrity.size",
            Self::IntegrityTree => "integrity.tree",
            Self::AuthenticitySignature => "authenticity.signature",
            Self::ReproducibilityRebuild => "reproducibility.rebuild",
        }
    }

    /// The dimension the check belongs to.
    pub const fn dimension(self) -> Dimension {
        match self {
            Self::IntegrityManifest
            | Self::IntegrityDigest
            | Self::IntegritySize
            | Self::IntegrityTree => Dimension::Integrity,
            Self::AuthenticitySignature => Dimension::Authenticity,
            Self::ReproducibilityRebuild => Dimension::Reproducibility,
        }
    }

    /// The check whose [name](Self::name) is `name`.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|id| id.name() == name)
    }
}

/// Where a reference came from, which limits what it can establish.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReferenceOrigin {
    /// Given directly by the user, such as `--expect sha256:…`.
    UserSupplied,
    /// A manifest whose SHA-256 the user pinned.
    UserPinned,
    /// Taken from an unsigned document, such as an unsigned manifest.
    UnauthenticatedClaim,
}

impl ReferenceOrigin {
    const ALL: [ReferenceOrigin; 3] = [
        Self::UserSupplied,
        Self::UserPinned,
        Self::UnauthenticatedClaim,
    ];

    /// The spelling in JSON reports: `user-supplied`, `user-pinned` or
    /// `unauthenticated-claim`.
    pub const fn code(self) -> &'static str {
        match self {
            Self::UserSupplied => "user-supplied",
            Self::UserPinned => "user-pinned",
            Self::UnauthenticatedClaim => "unauthenticated-claim",
        }
    }

    /// The spelling in text output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::UserSupplied => "user-supplied",
            Self::UserPinned => "user-pinned",
            Self::UnauthenticatedClaim => "unauthenticated claim",
        }
    }

    pub(crate) fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|o| o.code() == code)
    }
}

/// What kind of artifact a reference describes.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClaimedKind {
    /// A file (or a stream, which has the same kind of content).
    File,
    /// A directory tree.
    Directory,
}

impl ClaimedKind {
    /// `file` or `directory`.
    pub const fn code(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
        }
    }

    pub(crate) fn from_code(code: &str) -> Option<Self> {
        [Self::File, Self::Directory]
            .into_iter()
            .find(|k| k.code() == code)
    }

    /// Whether an artifact of `kind` is of this kind. A stream has the
    /// content of a file.
    pub fn admits(self, kind: ArtifactKind) -> bool {
        matches!(
            (self, kind),
            (Self::File, ArtifactKind::File | ArtifactKind::Stream)
                | (Self::Directory, ArtifactKind::Directory)
        )
    }
}

/// Which digest-set keys a set of digests is written with.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DigestKind {
    /// Content digests of a file or stream: `sha256`, …
    Content,
    /// Digests of a tree's NAR serialization: `narSha256`, …
    Tree,
}

impl DigestKind {
    /// The digest-set key for `algorithm`.
    pub fn key(self, algorithm: DigestAlgorithm) -> &'static str {
        match self {
            Self::Content => algorithm.name(),
            Self::Tree => algorithm.tree_name(),
        }
    }
}

/// Why a check did not run against a reference.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SkipReason {
    /// The manifest does not match the digest the user pinned, so its claims
    /// were not used.
    PinMismatch,
    /// The artifact could not be inspected.
    NotInspected,
    /// The artifact is not the kind of artifact the reference describes.
    KindMismatch,
}

impl SkipReason {
    const ALL: [SkipReason; 3] = [Self::PinMismatch, Self::NotInspected, Self::KindMismatch];

    /// `pin-mismatch`, `not-inspected` or `kind-mismatch`.
    pub const fn code(self) -> &'static str {
        match self {
            Self::PinMismatch => "pin-mismatch",
            Self::NotInspected => "not-inspected",
            Self::KindMismatch => "kind-mismatch",
        }
    }

    pub(crate) fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.code() == code)
    }
}

/// Supplied evidence that no check evaluated. What it is, is recorded with
/// the reference.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Unevaluated {
    /// A manifest claims a recipe, but no check rebuilt it.
    Recipe,
    /// The reference is a signed envelope, but no check verified it.
    Envelope,
}

impl Unevaluated {
    /// `recipe` or `envelope`.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Recipe => "recipe",
            Self::Envelope => "envelope",
        }
    }

    /// The check that would evaluate it.
    pub const fn check(self) -> CheckId {
        match self {
            Self::Recipe => CheckId::ReproducibilityRebuild,
            Self::Envelope => CheckId::AuthenticitySignature,
        }
    }
}

/// Why this version cannot evaluate a reference.
///
/// Values taken from the document are kept apart from the explanation, cut to
/// 256 characters, and only ever shown [quoted](crate::name::Quoted), so a
/// document cannot write any part of TrustForge's own sentences.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum UnsupportedReason {
    /// A statement of another type than in-toto Statement v1.
    StatementType {
        /// The statement type, as written.
        value: String,
    },
    /// A manifest of another predicate type or version.
    PredicateType {
        /// The predicate type, as written.
        value: String,
    },
    /// A digest set without any algorithm this version accepts.
    NoAcceptedAlgorithm {
        /// Where, as an RFC 6901 JSON Pointer.
        pointer: String,
    },
    /// A DSSE envelope: a signed attestation.
    DsseEnvelope,
    /// A Sigstore bundle.
    SigstoreBundle,
}

impl UnsupportedReason {
    /// `statement-type`, `predicate-type`, `no-accepted-algorithm`,
    /// `dsse-envelope` or `sigstore-bundle`.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::StatementType { .. } => "statement-type",
            Self::PredicateType { .. } => "predicate-type",
            Self::NoAcceptedAlgorithm { .. } => "no-accepted-algorithm",
            Self::DsseEnvelope => "dsse-envelope",
            Self::SigstoreBundle => "sigstore-bundle",
        }
    }

    /// Whether the reference is a signed envelope.
    pub const fn is_envelope(&self) -> bool {
        matches!(self, Self::DsseEnvelope | Self::SigstoreBundle)
    }

    /// For people: what the reference is, with any value from the document
    /// quoted.
    pub fn describe(&self) -> String {
        match self {
            Self::StatementType { value } => format!("a statement of type {}", Quoted(value)),
            Self::PredicateType { value } => format!("a manifest of type {}", Quoted(value)),
            Self::NoAcceptedAlgorithm { pointer } => format!(
                "a digest set without any algorithm this version accepts, at {}",
                Quoted(pointer)
            ),
            Self::DsseEnvelope => "a DSSE envelope (a signed attestation)".to_owned(),
            Self::SigstoreBundle => "a Sigstore bundle".to_owned(),
        }
    }
}

/// What a check observed. A result's status is computed from its evidence
/// alone (and the policy's accepted algorithms), by the same function when a
/// report is produced and when a saved report is read.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// No reference was supplied. Status `NOT_PROVIDED`.
    NoReference,
    /// The digests the reference claims, and those computed for the
    /// algorithms the policy accepts. `PASSED` when every claimed algorithm
    /// the policy accepts was computed and matches.
    Digests {
        /// Content or tree digests.
        kind: DigestKind,
        /// What the reference claims, including algorithms the policy does
        /// not accept.
        expected: DigestSet,
        /// What was computed, for the compared algorithms only.
        actual: Vec<Digest>,
    },
    /// The artifact is not the kind of artifact the reference describes.
    /// Status `FAILED`.
    KindMismatch {
        /// What the reference describes.
        expected: ClaimedKind,
        /// What the artifact is.
        actual: ArtifactKind,
    },
    /// The artifact could not be inspected; the report's artifact section
    /// says why. Status `ERROR`, or `UNSUPPORTED` when this platform cannot
    /// inspect such an artifact.
    NotInspected {
        /// Whether the failure is that the platform does not support it.
        unsupported: bool,
    },
    /// Not run. Status `SKIPPED`.
    Skipped(SkipReason),
    /// This version cannot evaluate the reference; its claim says why.
    /// Status `UNSUPPORTED`.
    UnsupportedReference,
    /// The claimed and the actual size. `PASSED` when equal.
    Size {
        /// The claimed size in bytes.
        expected: u64,
        /// The artifact's size in bytes.
        actual: u64,
    },
    /// The entry-by-entry comparison of a directory with a claimed listing.
    Tree(TreeComparison),
    /// The digest the user pinned for a manifest, and the manifest's own.
    /// `PASSED` when equal.
    Pin {
        /// The pinned digest.
        pinned: Digest,
        /// The SHA-256 of the manifest's exact bytes.
        actual: Digest,
    },
    /// Evidence no registered check can evaluate. Status `UNSUPPORTED`.
    NoCheck(Unevaluated),
    /// Another check already uses this identifier. Status `ERROR`.
    DuplicateCheck,
    /// The check returned evidence its identifier does not allow, or named
    /// a reference that does not exist. Status `ERROR`.
    InvalidEvidence,
}

/// The result of one check against one reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckResult {
    id: CheckId,
    reference: Option<usize>,
    evidence: Evidence,
    status: CheckStatus,
    summary: String,
}

impl CheckResult {
    pub(crate) fn new(
        id: CheckId,
        reference: Option<usize>,
        evidence: Evidence,
        accepted: &AlgorithmSet,
    ) -> Self {
        let status = status::check_status(&evidence, accepted);
        let summary = text::check_summary(&evidence, accepted);
        Self {
            id,
            reference,
            evidence,
            status,
            summary,
        }
    }

    /// The check's identifier.
    pub fn id(&self) -> CheckId {
        self.id
    }

    /// The check's dimension.
    pub fn dimension(&self) -> Dimension {
        self.id.dimension()
    }

    /// The index of the reference the result is about, if any.
    pub fn reference(&self) -> Option<usize> {
        self.reference
    }

    /// What the check observed.
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// The status, computed from the evidence.
    pub fn status(&self) -> CheckStatus {
        self.status
    }

    /// One line explaining the result, computed from the evidence.
    pub fn summary(&self) -> &str {
        &self.summary
    }
}

/// What can go wrong when an artifact is inspected, in reports.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FailureKind {
    /// The path does not exist.
    NotFound,
    /// Another error reported by the operating system.
    Io,
    /// A FIFO, socket or device.
    UnsupportedFileType,
    /// An invalid name inside a directory.
    InvalidName,
    /// An invalid symlink target inside a directory.
    InvalidSymlinkTarget,
    /// A directory listed a name twice.
    DuplicateEntry,
    /// The artifact changed while it was read.
    ConcurrentModification,
    /// A mount point inside a directory.
    MountPoint,
    /// A directory that is its own ancestor.
    DirectoryCycle,
    /// A resource limit was exceeded.
    LimitExceeded,
    /// Not supported on this platform.
    Unsupported,
    /// Any other failure.
    Other,
}

impl FailureKind {
    const ALL: [FailureKind; 12] = [
        Self::NotFound,
        Self::Io,
        Self::UnsupportedFileType,
        Self::InvalidName,
        Self::InvalidSymlinkTarget,
        Self::DuplicateEntry,
        Self::ConcurrentModification,
        Self::MountPoint,
        Self::DirectoryCycle,
        Self::LimitExceeded,
        Self::Unsupported,
        Self::Other,
    ];

    /// The spelling in reports, such as `not-found`.
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotFound => "not-found",
            Self::Io => "io",
            Self::UnsupportedFileType => "unsupported-file-type",
            Self::InvalidName => "invalid-name",
            Self::InvalidSymlinkTarget => "invalid-symlink-target",
            Self::DuplicateEntry => "duplicate-entry",
            Self::ConcurrentModification => "concurrent-modification",
            Self::MountPoint => "mount-point",
            Self::DirectoryCycle => "directory-cycle",
            Self::LimitExceeded => "limit-exceeded",
            Self::Unsupported => "unsupported",
            Self::Other => "other",
        }
    }

    pub(crate) fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.code() == code)
    }

    pub(crate) fn of(err: &InspectError) -> Self {
        match err {
            InspectError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
                Self::NotFound
            }
            InspectError::Io { .. } => Self::Io,
            InspectError::UnsupportedFileType { .. } => Self::UnsupportedFileType,
            InspectError::InvalidName { .. } => Self::InvalidName,
            InspectError::InvalidSymlinkTarget { .. } => Self::InvalidSymlinkTarget,
            InspectError::DuplicateEntry { .. } => Self::DuplicateEntry,
            InspectError::ConcurrentModification { .. } => Self::ConcurrentModification,
            InspectError::MountPoint { .. } => Self::MountPoint,
            InspectError::DirectoryCycle { .. } => Self::DirectoryCycle,
            InspectError::LimitExceeded { .. } => Self::LimitExceeded,
            InspectError::Unsupported { .. } => Self::Unsupported,
        }
    }
}

/// Why an artifact could not be inspected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactFailure {
    kind: FailureKind,
    message: String,
}

impl ArtifactFailure {
    pub(crate) fn new(kind: FailureKind, message: &str) -> Self {
        Self {
            kind,
            message: display_text(message, MAX_MESSAGE_CHARS),
        }
    }

    /// A failure as recorded in a saved report, kept as written.
    pub(crate) fn read(kind: FailureKind, message: String) -> Self {
        Self { kind, message }
    }

    /// What kind of failure.
    pub fn kind(&self) -> FailureKind {
        self.kind
    }

    /// The error message, in display form.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// What was learned about an artifact that was inspected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InspectedArtifact {
    kind: ArtifactKind,
    size: u64,
    digests: ArtifactDigests,
    entries: Option<u64>,
}

impl InspectedArtifact {
    pub(crate) fn new(
        kind: ArtifactKind,
        size: u64,
        digests: ArtifactDigests,
        entries: Option<u64>,
    ) -> Self {
        Self {
            kind,
            size,
            digests,
            entries,
        }
    }

    /// For a directory, the number of entries, not counting its root.
    pub fn entries(&self) -> Option<u64> {
        self.entries
    }

    /// File, directory or stream.
    pub fn kind(&self) -> ArtifactKind {
        self.kind
    }

    /// Size in bytes; for a directory, the total size of its regular files.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The digests computed.
    pub fn digests(&self) -> &ArtifactDigests {
        &self.digests
    }
}

/// The artifact a report or comparison is about: its name, and what
/// inspecting it found or why it failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactSummary {
    name: String,
    result: Result<InspectedArtifact, ArtifactFailure>,
}

impl ArtifactSummary {
    pub(crate) fn new(name: String, result: Result<InspectedArtifact, ArtifactFailure>) -> Self {
        Self { name, result }
    }

    pub(crate) fn of(name: String, inspection: &Result<Inspection, InspectError>) -> Self {
        let result = match inspection {
            Ok(inspection) => Ok(InspectedArtifact::new(
                inspection.kind(),
                inspection.size(),
                inspection.digests().clone(),
                inspection.entries().map(|entries| entries.len() as u64),
            )),
            Err(err) => Err(ArtifactFailure::new(FailureKind::of(err), &err.to_string())),
        };
        Self { name, result }
    }

    /// The name as given, in display form: characters unsafe for a terminal
    /// are escaped, so it is unambiguous to read but may not be unique.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What inspecting the artifact found, or why it failed.
    pub fn result(&self) -> Result<&InspectedArtifact, &ArtifactFailure> {
        self.result.as_ref()
    }
}

/// The artifact to verify or compare.
#[non_exhaustive]
pub enum ArtifactSource<'a> {
    /// A file or directory.
    Path(&'a Path),
    /// A stream, such as standard input, and the name to show for it.
    Reader {
        /// The name to show, such as `-`.
        name: &'a str,
        /// The stream.
        reader: Box<dyn Read + 'a>,
    },
}

impl ArtifactSource<'_> {
    /// Inspects the artifact: its display name, and the inspection.
    pub(crate) fn inspect(
        self,
        opts: &InspectOptions,
    ) -> (String, Result<Inspection, InspectError>) {
        match self {
            Self::Path(path) => (
                EscapedBytes(path.as_os_str().as_encoded_bytes()).to_string(),
                inspect_path(path, opts),
            ),
            Self::Reader { name, reader } => (
                EscapedBytes(name.as_bytes()).to_string(),
                inspect_reader(name, reader, opts),
            ),
        }
    }
}

/// A check of one aspect of an artifact against its references.
///
/// Its results' identifier and dimension come from [`Check::id`], never
/// from what [`Check::run`] returns, and their statuses are computed from
/// their evidence.
pub trait Check {
    /// The check's stable identifier, which also fixes its dimension.
    fn id(&self) -> CheckId;

    /// Runs the check: one outcome for each reference it applies to. It must
    /// not panic; a check that cannot complete says so in its evidence.
    fn run(&self, ctx: &CheckContext<'_>) -> Vec<Outcome>;
}

/// What a check can see.
#[non_exhaustive]
pub struct CheckContext<'a> {
    /// The inspection of the artifact, or why it failed.
    pub inspection: Result<&'a Inspection, &'a InspectError>,
    /// The references, in the order given.
    pub references: &'a [Reference],
    /// The policy.
    pub policy: &'a VerificationPolicy,
}

/// One outcome of a check: the reference it is about and what was observed.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// The index of the reference, if the outcome is about one.
    pub reference: Option<usize>,
    /// What was observed.
    pub evidence: Evidence,
}

impl Outcome {
    /// An outcome about `reference`.
    pub fn new(reference: Option<usize>, evidence: Evidence) -> Self {
        Self {
            reference,
            evidence,
        }
    }
}

/// Everything one verification needs.
#[non_exhaustive]
pub struct VerificationRequest<'a> {
    /// The artifact.
    pub artifact: ArtifactSource<'a>,
    /// The expected values to compare it with.
    pub references: Vec<Reference>,
    /// Checks to run in addition to the built-in ones, which always run.
    pub extra_checks: Vec<Box<dyn Check + 'a>>,
    /// What must be verified.
    pub policy: VerificationPolicy,
    /// Resource limits for inspecting the artifact.
    pub limits: Limits,
}

impl<'a> VerificationRequest<'a> {
    /// A request with no extra checks and default limits.
    pub fn new(
        artifact: ArtifactSource<'a>,
        references: Vec<Reference>,
        policy: VerificationPolicy,
    ) -> Self {
        Self {
            artifact,
            references,
            extra_checks: Vec::new(),
            policy,
            limits: Limits::default(),
        }
    }
}

/// The outcome of a verification: every check result, the status of each
/// dimension, and the overall status, with everything needed to explain
/// them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationReport {
    tool_version: String,
    artifact: ArtifactSummary,
    references: Vec<ReferenceSummary>,
    checks: Vec<CheckResult>,
    policy: VerificationPolicy,
    generated_at: Option<i64>,
    dimensions: Vec<(Dimension, DimensionStatus)>,
    overall: OverallStatus,
}

impl VerificationReport {
    /// Assembles a report, ordering the checks and computing every status.
    pub(crate) fn new(
        tool_version: String,
        artifact: ArtifactSummary,
        references: Vec<ReferenceSummary>,
        mut checks: Vec<CheckResult>,
        policy: VerificationPolicy,
        generated_at: Option<i64>,
    ) -> Self {
        checks.sort_by_key(|c| (c.dimension(), c.reference.map_or(0, |i| i + 1), c.id));
        let dimensions: Vec<_> = Dimension::ALL
            .into_iter()
            .map(|d| (d, status::dimension_status(d, &checks, references.len())))
            .collect();
        let overall = status::overall_status(&dimensions, &checks, &policy);
        Self {
            tool_version,
            artifact,
            references,
            checks,
            policy,
            generated_at,
            dimensions,
            overall,
        }
    }

    /// This report with the time it was produced, which reports leave out
    /// unless asked (decision 9). Times outside the years 0000–9999 are left
    /// out.
    pub fn with_generated_at(mut self, time: SystemTime) -> Self {
        let secs = match time.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(after) => i64::try_from(after.as_secs()).ok(),
            Err(before) => i64::try_from(before.duration().as_secs()).ok().map(|s| -s),
        };
        self.generated_at = secs.filter(|&s| time::rfc3339_utc(s).is_some());
        self
    }

    /// The version of TrustForge that produced the report.
    pub fn tool_version(&self) -> &str {
        &self.tool_version
    }

    /// The artifact.
    pub fn artifact(&self) -> &ArtifactSummary {
        &self.artifact
    }

    /// The references, in the order given.
    pub fn references(&self) -> &[ReferenceSummary] {
        &self.references
    }

    /// Every check result, by dimension, then reference, then check.
    pub fn checks(&self) -> &[CheckResult] {
        &self.checks
    }

    /// The policy.
    pub fn policy(&self) -> &VerificationPolicy {
        &self.policy
    }

    /// When the report was produced, as an RFC 3339 UTC timestamp, if that
    /// was asked for.
    pub fn generated_at(&self) -> Option<String> {
        self.generated_at.and_then(time::rfc3339_utc)
    }

    /// The status of every dimension, in report order.
    pub fn dimensions(&self) -> &[(Dimension, DimensionStatus)] {
        &self.dimensions
    }

    /// The status of `dimension`.
    pub fn dimension(&self, dimension: Dimension) -> DimensionStatus {
        self.dimensions
            .iter()
            .find(|(d, _)| *d == dimension)
            .map_or(
                DimensionStatus::NotEvaluated(NotEvaluatedReason::NotProvided),
                |(_, s)| *s,
            )
    }

    /// The overall status.
    pub fn overall(&self) -> OverallStatus {
        self.overall
    }
}

/// Characters an error message keeps in a report.
pub(crate) const MAX_MESSAGE_CHARS: usize = 4096;

/// What a report keeps at most, shared with the report reader.
pub(crate) mod limits {
    pub(crate) use super::reference::{MAX_QUOTED_CHARS, MAX_WARNINGS};
    pub(crate) use super::tree_diff::MAX_DIFFERENCES;
}

/// `text` in display form, cut to `max` characters with a final `…`.
pub(crate) fn display_text(text: &str, max: usize) -> String {
    let shown = EscapedBytes(text.as_bytes()).to_string();
    match shown.char_indices().nth(max) {
        Some((cut, _)) => format!("{}…", &shown[..cut]),
        None => shown,
    }
}

/// Inspects the artifact once, runs every check, and reports.
///
/// The built-in integrity checks always run; `request.extra_checks` run
/// after them. A check whose identifier is already taken gets an `ERROR`
/// result, and so does an outcome whose evidence its identifier does not
/// allow, or that disagrees with the artifact or the reference it names:
/// every outcome must meet the rules a saved report is held to. Evidence
/// that no check evaluated (a claimed recipe, a signed envelope) gets an
/// explicit `UNSUPPORTED` result. Panics are not caught: a bug ends the
/// process with an internal error, never with success.
pub fn verify(request: VerificationRequest<'_>) -> VerificationReport {
    let VerificationRequest {
        artifact,
        references,
        extra_checks,
        policy,
        limits,
    } = request;
    let opts = InspectOptions {
        algorithms: algorithms_for(&references, &policy),
        limits,
    };
    let (name, inspection) = artifact.inspect(&opts);
    let accepted = policy.accepted_algorithms();
    let ctx = CheckContext {
        inspection: inspection.as_ref(),
        references: &references,
        policy: &policy,
    };

    let artifact = ArtifactSummary::of(name, &inspection);
    let summaries: Vec<ReferenceSummary> = references.iter().map(Reference::summary).collect();

    let builtins: [&dyn Check; 4] = [
        &integrity::ManifestPin,
        &integrity::DigestCheck,
        &integrity::SizeCheck,
        &integrity::TreeCheck,
    ];
    let mut results = Vec::new();
    let mut ids = BTreeSet::new();
    for check in builtins
        .into_iter()
        .chain(extra_checks.iter().map(|c| c.as_ref()))
    {
        let id = check.id();
        if !ids.insert(id) {
            results.push(CheckResult::new(
                id,
                None,
                Evidence::DuplicateCheck,
                accepted,
            ));
            continue;
        }
        for outcome in check.run(&ctx) {
            // The rules a saved report must meet apply to every outcome, so
            // that no check can claim more than a report could hold.
            let valid = evidence_allowed(id, &outcome.evidence)
                && consistency::evidence_agrees(
                    &outcome.evidence,
                    outcome.reference,
                    &artifact,
                    &summaries,
                )
                .is_ok();
            let (reference, evidence) = if valid {
                (outcome.reference, outcome.evidence)
            } else {
                (None, Evidence::InvalidEvidence)
            };
            results.push(CheckResult::new(id, reference, evidence, accepted));
        }
    }
    // Evidence that no check evaluated gets an explicit UNSUPPORTED result.
    let evaluated = consistency::evaluated(&results);
    for (i, reference) in references.iter().enumerate() {
        for unevaluated in reference.unevaluated() {
            let id = unevaluated.check();
            if !evaluated.contains(&(id.dimension(), i)) {
                results.push(CheckResult::new(
                    id,
                    Some(i),
                    Evidence::NoCheck(unevaluated),
                    accepted,
                ));
            }
        }
    }

    VerificationReport::new(
        TOOL_VERSION.to_owned(),
        artifact,
        summaries,
        results,
        policy,
        None,
    )
}

/// The digest algorithms to compute: every algorithm the policy accepts that
/// any reference claims, including those of a listing's files, so that each
/// claimed digest can be compared. SHA-256 alone if there are none.
fn algorithms_for(references: &[Reference], policy: &VerificationPolicy) -> AlgorithmSet {
    let accepted = policy.accepted_algorithms();
    let claimed = references
        .iter()
        .flat_map(Reference::claimed_algorithms)
        .filter(|a| accepted.contains(*a));
    AlgorithmSet::new(claimed)
        .unwrap_or_else(|_| AlgorithmSet::new([DigestAlgorithm::Sha256]).unwrap_or_default())
}

/// Which evidence each check may report: the same table governs the checks
/// that run and the reports that are read back.
pub(crate) fn evidence_allowed(id: CheckId, evidence: &Evidence) -> bool {
    use Evidence as E;
    match evidence {
        E::DuplicateCheck | E::InvalidEvidence => true,
        _ => match id {
            CheckId::IntegrityManifest => matches!(evidence, E::Pin { .. }),
            CheckId::IntegrityDigest => matches!(
                evidence,
                E::NoReference
                    | E::Digests { .. }
                    | E::KindMismatch { .. }
                    | E::NotInspected { .. }
                    | E::Skipped(SkipReason::PinMismatch)
                    | E::UnsupportedReference
            ),
            CheckId::IntegritySize => matches!(
                evidence,
                E::Size { .. } | E::Skipped(SkipReason::NotInspected | SkipReason::KindMismatch)
            ),
            CheckId::IntegrityTree => matches!(
                evidence,
                E::Tree(_) | E::Skipped(SkipReason::NotInspected | SkipReason::KindMismatch)
            ),
            CheckId::AuthenticitySignature => {
                matches!(evidence, E::NoCheck(Unevaluated::Envelope))
            }
            CheckId::ReproducibilityRebuild => matches!(evidence, E::NoCheck(Unevaluated::Recipe)),
        },
    }
}

/// The views of an inspection's entries, for the tree comparison.
pub(crate) fn entry_views(entries: &[crate::inspect::TreeEntry]) -> impl Iterator<Item = View<'_>> {
    entries.iter().map(|entry| View {
        path: entry.path(),
        kind: match entry.kind() {
            EntryKind::File {
                executable,
                size,
                digest,
            } => tree_diff::ViewKind::File {
                executable: *executable,
                size: *size,
                digest,
            },
            EntryKind::Symlink { target, .. } => tree_diff::ViewKind::Symlink { target },
            EntryKind::Directory => tree_diff::ViewKind::Directory,
        },
    })
}

#[cfg(test)]
mod tests;
