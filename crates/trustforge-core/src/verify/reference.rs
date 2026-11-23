//! References: the expected values an artifact is compared with, each
//! tagged with its origin.
//!
//! A reference is built from digests the user supplies directly, or from a
//! manifest. A manifest is read once, in this order:
//! 1. its size is checked, so that a document over the limit is rejected
//!    rather than hashed truncated;
//! 2. the SHA-256 of its exact bytes is computed: its identity, which every
//!    report shows;
//! 3. if the user pinned a digest and it differs, the manifest is **not
//!    parsed at all**: its claims are unusable, and the pin check fails;
//! 4. it is parsed as strict JSON;
//! 5. a signed envelope (DSSE, or a Sigstore bundle) is recognized as such
//!    and reported as unsupported, never misread as an invalid manifest;
//! 6. it is validated as a manifest. A manifest of another version, or one
//!    that uses only digest algorithms this version does not know, is a
//!    reference this version cannot evaluate (`UNSUPPORTED`).

use super::{ClaimedKind, ReferenceOrigin, Unevaluated, UnsupportedReason, display_text};
use crate::digest::{Digest, DigestAlgorithm, DigestSet};
use crate::inspect::ArtifactDigests;
use crate::json::{self, JsonError, Pointer, StrictValue};
use crate::manifest::{
    self, ArtifactClaim, BuildDefinition, CARGO_BUILD_TYPE_V0, EntryClaimKind, ManifestError,
    ParseOptions, Problem, TreeEntryClaim, Unsupported, WarningKind,
};
use crate::name::{EscapedBytes, shortened};

/// At most this many manifest warnings are kept with a reference.
pub(crate) const MAX_WARNINGS: usize = 100;

/// At most about this many bytes of warning locations are kept: a key, and
/// so a location, can be as long as the document.
pub(crate) const MAX_WARNING_BYTES: usize = 64 << 10;

/// Characters kept of a value quoted from a document.
pub(crate) const MAX_QUOTED_CHARS: usize = 256;

/// An expected value to compare an artifact with, and where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    origin: ReferenceOrigin,
    source: ReferenceSource,
    claim: Claim,
    recipe: Option<String>,
    warnings: Vec<WarningSummary>,
    warnings_omitted: u64,
}

/// Where a reference came from.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReferenceSource {
    /// Digests the user gave directly, such as with `--expect`.
    Expected,
    /// A manifest.
    Manifest {
        /// The manifest's path as given, in display form.
        path: String,
        /// The SHA-256 of its exact bytes: its identity.
        sha256: Digest,
        /// The digest the user pinned for it, if any.
        pinned: Option<Digest>,
    },
}

/// What a reference claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Claim {
    File {
        digest: DigestSet,
        size: Option<u64>,
    },
    Directory {
        tree_digest: DigestSet,
        size: Option<u64>,
        tree: Option<Vec<TreeEntryClaim>>,
    },
    Unsupported(UnsupportedReason),
    Unusable,
}

/// What a report records about a reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceSummary {
    origin: ReferenceOrigin,
    source: ReferenceSource,
    claim: ClaimSummary,
    recipe: Option<String>,
    warnings: Vec<WarningSummary>,
    warnings_omitted: u64,
}

/// What a reference claims, as a report records it.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimSummary {
    /// A file (or stream).
    File {
        /// The claimed size, if any.
        size: Option<u64>,
    },
    /// A directory.
    Directory {
        /// The claimed total size of its regular files, if any.
        size: Option<u64>,
        /// The number of entries its listing has, if it has one.
        entries: Option<u64>,
    },
    /// Something this version cannot evaluate.
    Unsupported {
        /// Why.
        reason: UnsupportedReason,
    },
    /// Nothing usable: the manifest does not match the digest the user
    /// pinned, so it was not read.
    Unusable,
}

/// A note about an accepted manifest, as a report records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WarningSummary {
    pointer: String,
    kind: WarningKind,
}

impl WarningSummary {
    pub(crate) fn new(pointer: String, kind: WarningKind) -> Self {
        Self { pointer, kind }
    }

    /// Where, as an RFC 6901 JSON Pointer into the manifest.
    pub fn pointer(&self) -> &str {
        &self.pointer
    }

    /// What.
    pub fn kind(&self) -> &WarningKind {
        &self.kind
    }
}

impl Reference {
    /// Digests the user supplied directly, such as with `--expect`: content
    /// digests describe a file or stream, tree digests a directory.
    pub fn expected(digests: ArtifactDigests) -> Self {
        let claim = match digests {
            ArtifactDigests::Content(digest) => Claim::File { digest, size: None },
            ArtifactDigests::Tree(tree_digest) => Claim::Directory {
                tree_digest,
                size: None,
                tree: None,
            },
        };
        Self {
            origin: ReferenceOrigin::UserSupplied,
            source: ReferenceSource::Expected,
            claim,
            recipe: None,
            warnings: Vec::new(),
            warnings_omitted: 0,
        }
    }

    /// The claims of the manifest whose exact bytes are `bytes`, read from
    /// `path`. With `pinned`, the manifest is used only if its SHA-256 is
    /// that digest; otherwise its claims are unusable and it is not parsed
    /// (any digest of another algorithm never matches).
    ///
    /// Returns an error for a document that is too large, is not strict
    /// JSON, or breaks a rule of the specification. A document this version
    /// cannot evaluate, such as a signed envelope or another manifest
    /// version, is a reference with unsupported claims instead.
    pub fn from_manifest(
        bytes: &[u8],
        path: &str,
        pinned: Option<&Digest>,
        opts: &ParseOptions,
    ) -> Result<Self, ManifestError> {
        let max = opts.limits.max_bytes;
        if bytes.len() > max {
            return Err(ManifestError::Json(JsonError::TooLarge {
                size: bytes.len(),
                max,
            }));
        }
        let sha256 = Digest::of(DigestAlgorithm::Sha256, bytes);
        let mut reference = Self {
            origin: if pinned.is_some() {
                ReferenceOrigin::UserPinned
            } else {
                ReferenceOrigin::UnauthenticatedClaim
            },
            source: ReferenceSource::Manifest {
                path: EscapedBytes(path.as_bytes()).to_string(),
                sha256: sha256.clone(),
                pinned: pinned.cloned(),
            },
            claim: Claim::Unusable,
            recipe: None,
            warnings: Vec::new(),
            warnings_omitted: 0,
        };
        if pinned.is_some_and(|pinned| *pinned != sha256) {
            return Ok(reference);
        }
        let value = json::parse(bytes, &opts.limits)?;
        if let Some(reason) = envelope(&value) {
            reference.claim = Claim::Unsupported(reason);
            return Ok(reference);
        }
        let (manifest, warnings) = match manifest::read_value(&value, opts.strict) {
            Ok(read) => read,
            Err(ManifestError::Unsupported { pointer, what }) => {
                reference.claim = Claim::Unsupported(unsupported_reason(&pointer, what));
                return Ok(reference);
            }
            Err(e) => return Err(e),
        };
        reference.claim = match (manifest.artifact(), manifest.subjects()) {
            (ArtifactClaim::File { size }, [subject]) => Claim::File {
                digest: subject.digest().clone(),
                size: *size,
            },
            (
                ArtifactClaim::Directory {
                    size,
                    tree,
                    tree_digest,
                },
                _,
            ) => Claim::Directory {
                tree_digest: tree_digest.clone(),
                size: *size,
                tree: Some(tree.clone()),
            },
            // Validation guarantees one subject for a file; fail closed.
            _ => {
                return Err(manifest::invalid(
                    &Pointer::root().key("subject"),
                    Problem::Rule("a file artifact has exactly one subject"),
                ));
            }
        };
        reference.recipe = manifest
            .build_definition()
            .map(|definition| match definition {
                BuildDefinition::Cargo(_) => CARGO_BUILD_TYPE_V0.to_owned(),
                BuildDefinition::Unsupported { build_type, .. } => {
                    display_text(build_type, MAX_QUOTED_CHARS)
                }
            });
        let mut bytes_kept = 0;
        for warning in warnings {
            let pointer = display_text(&warning.pointer.to_rfc6901(), usize::MAX);
            if reference.warnings.len() < MAX_WARNINGS
                && bytes_kept + pointer.len() <= MAX_WARNING_BYTES
            {
                bytes_kept += pointer.len();
                reference
                    .warnings
                    .push(WarningSummary::new(pointer, warning.kind));
            } else {
                reference.warnings_omitted = reference.warnings_omitted.saturating_add(1);
            }
        }
        Ok(reference)
    }

    /// Where the reference came from, which limits what it can establish.
    pub fn origin(&self) -> ReferenceOrigin {
        self.origin
    }

    /// Where the reference came from.
    pub fn source(&self) -> &ReferenceSource {
        &self.source
    }

    /// Warnings about the manifest, as many as are kept.
    pub fn warnings(&self) -> &[WarningSummary] {
        &self.warnings
    }

    pub(crate) fn claim(&self) -> &Claim {
        &self.claim
    }

    /// The digest algorithms the reference claims digests for, including
    /// those of a listing's files.
    pub(crate) fn claimed_algorithms(&self) -> Vec<DigestAlgorithm> {
        match &self.claim {
            Claim::File { digest, .. } => digest.algorithms().collect(),
            Claim::Directory {
                tree_digest, tree, ..
            } => {
                let mut algorithms: Vec<_> = tree_digest.algorithms().collect();
                for entry in tree.iter().flatten() {
                    if let EntryClaimKind::File { digest, .. } = entry.kind() {
                        algorithms.extend(digest.algorithms());
                    }
                }
                algorithms
            }
            Claim::Unsupported(_) | Claim::Unusable => Vec::new(),
        }
    }

    /// Evidence in this reference that needs a check of another dimension.
    pub(crate) fn unevaluated(&self) -> Vec<Unevaluated> {
        let mut out = Vec::new();
        if self.recipe.is_some() {
            out.push(Unevaluated::Recipe);
        }
        if matches!(&self.claim, Claim::Unsupported(reason) if reason.is_envelope()) {
            out.push(Unevaluated::Envelope);
        }
        out
    }

    /// What a report records about this reference.
    pub(crate) fn summary(&self) -> ReferenceSummary {
        let claim = match &self.claim {
            Claim::File { size, .. } => ClaimSummary::File { size: *size },
            Claim::Directory { size, tree, .. } => ClaimSummary::Directory {
                size: *size,
                entries: tree.as_ref().map(|t| t.len() as u64),
            },
            Claim::Unsupported(reason) => ClaimSummary::Unsupported {
                reason: reason.clone(),
            },
            Claim::Unusable => ClaimSummary::Unusable,
        };
        ReferenceSummary {
            origin: self.origin,
            source: self.source.clone(),
            claim,
            recipe: self.recipe.clone(),
            warnings: self.warnings.clone(),
            warnings_omitted: self.warnings_omitted,
        }
    }
}

impl ReferenceSummary {
    pub(crate) fn new(
        origin: ReferenceOrigin,
        source: ReferenceSource,
        claim: ClaimSummary,
        recipe: Option<String>,
        warnings: Vec<WarningSummary>,
        warnings_omitted: u64,
    ) -> Self {
        Self {
            origin,
            source,
            claim,
            recipe,
            warnings,
            warnings_omitted,
        }
    }

    /// Where the reference came from, which limits what it can establish.
    pub fn origin(&self) -> ReferenceOrigin {
        self.origin
    }

    /// Where the reference came from.
    pub fn source(&self) -> &ReferenceSource {
        &self.source
    }

    /// What it claims.
    pub fn claim(&self) -> &ClaimSummary {
        &self.claim
    }

    /// The build type of the recipe a manifest claims, in display form, cut
    /// to 256 characters. A value from the document: show it quoted.
    pub fn recipe(&self) -> Option<&str> {
        self.recipe.as_deref()
    }

    /// Warnings about the manifest, as many as were kept.
    pub fn warnings(&self) -> &[WarningSummary] {
        &self.warnings
    }

    /// How many further warnings there were.
    pub fn warnings_omitted(&self) -> u64 {
        self.warnings_omitted
    }

    /// The kind of artifact it describes, if it can be evaluated.
    pub fn claimed_kind(&self) -> Option<ClaimedKind> {
        match self.claim {
            ClaimSummary::File { .. } => Some(ClaimedKind::File),
            ClaimSummary::Directory { .. } => Some(ClaimedKind::Directory),
            ClaimSummary::Unsupported { .. } | ClaimSummary::Unusable => None,
        }
    }

    /// The size it claims, if it claims one.
    pub fn claimed_size(&self) -> Option<u64> {
        match self.claim {
            ClaimSummary::File { size } | ClaimSummary::Directory { size, .. } => size,
            ClaimSummary::Unsupported { .. } | ClaimSummary::Unusable => None,
        }
    }
}

/// Why a manifest that the manifest reader found unsupported cannot be
/// evaluated.
fn unsupported_reason(pointer: &Pointer, what: Unsupported) -> UnsupportedReason {
    match what {
        Unsupported::StatementType(value) => UnsupportedReason::StatementType {
            value: shortened(&value, MAX_QUOTED_CHARS),
        },
        Unsupported::PredicateType(value) => UnsupportedReason::PredicateType {
            value: shortened(&value, MAX_QUOTED_CHARS),
        },
        Unsupported::NoAcceptedAlgorithm => UnsupportedReason::NoAcceptedAlgorithm {
            pointer: shortened(&pointer.to_rfc6901(), MAX_QUOTED_CHARS),
        },
    }
}

/// What kind of signed envelope `value` is, if it is one: a DSSE envelope,
/// or a Sigstore bundle.
fn envelope(value: &StrictValue) -> Option<UnsupportedReason> {
    let StrictValue::Object(members) = value else {
        return None;
    };
    if members.contains_key("payloadType") && members.contains_key("signatures") {
        return Some(UnsupportedReason::DsseEnvelope);
    }
    match members.get("mediaType") {
        Some(StrictValue::String(media))
            if media.starts_with("application/vnd.dev.sigstore.bundle") =>
        {
            Some(UnsupportedReason::SigstoreBundle)
        }
        _ => None,
    }
}
