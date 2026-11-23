//! The built-in integrity checks: the pinned manifest, the digests, the
//! size and the directory listing. They always run.

use super::reference::Claim;
use super::{
    Check, CheckContext, CheckId, ClaimedKind, DigestKind, Evidence, Outcome, ReferenceSource,
    SkipReason, entry_views, tree_diff,
};
use crate::inspect::{ArtifactDigests, InspectError, Inspection};

/// `integrity.manifest`: a pinned manifest's SHA-256 is the pinned digest.
pub(crate) struct ManifestPin;

/// `integrity.digest`: exactly one result per reference.
pub(crate) struct DigestCheck;

/// `integrity.size`: for references that claim a size.
pub(crate) struct SizeCheck;

/// `integrity.tree`: for references with a directory listing.
pub(crate) struct TreeCheck;

impl Check for ManifestPin {
    fn id(&self) -> CheckId {
        CheckId::IntegrityManifest
    }

    fn run(&self, ctx: &CheckContext<'_>) -> Vec<Outcome> {
        ctx.references
            .iter()
            .enumerate()
            .filter_map(|(i, reference)| match reference.source() {
                ReferenceSource::Manifest {
                    sha256,
                    pinned: Some(pinned),
                    ..
                } => Some(Outcome::new(
                    Some(i),
                    Evidence::Pin {
                        pinned: pinned.clone(),
                        actual: sha256.clone(),
                    },
                )),
                _ => None,
            })
            .collect()
    }
}

impl Check for DigestCheck {
    fn id(&self) -> CheckId {
        CheckId::IntegrityDigest
    }

    fn run(&self, ctx: &CheckContext<'_>) -> Vec<Outcome> {
        // An artifact that could not be read makes verification fail,
        // whatever the references are: the check could not complete.
        let inspection = match ctx.inspection {
            Ok(inspection) => inspection,
            Err(err) => {
                let evidence = Evidence::NotInspected {
                    unsupported: matches!(err, InspectError::Unsupported { .. }),
                };
                if ctx.references.is_empty() {
                    return vec![Outcome::new(None, evidence)];
                }
                return (0..ctx.references.len())
                    .map(|i| Outcome::new(Some(i), evidence.clone()))
                    .collect();
            }
        };
        if ctx.references.is_empty() {
            return vec![Outcome::new(None, Evidence::NoReference)];
        }
        ctx.references
            .iter()
            .enumerate()
            .map(|(i, reference)| {
                Outcome::new(Some(i), digest_evidence(reference.claim(), inspection, ctx))
            })
            .collect()
    }
}

fn digest_evidence(claim: &Claim, inspection: &Inspection, ctx: &CheckContext<'_>) -> Evidence {
    let (kind, expected) = match claim {
        Claim::Unusable => return Evidence::Skipped(SkipReason::PinMismatch),
        Claim::Unsupported(_) => return Evidence::UnsupportedReference,
        Claim::File { digest, .. } => (ClaimedKind::File, digest),
        Claim::Directory { tree_digest, .. } => (ClaimedKind::Directory, tree_digest),
    };
    // Content and tree digests can never stand in for each other.
    let (digest_kind, computed) = match (kind, inspection.digests()) {
        (ClaimedKind::File, ArtifactDigests::Content(digests))
            if kind.admits(inspection.kind()) =>
        {
            (DigestKind::Content, digests)
        }
        (ClaimedKind::Directory, ArtifactDigests::Tree(digests))
            if kind.admits(inspection.kind()) =>
        {
            (DigestKind::Tree, digests)
        }
        _ => {
            return Evidence::KindMismatch {
                expected: kind,
                actual: inspection.kind(),
            };
        }
    };
    let accepted = ctx.policy.accepted_algorithms();
    let actual = expected
        .algorithms()
        .filter(|algorithm| accepted.contains(*algorithm))
        .filter_map(|algorithm| computed.get(algorithm).cloned())
        .collect();
    Evidence::Digests {
        kind: digest_kind,
        expected: expected.clone(),
        actual,
    }
}

/// The inspection, if the artifact was inspected and is the kind of
/// artifact the reference describes.
fn applicable<'a>(kind: ClaimedKind, ctx: &CheckContext<'a>) -> Result<&'a Inspection, SkipReason> {
    match ctx.inspection {
        Err(_) => Err(SkipReason::NotInspected),
        Ok(inspection) if !kind.admits(inspection.kind()) => Err(SkipReason::KindMismatch),
        Ok(inspection) => Ok(inspection),
    }
}

impl Check for SizeCheck {
    fn id(&self) -> CheckId {
        CheckId::IntegritySize
    }

    fn run(&self, ctx: &CheckContext<'_>) -> Vec<Outcome> {
        ctx.references
            .iter()
            .enumerate()
            .filter_map(|(i, reference)| {
                let (kind, expected) = match reference.claim() {
                    Claim::File {
                        size: Some(size), ..
                    } => (ClaimedKind::File, *size),
                    Claim::Directory {
                        size: Some(size), ..
                    } => (ClaimedKind::Directory, *size),
                    _ => return None,
                };
                let evidence = match applicable(kind, ctx) {
                    Ok(inspection) => Evidence::Size {
                        expected,
                        actual: inspection.size(),
                    },
                    Err(reason) => Evidence::Skipped(reason),
                };
                Some(Outcome::new(Some(i), evidence))
            })
            .collect()
    }
}

impl Check for TreeCheck {
    fn id(&self) -> CheckId {
        CheckId::IntegrityTree
    }

    fn run(&self, ctx: &CheckContext<'_>) -> Vec<Outcome> {
        ctx.references
            .iter()
            .enumerate()
            .filter_map(|(i, reference)| {
                let Claim::Directory {
                    tree: Some(tree), ..
                } = reference.claim()
                else {
                    return None;
                };
                let evidence = match applicable(ClaimedKind::Directory, ctx) {
                    Ok(inspection) => Evidence::Tree(tree_diff::compare(
                        tree_diff::claim_views(tree),
                        entry_views(inspection.entries().unwrap_or_default()),
                        ctx.policy.accepted_algorithms(),
                    )),
                    Err(reason) => Evidence::Skipped(reason),
                };
                Some(Outcome::new(Some(i), evidence))
            })
            .collect()
    }
}
