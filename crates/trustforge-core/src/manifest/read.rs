//! Reading a [`StrictValue`] into a validated [`Manifest`], field by field.
//!
//! Every object is checked against the fields this version defines before
//! any of them is used:
//! - a key that differs from a defined field only in letter case is always
//!   an error, because some JSON parsers match field names
//!   case-insensitively (Go's, even with Unicode case folding) and would
//!   read a different field than TrustForge;
//! - other unknown keys are ignored with a warning, or rejected where they
//!   could change what gets built.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};

use super::{
    ArtifactClaim, BuildDefinition, CARGO_BUILD_TYPE_V0, EntryClaimKind, Manifest, ManifestError,
    ManifestWarning, PREDICATE_TYPE_V0, Problem, STATEMENT_TYPE, Subject, TreeEntryClaim,
    Unsupported, WarningKind, cargo, invalid,
};
use crate::digest::{Digest, DigestAlgorithm, DigestError, DigestSet};
use crate::json::{Pointer, StrictValue};
use crate::name::{RelPath, shortened, validate_symlink_target};

/// Warnings collected while reading.
#[derive(Default)]
pub(super) struct Context {
    warnings: Vec<ManifestWarning>,
}

impl Context {
    pub(super) fn warn(&mut self, pointer: Pointer, kind: WarningKind) {
        self.warnings.push(ManifestWarning { pointer, kind });
    }

    /// The warnings; in strict mode, the first warning becomes an error.
    pub(super) fn finish(self, strict: bool) -> Result<Vec<ManifestWarning>, ManifestError> {
        if strict && let Some(first) = self.warnings.first() {
            return Err(invalid(&first.pointer, Problem::Strict(first.kind.clone())));
        }
        Ok(self.warnings)
    }
}

/// What to do with keys a level does not define.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Unknown {
    /// Ignore them, with a warning (the in-toto rule).
    Warn,
    /// Reject them, because they could change what gets built.
    Reject,
}

/// An object whose keys have been checked against the fields it may have.
pub(super) struct Fields<'v> {
    members: &'v BTreeMap<String, StrictValue>,
    at: Pointer,
}

impl<'v> Fields<'v> {
    pub(super) fn new(
        value: &'v StrictValue,
        at: &Pointer,
        known: &[&'static str],
        unknown: Unknown,
        ctx: &mut Context,
    ) -> Result<Self, ManifestError> {
        let StrictValue::Object(members) = value else {
            return Err(invalid(at, Problem::WrongType("an object")));
        };
        for key in members.keys() {
            if known.contains(&key.as_str()) {
                continue;
            }
            if let Some(field) = known.iter().copied().find(|field| folds_to(key, field)) {
                return Err(invalid(&at.key(key), Problem::CaseVariant(field)));
            }
            match unknown {
                Unknown::Warn => ctx.warn(at.key(key), WarningKind::UnknownField),
                Unknown::Reject => return Err(invalid(&at.key(key), Problem::UnknownField)),
            }
        }
        Ok(Self {
            members,
            at: at.clone(),
        })
    }

    pub(super) fn optional(&self, key: &str) -> Option<(&'v StrictValue, Pointer)> {
        self.members.get(key).map(|value| (value, self.at.key(key)))
    }

    pub(super) fn required(&self, key: &str) -> Result<(&'v StrictValue, Pointer), ManifestError> {
        self.optional(key)
            .ok_or_else(|| invalid(&self.at.key(key), Problem::Missing))
    }

    pub(super) fn has(&self, key: &str) -> bool {
        self.members.contains_key(key)
    }
}

/// Whether `key` equals the ASCII field name `field` under case folding,
/// including the Unicode characters that fold to ASCII letters, such as
/// U+017F (long s) and U+212A (Kelvin sign).
pub(super) fn folds_to(key: &str, field: &str) -> bool {
    key.chars()
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .eq(field.chars().map(|c| c.to_ascii_lowercase()))
}

pub(super) fn string<'v>(value: &'v StrictValue, at: &Pointer) -> Result<&'v str, ManifestError> {
    match value {
        StrictValue::String(s) => Ok(s),
        _ => Err(invalid(at, Problem::WrongType("a string"))),
    }
}

pub(super) fn integer(value: &StrictValue, at: &Pointer) -> Result<u64, ManifestError> {
    match value {
        StrictValue::Integer(n) => Ok(*n),
        _ => Err(invalid(at, Problem::WrongType("an integer"))),
    }
}

pub(super) fn boolean(value: &StrictValue, at: &Pointer) -> Result<bool, ManifestError> {
    match value {
        StrictValue::Bool(b) => Ok(*b),
        _ => Err(invalid(at, Problem::WrongType("true or false"))),
    }
}

pub(super) fn array<'v>(
    value: &'v StrictValue,
    at: &Pointer,
) -> Result<&'v [StrictValue], ManifestError> {
    match value {
        StrictValue::Array(items) => Ok(items),
        _ => Err(invalid(at, Problem::WrongType("an array"))),
    }
}

fn rel_path(value: &StrictValue, at: &Pointer) -> Result<RelPath, ManifestError> {
    RelPath::parse(string(value, at)?).map_err(|e| invalid(at, Problem::Name(e)))
}

/// Reads a whole Statement.
pub(super) fn statement(value: &StrictValue, ctx: &mut Context) -> Result<Manifest, ManifestError> {
    let root = Pointer::root();
    let fields = Fields::new(
        value,
        &root,
        &["_type", "subject", "predicateType", "predicate"],
        Unknown::Warn,
        ctx,
    )?;

    // The type and version are checked before anything else is interpreted.
    let (statement_type, at) = fields.required("_type")?;
    let statement_type = string(statement_type, &at)?;
    if statement_type != STATEMENT_TYPE {
        return Err(unsupported(&at, Unsupported::StatementType, statement_type));
    }
    let (predicate_type, at) = fields.required("predicateType")?;
    let predicate_type = string(predicate_type, &at)?;
    if predicate_type != PREDICATE_TYPE_V0 {
        return Err(unsupported(&at, Unsupported::PredicateType, predicate_type));
    }

    let (subject_value, subject_at) = fields.required("subject")?;
    let subjects = subjects(subject_value, &subject_at, ctx)?;

    let (predicate, at) = fields.required("predicate")?;
    let predicate = Fields::new(
        predicate,
        &at,
        &["artifact", "buildDefinition"],
        Unknown::Warn,
        ctx,
    )?;
    let (artifact_value, artifact_at) = predicate.required("artifact")?;
    let artifact = artifact(artifact_value, &artifact_at, ctx)?;
    check_subjects_match_artifact(&subjects, &subject_at, &artifact, &artifact_at)?;
    let build_definition = match predicate.optional("buildDefinition") {
        Some((value, at)) => Some(build_definition(value, &at, ctx)?),
        None => None,
    };
    Ok(Manifest {
        subjects,
        artifact,
        build_definition,
    })
}

/// Values quoted from a document are cut to this many characters.
const MAX_QUOTED_CHARS: usize = 256;

fn unsupported(at: &Pointer, what: fn(String) -> Unsupported, value: &str) -> ManifestError {
    ManifestError::Unsupported {
        pointer: at.clone(),
        what: what(shortened(value, MAX_QUOTED_CHARS)),
    }
}

fn subjects(
    value: &StrictValue,
    at: &Pointer,
    ctx: &mut Context,
) -> Result<Vec<Subject>, ManifestError> {
    let items = array(value, at)?;
    if items.is_empty() {
        return Err(invalid(
            at,
            Problem::Rule("must contain at least one subject"),
        ));
    }
    let mut names = HashSet::new();
    let mut subjects = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let at = at.index(i);
        let fields = Fields::new(item, &at, &["name", "digest"], Unknown::Warn, ctx)?;
        let (name, name_at) = fields.required("name")?;
        let name = rel_path(name, &name_at)?;
        if !names.insert(name.as_str().to_owned()) {
            return Err(invalid(
                &name_at,
                Problem::Rule("subject names must be unique"),
            ));
        }
        let (digest, digest_at) = fields.required("digest")?;
        let digest = content_digests(digest, &digest_at, ctx)?;
        if digest.get(DigestAlgorithm::Sha256).is_none() {
            ctx.warn(digest_at, WarningKind::MissingSha256);
        }
        subjects.push(Subject { name, digest });
    }
    Ok(subjects)
}

/// A digest set keyed by algorithm names (`sha256`, …).
pub(super) fn content_digests(
    value: &StrictValue,
    at: &Pointer,
    ctx: &mut Context,
) -> Result<DigestSet, ManifestError> {
    digest_set(value, at, ctx, |key| match key.parse::<DigestAlgorithm>() {
        Ok(algorithm) => Key::Accepted(algorithm),
        Err(DigestError::InsecureAlgorithm { .. }) => Key::Insecure,
        Err(_) => Key::Other,
    })
}

/// A digest set keyed by tree digest names (`narSha256`, …).
fn tree_digests(
    value: &StrictValue,
    at: &Pointer,
    ctx: &mut Context,
) -> Result<DigestSet, ManifestError> {
    digest_set(
        value,
        at,
        ctx,
        |key| match DigestAlgorithm::from_tree_name(key) {
            Some(algorithm) => Key::Accepted(algorithm),
            None => Key::Other,
        },
    )
}

enum Key {
    Accepted(DigestAlgorithm),
    Insecure,
    Other,
}

fn digest_set(
    value: &StrictValue,
    at: &Pointer,
    ctx: &mut Context,
    classify: impl Fn(&str) -> Key,
) -> Result<DigestSet, ManifestError> {
    let StrictValue::Object(members) = value else {
        return Err(invalid(at, Problem::WrongType("an object")));
    };
    let accepted_names: Vec<&'static str> = DigestAlgorithm::ALL
        .iter()
        .flat_map(|a| [a.name(), a.tree_name()])
        .filter(|name| matches!(classify(name), Key::Accepted(_)))
        .collect();
    let mut digests = Vec::new();
    for (key, value) in members {
        let key_at = at.key(key);
        let text = string(value, &key_at)?;
        let kind = match classify(key) {
            Key::Accepted(algorithm) => {
                digests.push(
                    Digest::from_hex(algorithm, text)
                        .map_err(|e| invalid(&key_at, Problem::Digest(e)))?,
                );
                continue;
            }
            Key::Insecure => WarningKind::InsecureAlgorithm,
            Key::Other => WarningKind::UnknownAlgorithm,
        };
        // A case variant of an accepted name could be read as that algorithm
        // by another tool.
        if let Some(name) = accepted_names
            .iter()
            .copied()
            .find(|name| folds_to(key, name))
        {
            return Err(invalid(&key_at, Problem::CaseVariant(name)));
        }
        ctx.warn(key_at, kind);
    }
    if members.is_empty() {
        return Err(invalid(
            at,
            Problem::Rule("must contain at least one digest"),
        ));
    }
    DigestSet::new(digests).map_err(|e| match e {
        // The algorithms may be valid ones this version does not know.
        DigestError::EmptyDigestSet => ManifestError::Unsupported {
            pointer: at.clone(),
            what: Unsupported::NoAcceptedAlgorithm,
        },
        other => invalid(at, Problem::Digest(other)),
    })
}

fn artifact(
    value: &StrictValue,
    at: &Pointer,
    ctx: &mut Context,
) -> Result<ArtifactClaim, ManifestError> {
    let fields = Fields::new(
        value,
        at,
        &["kind", "size", "tree", "treeDigest"],
        Unknown::Warn,
        ctx,
    )?;
    let (kind, kind_at) = fields.required("kind")?;
    let size = match fields.optional("size") {
        Some((value, at)) => Some(integer(value, &at)?),
        None => None,
    };
    match string(kind, &kind_at)? {
        "file" => {
            for key in ["tree", "treeDigest"] {
                if fields.has(key) {
                    return Err(invalid(
                        &at.key(key),
                        Problem::Rule("is only allowed for directory artifacts"),
                    ));
                }
            }
            Ok(ArtifactClaim::File { size })
        }
        "directory" => {
            let (tree, tree_at) = fields.required("tree")?;
            let tree = tree_entries(tree, &tree_at, ctx)?;
            let (digest, digest_at) = fields.required("treeDigest")?;
            let tree_digest = tree_digests(digest, &digest_at, ctx)?;
            if let Some(size) = size {
                let total = tree.iter().try_fold(0u64, |sum, entry| match entry.kind {
                    EntryClaimKind::File { size, .. } => sum.checked_add(size),
                    _ => Some(sum),
                });
                if total != Some(size) {
                    return Err(invalid(
                        &at.key("size"),
                        Problem::Rule("does not equal the total size of the tree's regular files"),
                    ));
                }
            }
            Ok(ArtifactClaim::Directory {
                size,
                tree,
                tree_digest,
            })
        }
        _ => Err(invalid(
            &kind_at,
            Problem::Rule("must be \"file\" or \"directory\""),
        )),
    }
}

fn tree_entries(
    value: &StrictValue,
    at: &Pointer,
    ctx: &mut Context,
) -> Result<Vec<TreeEntryClaim>, ManifestError> {
    let items = array(value, at)?;
    let mut entries: Vec<TreeEntryClaim> = Vec::with_capacity(items.len());
    let mut directories = HashSet::new();
    for (i, item) in items.iter().enumerate() {
        let at = at.index(i);
        let fields = Fields::new(
            item,
            &at,
            &["path", "type", "executable", "size", "digest", "target"],
            Unknown::Warn,
            ctx,
        )?;
        let (path, path_at) = fields.required("path")?;
        let path = rel_path(path, &path_at)?;
        if let Some(previous) = entries.last()
            && previous.path.tree_cmp(&path) != Ordering::Less
        {
            return Err(invalid(
                &path_at,
                Problem::Rule(
                    "entries must be unique and in tree order: depth-first, siblings in ascending byte order",
                ),
            ));
        }
        if let Some((parent, _)) = path.as_str().rsplit_once('/')
            && !directories.contains(parent)
        {
            return Err(invalid(
                &path_at,
                Problem::Rule("its parent directory is not listed before it"),
            ));
        }
        let (kind, kind_at) = fields.required("type")?;
        let kind = string(kind, &kind_at)?;
        let allowed: &[&str] = match kind {
            "file" => &["executable", "size", "digest"],
            "symlink" => &["target"],
            "directory" => &[],
            _ => {
                return Err(invalid(
                    &kind_at,
                    Problem::Rule("must be \"file\", \"directory\" or \"symlink\""),
                ));
            }
        };
        for key in ["executable", "size", "digest", "target"] {
            if fields.has(key) && !allowed.contains(&key) {
                return Err(invalid(
                    &at.key(key),
                    Problem::Rule("is not allowed for this entry type"),
                ));
            }
        }
        let kind = match kind {
            "file" => {
                let (executable, executable_at) = fields.required("executable")?;
                let (size, size_at) = fields.required("size")?;
                let (digest, digest_at) = fields.required("digest")?;
                EntryClaimKind::File {
                    executable: boolean(executable, &executable_at)?,
                    size: integer(size, &size_at)?,
                    digest: content_digests(digest, &digest_at, ctx)?,
                }
            }
            "symlink" => {
                let (target, target_at) = fields.required("target")?;
                let target = string(target, &target_at)?;
                validate_symlink_target(target.as_bytes())
                    .map_err(|e| invalid(&target_at, Problem::Name(e)))?;
                EntryClaimKind::Symlink {
                    target: target.to_owned(),
                }
            }
            _ => {
                directories.insert(path.as_str().to_owned());
                EntryClaimKind::Directory
            }
        };
        entries.push(TreeEntryClaim { path, kind });
    }
    Ok(entries)
}

/// A file artifact has exactly one subject. A directory artifact's subjects
/// are exactly its regular files, in tree order, with the same digests.
fn check_subjects_match_artifact(
    subjects: &[Subject],
    subjects_at: &Pointer,
    artifact: &ArtifactClaim,
    artifact_at: &Pointer,
) -> Result<(), ManifestError> {
    match artifact {
        ArtifactClaim::File { .. } => {
            if subjects.len() != 1 {
                return Err(invalid(
                    subjects_at,
                    Problem::Rule("a file artifact has exactly one subject"),
                ));
            }
        }
        ArtifactClaim::Directory { tree, .. } => {
            let files = tree.iter().filter_map(|entry| match &entry.kind {
                EntryClaimKind::File { digest, .. } => Some((&entry.path, digest)),
                _ => None,
            });
            let mut subjects_iter = subjects.iter().enumerate();
            for (path, digest) in files {
                match subjects_iter.next() {
                    Some((_, subject)) if subject.name == *path && subject.digest == *digest => {}
                    Some((i, _)) => {
                        return Err(invalid(
                            &subjects_at.index(i),
                            Problem::Rule(
                                "subjects must be the tree's regular files, in tree order, with the same digests",
                            ),
                        ));
                    }
                    None => {
                        return Err(invalid(
                            &artifact_at.key("tree"),
                            Problem::Rule("lists a regular file that is not a subject"),
                        ));
                    }
                }
            }
            if let Some((i, _)) = subjects_iter.next() {
                return Err(invalid(
                    &subjects_at.index(i),
                    Problem::Rule("is not a regular file of the tree"),
                ));
            }
        }
    }
    Ok(())
}

/// Reads a `buildDefinition` object.
pub(super) fn build_definition(
    value: &StrictValue,
    at: &Pointer,
    ctx: &mut Context,
) -> Result<BuildDefinition, ManifestError> {
    let fields = Fields::new(
        value,
        at,
        &[
            "buildType",
            "externalParameters",
            "internalParameters",
            "resolvedDependencies",
        ],
        Unknown::Warn,
        ctx,
    )?;
    let (build_type, build_type_at) = fields.required("buildType")?;
    let build_type = string(build_type, &build_type_at)?;
    if build_type != CARGO_BUILD_TYPE_V0 {
        ctx.warn(build_type_at, WarningKind::UnsupportedBuildType);
        return Ok(BuildDefinition::Unsupported {
            build_type: build_type.to_owned(),
            raw: value.clone(),
        });
    }
    Ok(BuildDefinition::Cargo(Box::new(cargo::read(&fields, ctx)?)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_folding_catches_unicode_lookalikes() {
        assert!(folds_to("Subject", "subject"));
        assert!(folds_to("SUBJECT", "subject"));
        assert!(folds_to("\u{17f}ubject", "subject"), "long s folds to s");
        assert!(folds_to("\u{212a}ind", "kind"), "Kelvin sign folds to k");
        assert!(!folds_to("subjects", "subject"));
        assert!(!folds_to("subjeçt", "subject"));
    }
}
