//! TrustForge manifests: in-toto Statements that claim an artifact's digests
//! and, optionally, the recipe that builds it (`docs/manifest-spec.md`).
//!
//! A manifest is a **claim document**, not evidence. Parsing one checks that
//! it is well-formed and follows every rule of the specification; it says
//! nothing about whether the claims are true or who made them. An unsigned
//! manifest is an unauthenticated claim.
//!
//! - [`parse_manifest`] reads a document strictly ([`crate::json`]), then
//!   converts and validates it field by field. Unknown fields are ignored
//!   with a [warning](ManifestWarning) where the in-toto rules require it,
//!   and rejected where they could change a build. A manifest is identified
//!   by the SHA-256 of its exact bytes ([`ParsedManifest::file_digest`]).
//! - [`Manifest::from_inspection`] creates a manifest from an
//!   [`Inspection`].
//! - [`Manifest::to_canonical_json`] and [`Manifest::to_pretty_json`] write
//!   it deterministically ([`crate::json::to_canonical`]).

mod cargo;
mod read;

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use crate::digest::{Digest, DigestAlgorithm, DigestError, DigestSet};
use crate::inspect::{ArtifactDigests, ArtifactKind, EntryKind, Inspection};
use crate::json::{self, JsonError, JsonLimits, Pointer, StrictValue};
use crate::name::{NameError, Quoted, RelPath};

pub use cargo::{CargoRecipe, ResolvedDependency};

/// The in-toto Statement type every manifest uses.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// The namespace of TrustForge's type URIs.
pub const NAMESPACE: &str = "https://feurstern.github.io/trust-forge";

/// The predicate type of a version 0 manifest.
pub const PREDICATE_TYPE_V0: &str = "https://feurstern.github.io/trust-forge/manifest/v0";

/// The build type of a version 0 Rust/Cargo recipe.
pub const CARGO_BUILD_TYPE_V0: &str = "https://feurstern.github.io/trust-forge/build/cargo/v0";

/// A validated manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    subjects: Vec<Subject>,
    artifact: ArtifactClaim,
    build_definition: Option<BuildDefinition>,
}

/// One subject of the Statement: a name and the digests claimed for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subject {
    name: RelPath,
    digest: DigestSet,
}

impl Subject {
    /// The subject's name: the file name of a file artifact, or a regular
    /// file's path inside a directory artifact.
    pub fn name(&self) -> &RelPath {
        &self.name
    }

    /// The digests claimed for it.
    pub fn digest(&self) -> &DigestSet {
        &self.digest
    }
}

/// What the manifest claims about the artifact as a whole.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArtifactClaim {
    /// A single file, described by the manifest's one subject.
    File {
        /// The claimed size in bytes, if given.
        size: Option<u64>,
    },
    /// A directory tree.
    Directory {
        /// The claimed total size of its regular files, if given.
        size: Option<u64>,
        /// Every entry, in tree order.
        tree: Vec<TreeEntryClaim>,
        /// Digests of the tree's NAR serialization.
        tree_digest: DigestSet,
    },
}

/// One entry of a claimed directory tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeEntryClaim {
    path: RelPath,
    kind: EntryClaimKind,
}

impl TreeEntryClaim {
    /// The entry's path relative to the tree's root.
    pub fn path(&self) -> &RelPath {
        &self.path
    }

    /// What the entry is.
    pub fn kind(&self) -> &EntryClaimKind {
        &self.kind
    }
}

/// What a claimed tree entry is.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryClaimKind {
    /// A regular file.
    File {
        /// Whether its owner-execute bit is set.
        executable: bool,
        /// Its size in bytes.
        size: u64,
        /// Digests of its contents.
        digest: DigestSet,
    },
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink {
        /// The target text.
        target: String,
    },
}

/// The claimed recipe.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildDefinition {
    /// A Rust/Cargo recipe ([`CARGO_BUILD_TYPE_V0`]).
    Cargo(Box<CargoRecipe>),
    /// A build type this version cannot interpret. The manifest can still
    /// be used for integrity; the recipe is kept as written and not
    /// interpreted.
    Unsupported {
        /// The build type.
        build_type: String,
        /// The `buildDefinition` object as written.
        raw: StrictValue,
    },
}

/// A note about a manifest that was accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestWarning {
    /// Where.
    pub pointer: Pointer,
    /// What.
    pub kind: WarningKind,
}

impl fmt::Display for ManifestWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.pointer, self.kind)
    }
}

/// The kinds of [`ManifestWarning`].
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WarningKind {
    /// A field this version does not define, ignored as the in-toto rules
    /// require.
    #[error("unknown field, ignored")]
    UnknownField,
    /// A digest algorithm TrustForge does not know, ignored.
    #[error("unknown digest algorithm, ignored")]
    UnknownAlgorithm,
    /// `md5` or `sha1`, which are never accepted.
    #[error("insecure digest algorithm, ignored")]
    InsecureAlgorithm,
    /// A subject without a `sha256` digest, which other in-toto tools expect.
    #[error("no sha256 digest; other in-toto tools may not recognize this subject")]
    MissingSha256,
    /// A build type this version cannot interpret.
    #[error(
        "build type is not supported by this version, so the artifact cannot be rebuilt from it"
    )]
    UnsupportedBuildType,
}

impl WarningKind {
    /// The kind's name in reports: `unknown-field`, `unknown-algorithm`,
    /// `insecure-algorithm`, `missing-sha256` or `unsupported-build-type`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownField => "unknown-field",
            Self::UnknownAlgorithm => "unknown-algorithm",
            Self::InsecureAlgorithm => "insecure-algorithm",
            Self::MissingSha256 => "missing-sha256",
            Self::UnsupportedBuildType => "unsupported-build-type",
        }
    }

    /// The kind whose [code](Self::code) is `code`.
    pub fn from_code(code: &str) -> Option<Self> {
        [
            Self::UnknownField,
            Self::UnknownAlgorithm,
            Self::InsecureAlgorithm,
            Self::MissingSha256,
            Self::UnsupportedBuildType,
        ]
        .into_iter()
        .find(|kind| kind.code() == code)
    }
}

/// Why a manifest field is invalid.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Problem {
    /// A required field is absent.
    #[error("required field is missing")]
    Missing,
    /// A field has the wrong JSON type.
    #[error("must be {0}")]
    WrongType(&'static str),
    /// A key that differs from a defined field only in letter case.
    #[error("differs from the field \"{0}\" only in letter case")]
    CaseVariant(&'static str),
    /// A field that is not allowed where unknown fields are rejected.
    #[error("unknown field; it could change what gets built, so it is rejected")]
    UnknownField,
    /// A rule of the specification.
    #[error("{0}")]
    Rule(&'static str),
    /// An invalid name or path.
    #[error("invalid name: {0}")]
    Name(NameError),
    /// An invalid digest.
    #[error("{0}")]
    Digest(DigestError),
    /// A warning, which strict mode turns into an error.
    #[error("rejected in strict mode: {0}")]
    Strict(WarningKind),
}

/// Why a manifest was rejected.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    /// The document is not strict JSON, or is too large.
    #[error("{0}")]
    Json(#[from] JsonError),
    /// The document is well-formed but breaks a rule of the specification.
    #[error("{pointer}: {problem}")]
    Invalid {
        /// Where.
        pointer: Pointer,
        /// What is wrong.
        problem: Problem,
    },
    /// The document uses a type or version this version of TrustForge
    /// cannot interpret. It is never interpreted on a best-effort basis.
    #[error("{pointer}: {what} is not supported by this version of TrustForge")]
    Unsupported {
        /// Where.
        pointer: Pointer,
        /// What.
        what: Unsupported,
    },
}

/// What a manifest uses that this version cannot interpret.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Unsupported {
    /// A statement type other than in-toto Statement v1. The value is cut to
    /// 256 characters.
    #[error("statement type {}", Quoted(.0))]
    StatementType(String),
    /// A predicate type other than TrustForge manifest v0. The value is cut
    /// to 256 characters.
    #[error("predicate type {}", Quoted(.0))]
    PredicateType(String),
    /// A digest set without any algorithm this version accepts.
    #[error("a digest set without any algorithm this version accepts")]
    NoAcceptedAlgorithm,
}

/// Options for parsing.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParseOptions {
    /// Size and nesting limits.
    pub limits: JsonLimits,
    /// Turn every warning into an error.
    pub strict: bool,
}

/// A manifest as read from a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedManifest {
    /// The manifest.
    pub manifest: Manifest,
    /// SHA-256 of the exact bytes read: the manifest's identity.
    pub file_digest: Digest,
    /// Notes about accepted content, in document order.
    pub warnings: Vec<ManifestWarning>,
}

/// Parses and validates a manifest.
pub fn parse_manifest(bytes: &[u8], opts: &ParseOptions) -> Result<ParsedManifest, ManifestError> {
    let value = json::parse(bytes, &opts.limits)?;
    let (manifest, warnings) = read_value(&value, opts.strict)?;
    Ok(ParsedManifest {
        manifest,
        file_digest: Digest::of(DigestAlgorithm::Sha256, bytes),
        warnings,
    })
}

/// Validates a manifest that has already passed strict JSON parsing.
pub(crate) fn read_value(
    value: &StrictValue,
    strict: bool,
) -> Result<(Manifest, Vec<ManifestWarning>), ManifestError> {
    let mut ctx = read::Context::default();
    let manifest = read::statement(value, &mut ctx)?;
    Ok((manifest, ctx.finish(strict)?))
}

/// How many levels deeper a `buildDefinition` is once embedded in a
/// manifest (`predicate`, then `buildDefinition`).
const EMBEDDED_DEPTH: usize = 2;

/// Parses and validates a standalone `buildDefinition` object, such as a
/// recipe file to embed in a new manifest. Its nesting is limited as it will
/// be once embedded, so that every recipe accepted here can be embedded.
pub fn parse_build_definition(
    bytes: &[u8],
    opts: &ParseOptions,
) -> Result<(BuildDefinition, Vec<ManifestWarning>), ManifestError> {
    let mut limits = opts.limits.clone();
    limits.max_depth = limits.max_depth.saturating_sub(EMBEDDED_DEPTH);
    let value = json::parse(bytes, &limits)?;
    let mut ctx = read::Context::default();
    let definition = read::build_definition(&value, &Pointer::root(), &mut ctx)?;
    Ok((definition, ctx.finish(opts.strict)?))
}

impl Manifest {
    /// Creates a manifest from an inspection. A file or stream becomes one
    /// subject named `name`, or by default the inspected file's name; a
    /// directory becomes one subject per regular file plus the full tree.
    pub fn from_inspection(
        inspection: &Inspection,
        name: Option<&str>,
    ) -> Result<Self, ManifestError> {
        let subject_pointer = Pointer::root().key("subject");
        match inspection.digests() {
            ArtifactDigests::Content(digest) => {
                let name = match name {
                    Some(name) => name,
                    None if inspection.kind() == ArtifactKind::File => Path::new(inspection.name())
                        .file_name()
                        .and_then(|n| n.to_str())
                        .ok_or_else(|| {
                            invalid(
                                &subject_pointer,
                                Problem::Rule(
                                    "the artifact's file name cannot be used as its subject name",
                                ),
                            )
                        })?,
                    None => {
                        return Err(invalid(
                            &subject_pointer,
                            Problem::Rule("a stream needs a subject name"),
                        ));
                    }
                };
                let name = RelPath::parse(name).map_err(|e| {
                    invalid(&subject_pointer.index(0).key("name"), Problem::Name(e))
                })?;
                Ok(Self {
                    subjects: vec![Subject {
                        name,
                        digest: digest.clone(),
                    }],
                    artifact: ArtifactClaim::File {
                        size: Some(inspection.size()),
                    },
                    build_definition: None,
                })
            }
            ArtifactDigests::Tree(tree_digest) => {
                let entries = inspection.entries().unwrap_or_default();
                let mut subjects = Vec::new();
                let mut tree = Vec::with_capacity(entries.len());
                for entry in entries {
                    let kind = match entry.kind() {
                        EntryKind::File {
                            executable,
                            size,
                            digest,
                        } => {
                            subjects.push(Subject {
                                name: entry.path().clone(),
                                digest: digest.clone(),
                            });
                            EntryClaimKind::File {
                                executable: *executable,
                                size: *size,
                                digest: digest.clone(),
                            }
                        }
                        EntryKind::Directory => EntryClaimKind::Directory,
                        EntryKind::Symlink { target, .. } => EntryClaimKind::Symlink {
                            target: target.clone(),
                        },
                    };
                    tree.push(TreeEntryClaim {
                        path: entry.path().clone(),
                        kind,
                    });
                }
                if subjects.is_empty() {
                    return Err(invalid(
                        &subject_pointer,
                        Problem::Rule(
                            "a directory without regular files cannot be described: in-toto requires at least one subject",
                        ),
                    ));
                }
                Ok(Self {
                    subjects,
                    artifact: ArtifactClaim::Directory {
                        size: Some(inspection.size()),
                        tree,
                        tree_digest: tree_digest.clone(),
                    },
                    build_definition: None,
                })
            }
        }
    }

    /// This manifest with `definition` as its claimed recipe.
    pub fn with_build_definition(mut self, definition: BuildDefinition) -> Self {
        self.build_definition = Some(definition);
        self
    }

    /// The subjects, in document order.
    pub fn subjects(&self) -> &[Subject] {
        &self.subjects
    }

    /// The claims about the artifact as a whole.
    pub fn artifact(&self) -> &ArtifactClaim {
        &self.artifact
    }

    /// The claimed recipe, if any.
    pub fn build_definition(&self) -> Option<&BuildDefinition> {
        self.build_definition.as_ref()
    }

    /// The manifest as a JSON value: every field this version defines, as
    /// present. Fields that were ignored when parsing are not included.
    pub fn to_value(&self) -> StrictValue {
        let mut predicate = BTreeMap::new();
        predicate.insert("artifact".to_owned(), self.artifact_value());
        if let Some(definition) = &self.build_definition {
            let value = match definition {
                BuildDefinition::Cargo(recipe) => recipe.to_value(),
                BuildDefinition::Unsupported { raw, .. } => raw.clone(),
            };
            predicate.insert("buildDefinition".to_owned(), value);
        }
        let subjects = self
            .subjects
            .iter()
            .map(|s| {
                object([
                    ("digest", digest_value(&s.digest, DigestAlgorithm::name)),
                    ("name", string(s.name.as_str())),
                ])
            })
            .collect();
        object([
            ("_type", string(STATEMENT_TYPE)),
            ("predicate", StrictValue::Object(predicate)),
            ("predicateType", string(PREDICATE_TYPE_V0)),
            ("subject", StrictValue::Array(subjects)),
        ])
    }

    fn artifact_value(&self) -> StrictValue {
        let mut artifact = BTreeMap::new();
        let (kind, size) = match &self.artifact {
            ArtifactClaim::File { size } => ("file", size),
            ArtifactClaim::Directory {
                size,
                tree,
                tree_digest,
            } => {
                artifact.insert(
                    "tree".to_owned(),
                    StrictValue::Array(tree.iter().map(tree_entry_value).collect()),
                );
                artifact.insert(
                    "treeDigest".to_owned(),
                    digest_value(tree_digest, DigestAlgorithm::tree_name),
                );
                ("directory", size)
            }
        };
        artifact.insert("kind".to_owned(), string(kind));
        if let Some(size) = size {
            artifact.insert("size".to_owned(), StrictValue::Integer(*size));
        }
        StrictValue::Object(artifact)
    }

    /// The RFC 8785 (JCS) canonical form.
    pub fn to_canonical_json(&self) -> Vec<u8> {
        json::to_canonical(&self.to_value())
    }

    /// The deterministic human-readable form TrustForge writes by default.
    pub fn to_pretty_json(&self) -> Vec<u8> {
        json::to_pretty(&self.to_value())
    }
}

fn tree_entry_value(entry: &TreeEntryClaim) -> StrictValue {
    let mut fields = vec![("path", string(entry.path.as_str()))];
    match &entry.kind {
        EntryClaimKind::File {
            executable,
            size,
            digest,
        } => {
            fields.push(("type", string("file")));
            fields.push(("executable", StrictValue::Bool(*executable)));
            fields.push(("size", StrictValue::Integer(*size)));
            fields.push(("digest", digest_value(digest, DigestAlgorithm::name)));
        }
        EntryClaimKind::Directory => fields.push(("type", string("directory"))),
        EntryClaimKind::Symlink { target } => {
            fields.push(("type", string("symlink")));
            fields.push(("target", string(target)));
        }
    }
    object(fields)
}

fn digest_value(set: &DigestSet, key: fn(DigestAlgorithm) -> &'static str) -> StrictValue {
    StrictValue::Object(
        set.iter()
            .map(|d| (key(d.algorithm()).to_owned(), string(&d.to_hex())))
            .collect(),
    )
}

pub(crate) fn string(s: &str) -> StrictValue {
    StrictValue::String(s.to_owned())
}

pub(crate) fn object<'k>(fields: impl IntoIterator<Item = (&'k str, StrictValue)>) -> StrictValue {
    StrictValue::Object(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

pub(crate) fn invalid(pointer: &Pointer, problem: Problem) -> ManifestError {
    ManifestError::Invalid {
        pointer: pointer.clone(),
        problem,
    }
}
