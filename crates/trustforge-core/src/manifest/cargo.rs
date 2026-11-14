//! The Rust/Cargo build type ([`CARGO_BUILD_TYPE_V0`]): a claimed recipe that
//! builds one binary target of a Cargo project for one target triple.
//!
//! Every value is attacker-controlled. A later milestone passes these values
//! to `cargo` inside a container, as separate `--flag=value` arguments, so
//! they are held to strict character rules here:
//! - Cargo names and target triples use Cargo's characters, and **nothing
//!   may begin with `-`**, which would turn a value into an option;
//! - paths are relative (or, inside the container, absolute) without `.`,
//!   `..` or empty components;
//! - the source repository is an `https` URL without credentials;
//! - only allowlisted environment variables may be set;
//! - unknown parameters are rejected, because they could change what gets
//!   built.

use std::collections::BTreeMap;

use super::read::{Context, Fields, Unknown, array, boolean, folds_to, string};
use super::{CARGO_BUILD_TYPE_V0, ManifestError, Problem, WarningKind, invalid, object};
use crate::digest::{Digest, DigestAlgorithm};
use crate::json::{Pointer, StrictValue};
use crate::name::RelPath;

/// A claimed Rust/Cargo recipe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CargoRecipe {
    repository: String,
    git_ref: Option<String>,
    workspace_path: Option<RelPath>,
    package: Option<String>,
    bin: String,
    profile: Option<String>,
    target: String,
    features: Option<Vec<String>>,
    default_features: Option<bool>,
    output_path: RelPath,
    toolchain: String,
    workdir: Option<String>,
    cargo_home: Option<String>,
    env: Option<BTreeMap<String, String>>,
    dependencies: Vec<ResolvedDependency>,
    /// Index of the source repository entry in `dependencies`.
    source: usize,
    /// Index of the build image entry in `dependencies`.
    image: usize,
    source_commit: String,
    image_digest: Digest,
}

/// One entry of `resolvedDependencies` (an in-toto ResourceDescriptor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedDependency {
    uri: String,
    digest: BTreeMap<String, String>,
    name: Option<String>,
}

impl ResolvedDependency {
    /// The resource's URI.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Its digest set, as written, except for `md5` and `sha1` values (in
    /// any letter case), which are dropped with a warning.
    pub fn digest(&self) -> &BTreeMap<String, String> {
        &self.digest
    }

    /// Its name, if given.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

impl CargoRecipe {
    /// The source repository (`https` URL).
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// The full ref the commit must be reachable from, if given.
    pub fn git_ref(&self) -> Option<&str> {
        self.git_ref.as_deref()
    }

    /// The full commit ID of the source (`gitCommit`).
    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }

    /// The Cargo workspace root inside the repository; `None` means the
    /// repository root.
    pub fn workspace_path(&self) -> Option<&RelPath> {
        self.workspace_path.as_ref()
    }

    /// The Cargo package, if given.
    pub fn package(&self) -> Option<&str> {
        self.package.as_deref()
    }

    /// The binary target.
    pub fn bin(&self) -> &str {
        &self.bin
    }

    /// The Cargo profile (default `release`).
    pub fn profile(&self) -> &str {
        self.profile.as_deref().unwrap_or("release")
    }

    /// The target triple.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The enabled features, sorted.
    pub fn features(&self) -> &[String] {
        self.features.as_deref().unwrap_or_default()
    }

    /// Whether default features are enabled (default `true`).
    pub fn default_features(&self) -> bool {
        self.default_features.unwrap_or(true)
    }

    /// The produced artifact, relative to the workspace root.
    pub fn output_path(&self) -> &RelPath {
        &self.output_path
    }

    /// The exact rustup toolchain.
    pub fn toolchain(&self) -> &str {
        &self.toolchain
    }

    /// The source tree's path inside the build container (default
    /// `/build/src`).
    pub fn workdir(&self) -> &str {
        self.workdir.as_deref().unwrap_or("/build/src")
    }

    /// `CARGO_HOME` inside the build container (default
    /// `/build/cargo-home`).
    pub fn cargo_home(&self) -> &str {
        self.cargo_home.as_deref().unwrap_or("/build/cargo-home")
    }

    /// Extra environment variables, all on the allowlist.
    pub fn env(&self) -> impl Iterator<Item = (&str, &str)> {
        self.env
            .iter()
            .flatten()
            .map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// The build image's package URL.
    pub fn image(&self) -> &str {
        self.dependencies
            .get(self.image)
            .map_or("", |d| d.uri.as_str())
    }

    /// The build image's manifest digest.
    pub fn image_digest(&self) -> &Digest {
        &self.image_digest
    }

    /// Every resolved dependency, in document order, including the source
    /// and the build image.
    pub fn resolved_dependencies(&self) -> &[ResolvedDependency] {
        &self.dependencies
    }

    pub(super) fn to_value(&self) -> StrictValue {
        let string = |s: &str| StrictValue::String(s.to_owned());
        let mut source = vec![("repository", string(&self.repository))];
        if let Some(git_ref) = &self.git_ref {
            source.push(("ref", string(git_ref)));
        }
        let mut external = vec![
            ("source", object(source)),
            ("bin", string(&self.bin)),
            ("target", string(&self.target)),
            ("outputPath", string(self.output_path.as_str())),
        ];
        if let Some(path) = &self.workspace_path {
            external.push(("workspacePath", string(path.as_str())));
        }
        if let Some(package) = &self.package {
            external.push(("package", string(package)));
        }
        if let Some(profile) = &self.profile {
            external.push(("profile", string(profile)));
        }
        if let Some(features) = &self.features {
            external.push((
                "features",
                StrictValue::Array(features.iter().map(|f| string(f)).collect()),
            ));
        }
        if let Some(default_features) = self.default_features {
            external.push(("defaultFeatures", StrictValue::Bool(default_features)));
        }
        let mut internal = vec![("toolchain", string(&self.toolchain))];
        if let Some(workdir) = &self.workdir {
            internal.push(("workdir", string(workdir)));
        }
        if let Some(cargo_home) = &self.cargo_home {
            internal.push(("cargoHome", string(cargo_home)));
        }
        if let Some(env) = &self.env {
            internal.push((
                "env",
                object(env.iter().map(|(k, v)| (k.as_str(), string(v)))),
            ));
        }
        let dependencies = self
            .dependencies
            .iter()
            .map(|d| {
                let mut fields = vec![
                    ("uri", string(&d.uri)),
                    (
                        "digest",
                        object(d.digest.iter().map(|(k, v)| (k.as_str(), string(v)))),
                    ),
                ];
                if let Some(name) = &d.name {
                    fields.push(("name", string(name)));
                }
                object(fields)
            })
            .collect();
        object([
            ("buildType", string(CARGO_BUILD_TYPE_V0)),
            ("externalParameters", object(external)),
            ("internalParameters", object(internal)),
            ("resolvedDependencies", StrictValue::Array(dependencies)),
        ])
    }
}

/// Reads a Cargo recipe from a `buildDefinition` whose build type is
/// [`CARGO_BUILD_TYPE_V0`].
pub(super) fn read(fields: &Fields<'_>, ctx: &mut Context) -> Result<CargoRecipe, ManifestError> {
    let (external, at) = fields.required("externalParameters")?;
    let external = Fields::new(
        external,
        &at,
        &[
            "source",
            "workspacePath",
            "package",
            "bin",
            "profile",
            "target",
            "features",
            "defaultFeatures",
            "outputPath",
        ],
        Unknown::Reject,
        ctx,
    )?;
    let (source, source_at) = external.required("source")?;
    let source = Fields::new(
        source,
        &source_at,
        &["repository", "ref"],
        Unknown::Reject,
        ctx,
    )?;
    let repository = checked(
        source.required("repository")?,
        https_url,
        "must be an https URL without user name, password, query or fragment",
    )?;
    let git_ref = optional_checked(
        source.optional("ref"),
        full_ref,
        "must be a full ref name, such as refs/tags/v1.2.3",
    )?;
    let workspace_path = match external.optional("workspacePath") {
        Some(field) => Some(recipe_path(field)?),
        None => None,
    };
    let package = optional_checked(external.optional("package"), cargo_name, CARGO_NAME_RULE)?;
    let bin = checked(external.required("bin")?, cargo_name, CARGO_NAME_RULE)?;
    let profile = optional_checked(external.optional("profile"), cargo_name, CARGO_NAME_RULE)?;
    let target = checked(
        external.required("target")?,
        target_triple,
        "must be a target triple, such as x86_64-unknown-linux-gnu",
    )?;
    let features = match external.optional("features") {
        Some((value, at)) => Some(features(value, &at)?),
        None => None,
    };
    let default_features = match external.optional("defaultFeatures") {
        Some((value, at)) => Some(boolean(value, &at)?),
        None => None,
    };
    let output_path = recipe_path(external.required("outputPath")?)?;

    let (internal, at) = fields.required("internalParameters")?;
    let internal = Fields::new(
        internal,
        &at,
        &["toolchain", "workdir", "cargoHome", "env"],
        Unknown::Reject,
        ctx,
    )?;
    let toolchain = checked(
        internal.required("toolchain")?,
        exact_toolchain,
        "must be an exact toolchain: a version such as 1.99.1, or nightly-YYYY-MM-DD or beta-YYYY-MM-DD",
    )?;
    let workdir = optional_checked(
        internal.optional("workdir"),
        container_path,
        CONTAINER_PATH_RULE,
    )?;
    let cargo_home = optional_checked(
        internal.optional("cargoHome"),
        container_path,
        CONTAINER_PATH_RULE,
    )?;
    // A CARGO_HOME inside the source tree would make the repository's own
    // Cargo configuration apply to every Cargo command of the rebuild.
    let effective_workdir = workdir.as_deref().unwrap_or("/build/src");
    let effective_cargo_home = cargo_home.as_deref().unwrap_or("/build/cargo-home");
    if nested(effective_workdir, effective_cargo_home) {
        let key = if cargo_home.is_some() {
            "cargoHome"
        } else {
            "workdir"
        };
        return Err(invalid(
            &at.key(key),
            Problem::Rule(
                "workdir and cargoHome must not be the same directory or one inside the other",
            ),
        ));
    }
    let env = match internal.optional("env") {
        Some((value, at)) => Some(env(value, &at)?),
        None => None,
    };

    let (dependencies, dependencies_at) = fields.required("resolvedDependencies")?;
    let dependencies = resolved_dependencies(dependencies, &dependencies_at, ctx)?;
    let expected_source = match &git_ref {
        Some(git_ref) => format!("git+{repository}@{git_ref}"),
        None => format!("git+{repository}"),
    };
    let source = only_one(
        &dependencies,
        &dependencies_at,
        |d| has_prefix(&d.uri, "git+"),
        "must contain exactly one source entry (a git+ URI)",
    )?;
    let source_at = dependencies_at.index(source);
    let source_dependency = &dependencies[source];
    if source_dependency.uri != expected_source {
        return Err(invalid(
            &source_at.key("uri"),
            Problem::Rule("must be git+<repository>@<ref>, matching externalParameters.source"),
        ));
    }
    let source_commit = source_dependency
        .digest
        .get("gitCommit")
        .filter(|commit| is_commit(commit))
        .ok_or_else(|| {
            invalid(
                &source_at.key("digest").key("gitCommit"),
                Problem::Rule(
                    "must be the full commit ID: 40 or 64 lowercase hexadecimal characters",
                ),
            )
        })?
        .clone();
    let image = only_one(
        &dependencies,
        &dependencies_at,
        |d| has_prefix(&d.uri, "pkg:docker/"),
        "must contain exactly one build image entry (a pkg:docker/ URI)",
    )?;
    let image_at = dependencies_at.index(image);
    if !dependencies[image].uri.starts_with("pkg:docker/") {
        return Err(invalid(
            &image_at.key("uri"),
            Problem::Rule("must start with pkg:docker/ in lowercase"),
        ));
    }
    let image_digest = dependencies[image]
        .digest
        .get("sha256")
        .and_then(|hex| Digest::from_hex(DigestAlgorithm::Sha256, hex).ok())
        .ok_or_else(|| {
            invalid(
                &image_at.key("digest").key("sha256"),
                Problem::Rule("must be the image manifest's SHA-256 digest"),
            )
        })?;

    Ok(CargoRecipe {
        repository,
        git_ref,
        workspace_path,
        package,
        bin,
        profile,
        target,
        features,
        default_features,
        output_path,
        toolchain,
        workdir,
        cargo_home,
        env,
        dependencies,
        source,
        image,
        source_commit,
        image_digest,
    })
}

const CARGO_NAME_RULE: &str = "must be a Cargo name: ASCII letters, digits, '_' and '-', starting with a letter or '_', at most 64 characters";
const CONTAINER_PATH_RULE: &str = "must be a path under /build/ whose components start with an ASCII letter, digit or '_' and contain only ASCII letters, digits, '_', '-' and '.'";
const RECIPE_PATH_RULE: &str = "must be a relative path whose components start with an ASCII letter, digit or '_' and contain only ASCII letters, digits, '_', '-', '+' and '.'";

/// A string field that must satisfy `rule`.
fn checked(
    field: (&StrictValue, Pointer),
    rule: fn(&str) -> bool,
    text: &'static str,
) -> Result<String, ManifestError> {
    let (value, at) = field;
    let value = string(value, &at)?;
    if !rule(value) {
        return Err(invalid(&at, Problem::Rule(text)));
    }
    Ok(value.to_owned())
}

fn optional_checked(
    field: Option<(&StrictValue, Pointer)>,
    rule: fn(&str) -> bool,
    text: &'static str,
) -> Result<Option<String>, ManifestError> {
    field.map(|field| checked(field, rule, text)).transpose()
}

/// A path inside the repository, as passed to Cargo. Every component starts
/// with a letter, digit or `_`, so none can be read as an option.
fn recipe_path((value, at): (&StrictValue, Pointer)) -> Result<RelPath, ManifestError> {
    let text = string(value, &at)?;
    let path = RelPath::parse(text).map_err(|e| invalid(&at, Problem::Name(e)))?;
    if !text.split('/').all(|c| safe_component(c, true)) {
        return Err(invalid(&at, Problem::Rule(RECIPE_PATH_RULE)));
    }
    Ok(path)
}

/// A path component that cannot be read as an option and needs no quoting
/// in a command line or in `docker --mount` and `-v` values.
fn safe_component(component: &str, allow_plus: bool) -> bool {
    let mut chars = component.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        && chars.all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') || (allow_plus && c == '+')
        })
}

/// An absolute path inside the build container, under `/build/`, with
/// components that need no quoting anywhere (no `,`, `:` or `=`, which
/// `docker --mount` and `-v` treat as syntax).
fn container_path(s: &str) -> bool {
    s.strip_prefix("/build/")
        .is_some_and(|rest| !rest.is_empty() && rest.split('/').all(|c| safe_component(c, false)))
}

/// Whether two container paths are the same directory or one contains the
/// other.
fn nested(a: &str, b: &str) -> bool {
    a == b
        || a.strip_prefix(b).is_some_and(|rest| rest.starts_with('/'))
        || b.strip_prefix(a).is_some_and(|rest| rest.starts_with('/'))
}

/// Whether `uri` starts with `prefix`, ignoring ASCII letter case.
fn has_prefix(uri: &str, prefix: &str) -> bool {
    uri.get(..prefix.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
}

fn features(value: &StrictValue, at: &Pointer) -> Result<Vec<String>, ManifestError> {
    let mut features: Vec<String> = Vec::new();
    for (i, item) in array(value, at)?.iter().enumerate() {
        let item_at = at.index(i);
        let feature = string(item, &item_at)?;
        if !feature_name(feature) {
            return Err(invalid(
                &item_at,
                Problem::Rule(
                    "must be a feature name: ASCII letters, digits, '_', '-', '+' and '.', not starting with '-', '+' or '.'",
                ),
            ));
        }
        if features.last().is_some_and(|last| last.as_str() >= feature) {
            return Err(invalid(
                &item_at,
                Problem::Rule("features must be sorted and unique"),
            ));
        }
        features.push(feature.to_owned());
    }
    Ok(features)
}

fn env(value: &StrictValue, at: &Pointer) -> Result<BTreeMap<String, String>, ManifestError> {
    let StrictValue::Object(members) = value else {
        return Err(invalid(at, Problem::WrongType("an object")));
    };
    let mut env = BTreeMap::new();
    for (key, value) in members {
        let key_at = at.key(key);
        if !allowed_env(key) {
            return Err(invalid(
                &key_at,
                Problem::Rule(
                    "is not an allowed variable: only SOURCE_DATE_EPOCH, RUSTFLAGS and CARGO_PROFILE_* may be set",
                ),
            ));
        }
        let value = string(value, &key_at)?;
        let decimal = (1..=19).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_digit());
        if key == "SOURCE_DATE_EPOCH" && !decimal {
            return Err(invalid(&key_at, Problem::Rule("must be a decimal integer")));
        }
        env.insert(key.clone(), value.to_owned());
    }
    Ok(env)
}

fn resolved_dependencies(
    value: &StrictValue,
    at: &Pointer,
    ctx: &mut Context,
) -> Result<Vec<ResolvedDependency>, ManifestError> {
    let mut dependencies = Vec::new();
    for (i, item) in array(value, at)?.iter().enumerate() {
        let item_at = at.index(i);
        let fields = Fields::new(
            item,
            &item_at,
            &["uri", "digest", "name"],
            Unknown::Warn,
            ctx,
        )?;
        let (uri, uri_at) = fields.required("uri")?;
        let uri = string(uri, &uri_at)?;
        if uri.is_empty() {
            return Err(invalid(&uri_at, Problem::Rule("must not be empty")));
        }
        let (digest, digest_at) = fields.required("digest")?;
        let StrictValue::Object(members) = digest else {
            return Err(invalid(&digest_at, Problem::WrongType("an object")));
        };
        let mut digest = BTreeMap::new();
        for (key, value) in members {
            let key_at = digest_at.key(key);
            let hex = string(value, &key_at)?;
            // A case variant could be read as that digest by another tool.
            if !DEPENDENCY_DIGESTS.contains(&key.as_str())
                && let Some(name) = DEPENDENCY_DIGESTS
                    .iter()
                    .copied()
                    .find(|name| folds_to(key, name))
            {
                return Err(invalid(&key_at, Problem::CaseVariant(name)));
            }
            let valid = match key.as_str() {
                "gitCommit" => is_commit(hex),
                key => match key.parse::<DigestAlgorithm>() {
                    Ok(algorithm) => Digest::from_hex(algorithm, hex).is_ok(),
                    Err(_) => !hex.is_empty(),
                },
            };
            if !valid {
                return Err(invalid(
                    &key_at,
                    Problem::Rule("is not a valid digest for its algorithm"),
                ));
            }
            // In any letter case: `SHA1` is no more trustworthy than `sha1`.
            if ["md5", "sha1"].iter().any(|name| folds_to(key, name)) {
                ctx.warn(key_at, WarningKind::InsecureAlgorithm);
                continue;
            }
            digest.insert(key.clone(), hex.to_owned());
        }
        let name = match fields.optional("name") {
            Some((value, at)) => Some(string(value, &at)?.to_owned()),
            None => None,
        };
        dependencies.push(ResolvedDependency {
            uri: uri.to_owned(),
            digest,
            name,
        });
    }
    Ok(dependencies)
}

/// Digest keys with a defined format in resolved dependencies.
const DEPENDENCY_DIGESTS: [&str; 4] = ["blake3", "gitCommit", "sha256", "sha512"];

/// The index of the only dependency matching `pred`.
fn only_one(
    dependencies: &[ResolvedDependency],
    at: &Pointer,
    pred: impl Fn(&ResolvedDependency) -> bool,
    rule: &'static str,
) -> Result<usize, ManifestError> {
    let mut matching = dependencies
        .iter()
        .enumerate()
        .filter(|(_, d)| pred(d))
        .map(|(i, _)| i);
    match (matching.next(), matching.next()) {
        (Some(index), None) => Ok(index),
        _ => Err(invalid(at, Problem::Rule(rule))),
    }
}

/// A Cargo package, binary or profile name.
fn cargo_name(s: &str) -> bool {
    let mut chars = s.chars();
    s.len() <= 64
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn feature_name(s: &str) -> bool {
    let mut chars = s.chars();
    s.len() <= 64
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '.'))
}

/// A target triple name, never a path to a custom target specification.
fn target_triple(s: &str) -> bool {
    let mut parts = s.split('-');
    let arch_ok = parts.next().is_some_and(|arch| {
        !arch.is_empty()
            && arch
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    });
    let rest: Vec<&str> = parts.collect();
    s.len() <= 64
        && !s.ends_with(".json")
        && arch_ok
        && (1..=4).contains(&rest.len())
        && rest.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
        })
}

/// An exact toolchain: `X.Y.Z`, `nightly-YYYY-MM-DD` or `beta-YYYY-MM-DD`.
/// Channel names such as `stable` are not exact: they change over time.
fn exact_toolchain(s: &str) -> bool {
    let version = s.split('.').count() == 3
        && s.split('.')
            .all(|part| (1..=3).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit()));
    let dated = s
        .strip_prefix("nightly-")
        .or_else(|| s.strip_prefix("beta-"))
        .is_some_and(|date| {
            date.len() == 10
                && date.bytes().enumerate().all(|(i, b)| {
                    if i == 4 || i == 7 {
                        b == b'-'
                    } else {
                        b.is_ascii_digit()
                    }
                })
        });
    version || dated
}

/// An `https` URL with a host name, an optional port and an optional path,
/// and no user name, password, query, fragment, percent-encoding, or empty,
/// `.` or `..` path segment.
fn https_url(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("https://") else {
        return false;
    };
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, Some(path)),
        None => (rest, None),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    s.len() <= 2048
        && !host.is_empty()
        && !host.starts_with(['-', '.'])
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        && port.is_none_or(|p| (1..=5).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
        // Dot segments or percent-encoding would let git fetch another path
        // than the one shown; empty segments include a trailing slash.
        && path.is_none_or(|path| {
            path.split('/').all(|segment| {
                !matches!(segment, "" | "." | "..")
                    && segment.bytes().all(|b| {
                        b.is_ascii_graphic() && !matches!(b, b'?' | b'#' | b'\\' | b'@' | b'%')
                    })
            })
        })
}

/// A full git ref name (`refs/…`) under git's ref-name rules, without `@`.
fn full_ref(s: &str) -> bool {
    s.starts_with("refs/")
        && s.len() <= 255
        && !s.ends_with(['/', '.'])
        && !s.contains("..")
        // `@` is excluded entirely: the source URI is `git+<repository>@<ref>`.
        && s.bytes().all(|b| {
            b.is_ascii_graphic()
                && !matches!(b, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\' | b'@')
        })
        && s.split('/')
            .all(|part| !part.is_empty() && !part.starts_with('.') && !part.ends_with(".lock"))
}

/// A full commit ID: SHA-1 (40) or SHA-256 (64) lowercase hex.
fn is_commit(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64)
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn allowed_env(key: &str) -> bool {
    key == "SOURCE_DATE_EPOCH"
        || key == "RUSTFLAGS"
        || key.strip_prefix("CARGO_PROFILE_").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_names_never_start_with_a_dash() {
        for ok in ["app", "my-app", "my_app", "_private", "A1"] {
            assert!(cargo_name(ok), "{ok}");
        }
        for bad in [
            "",
            "-app",
            "--bin=x",
            "1app",
            "app name",
            "app/x",
            "ä",
            &"a".repeat(65),
        ] {
            assert!(!cargo_name(bad), "{bad}");
        }
        for ok in ["default", "serde", "tls-rustls", "v1.2", "c++", "1x"] {
            assert!(feature_name(ok), "{ok}");
        }
        for bad in ["", "-x", "+x", ".x", "a/b", "a b", "dep:x"] {
            assert!(!feature_name(bad), "{bad}");
        }
    }

    #[test]
    fn target_triples_are_names_not_paths() {
        for ok in [
            "x86_64-unknown-linux-gnu",
            "aarch64-apple-darwin",
            "wasm32-wasip1",
            "thumbv7em-none-eabihf",
            "x86_64-pc-windows-msvc",
        ] {
            assert!(target_triple(ok), "{ok}");
        }
        for bad in [
            "",
            "x86_64",
            "-x86_64-unknown-linux-gnu",
            "X86_64-unknown-linux-gnu",
            "my-target.json",
            "../t-u",
            "a-b c",
            "a-b-c-d-e-f",
        ] {
            assert!(!target_triple(bad), "{bad}");
        }
    }

    #[test]
    fn toolchains_must_be_exact() {
        for ok in ["1.99.1", "1.88.0", "nightly-2026-11-13", "beta-2026-01-02"] {
            assert!(exact_toolchain(ok), "{ok}");
        }
        for bad in [
            "stable",
            "nightly",
            "1.99",
            "1.99.1.0",
            "1.99.x",
            "nightly-2026-1-13",
            "/opt/toolchain",
            "-1.99.1",
            "1.99.1-x86_64-unknown-linux-gnu",
        ] {
            assert!(!exact_toolchain(bad), "{bad}");
        }
    }

    #[test]
    fn repositories_are_https_without_credentials() {
        for ok in [
            "https://github.com/example/project.git",
            "https://git.example.org:8443/a/b",
            "https://example.com",
        ] {
            assert!(https_url(ok), "{ok}");
        }
        for bad in [
            "http://github.com/x",
            "ssh://git@github.com/x",
            "git@github.com:x/y.git",
            "file:///tmp/repo",
            "ext::sh -c touch",
            "https://user:pass@github.com/x",
            "https://user@github.com/x",
            "https://github.com/x?y=1",
            "https://github.com/x#frag",
            "https://-github.com/x",
            "https://github.com:/x",
            "https://github.com/x y",
            "https:///x",
            "https://github.com/a/../b",
            "https://github.com/a/./b",
            "https://github.com/..",
            "https://github.com/a//b",
            "https://github.com/a/",
            "https://github.com/",
            "https://github.com/%2e%2e/x",
            "https://github.com/a%2Fb",
        ] {
            assert!(!https_url(bad), "{bad}");
        }
    }

    #[test]
    fn refs_follow_git_rules() {
        for ok in [
            "refs/tags/v1.2.3",
            "refs/heads/main",
            "refs/heads/feature/x-1",
            "refs/heads/locker",
            "refs/heads/x.locked",
        ] {
            assert!(full_ref(ok), "{ok}");
        }
        for bad in [
            "v1.2.3",
            "refs/",
            "refs/heads/../x",
            "refs/heads/x.lock",
            "refs/heads/x~1",
            "refs/heads/@{-1}",
            "refs/heads/.hidden",
            "refs//x",
            "refs/heads/x y",
            "refs/heads/x:y",
            "refs/heads/x.lock/y",
            "refs/heads/a@b",
            "refs/heads/@",
            "refs/tags/v1@refs/heads/x",
        ] {
            assert!(!full_ref(bad), "{bad}");
        }
    }

    #[test]
    fn only_allowlisted_environment_variables() {
        for ok in [
            "SOURCE_DATE_EPOCH",
            "RUSTFLAGS",
            "CARGO_PROFILE_RELEASE_LTO",
        ] {
            assert!(allowed_env(ok), "{ok}");
        }
        for bad in [
            "LD_PRELOAD",
            "RUSTC_WRAPPER",
            "CARGO_HOME",
            "PATH",
            "CARGO_PROFILE_",
            "cargo_profile_release_lto",
            "RUSTFLAGS2",
        ] {
            assert!(!allowed_env(bad), "{bad}");
        }
    }

    #[test]
    fn path_components_cannot_be_options_or_syntax() {
        for ok in ["src", "target_dir", "x86_64-linux", "v1.2", "_a", "9lives"] {
            assert!(safe_component(ok, false), "{ok}");
        }
        assert!(safe_component("c++", true));
        assert!(!safe_component("c++", false));
        for bad in [
            "", "-o", "--x", ".", "..", ".hidden", "+x", "a b", "a,b", "a:b", "a=b", "a\\b", "ä",
        ] {
            assert!(!safe_component(bad, true), "{bad}");
        }
    }

    #[test]
    fn container_paths_stay_under_build() {
        for ok in ["/build/src", "/build/cargo-home", "/build/a/b_c.d"] {
            assert!(container_path(ok), "{ok}");
        }
        for bad in [
            "build/src",
            "/",
            "/build",
            "/build/",
            "/build/src/",
            "/build/../etc",
            "/build//src",
            "/build/./src",
            "/etc",
            "/buildx/src",
            "/build/-v",
            "/build/a,b",
            "/build/a:b",
            "/build/a=b",
            "/build/c++",
        ] {
            assert!(!container_path(bad), "{bad}");
        }
        for (a, b) in [
            ("/build/src", "/build/src"),
            ("/build/src", "/build/src/.cargo"),
            ("/build/src/.cargo", "/build/src"),
        ] {
            assert!(nested(a, b), "{a} {b}");
        }
        for (a, b) in [
            ("/build/src", "/build/srcx"),
            ("/build/src", "/build/cargo-home"),
            ("/build/srcx", "/build/src"),
        ] {
            assert!(!nested(a, b), "{a} {b}");
        }
    }

    #[test]
    fn prefixes_are_matched_without_case() {
        assert!(has_prefix("git+https://x", "git+"));
        assert!(has_prefix("GIT+https://x", "git+"));
        assert!(has_prefix("pkg:DOCKER/x", "pkg:docker/"));
        assert!(!has_prefix("git", "git+"));
        assert!(!has_prefix("gît+x", "git+"));
        // A prefix that would end inside a multi-byte character.
        assert!(!has_prefix("gi\u{e9}+", "git+"));
    }

    #[test]
    fn commits() {
        assert!(is_commit(&"a".repeat(40)));
        assert!(is_commit(&"0".repeat(64)));
        for bad in ["abc", &"A".repeat(40), &"a".repeat(41), &"g".repeat(40)] {
            assert!(!is_commit(bad), "{bad}");
        }
    }
}
