//! `trustforge manifest`: create and validate manifests.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Subcommand};
use serde_json::json;
use trustforge_core::digest::{Digest, DigestAlgorithm};
use trustforge_core::json::{JsonError, JsonLimits};
use trustforge_core::manifest::{
    ArtifactClaim, BuildDefinition, CARGO_BUILD_TYPE_V0, Manifest, ManifestError, ParseOptions,
    ParsedManifest, Problem, parse_build_definition, parse_manifest,
};

use crate::artifact::ArtifactArgs;
use crate::output::{self, Format, diagnostic};
use crate::render::escape_for_terminal;
use crate::sanitize::sanitize;
use crate::{EXIT_FAILED, EXIT_USAGE};

#[derive(Debug, Subcommand)]
pub enum ManifestCommand {
    Create(CreateArgs),
    Validate(ValidateArgs),
}

/// Create a manifest describing an artifact.
///
/// The manifest is an in-toto Statement that claims the artifact's digests
/// (for a directory, also its full tree) and, optionally, the recipe that
/// builds it. Creating it verifies nothing, and an unsigned manifest does not
/// show who wrote it.
#[derive(Debug, Args)]
pub struct CreateArgs {
    #[command(flatten)]
    artifact: ArtifactArgs,

    /// Subject name for a file or standard input [default: the file's name].
    #[arg(long, value_name = "NAME")]
    name: Option<String>,

    /// Embed the claimed recipe read from FILE: a JSON `buildDefinition`
    /// object (see docs/manifest-spec.md).
    #[arg(long, value_name = "FILE")]
    build_definition: Option<PathBuf>,

    /// Write the RFC 8785 canonical form instead of the indented form.
    #[arg(long)]
    canonical: bool,

    /// Write to FILE instead of standard output. An existing regular file is
    /// replaced atomically; anything else at FILE is refused.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Largest manifest to write, and recipe file to read, in bytes.
    #[arg(long, value_name = "BYTES", default_value_t = JsonLimits::default().max_bytes)]
    max_manifest_size: usize,
}

/// Check that a manifest is well-formed and follows the specification.
///
/// The manifest is read strictly and checked against every rule of the
/// version 0 specification. Validation does not look at the artifact, and it
/// cannot tell who wrote the manifest: a valid manifest is still only a claim.
#[derive(Debug, Args)]
pub struct ValidateArgs {
    /// Manifest file, or "-" to read standard input.
    path: String,

    /// Treat every warning, such as an unknown field, as an error.
    #[arg(long)]
    strict: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Largest manifest to read, in bytes.
    #[arg(long, value_name = "BYTES", default_value_t = JsonLimits::default().max_bytes)]
    max_manifest_size: usize,
}

pub fn run(command: &ManifestCommand) -> ExitCode {
    match command {
        ManifestCommand::Create(args) => create(args),
        ManifestCommand::Validate(args) => validate(args),
    }
}

fn parse_options(max_bytes: usize, strict: bool) -> ParseOptions {
    let mut opts = ParseOptions::default();
    opts.limits.max_bytes = max_bytes;
    opts.strict = strict;
    opts
}

/// Reads at most `max + 1` bytes, so that an oversized document is
/// recognized without reading it all.
fn read_limited(reader: impl Read, max: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    reader.take(limit).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn shown(path: &Path) -> String {
    sanitize(&path.to_string_lossy())
}

fn create(args: &CreateArgs) -> ExitCode {
    let opts = parse_options(args.max_manifest_size, false);
    // The recipe is checked first, so that a mistake in it does not wait for
    // a long inspection.
    let definition = match &args.build_definition {
        Some(path) => {
            let bytes = match File::open(path)
                .and_then(|file| read_limited(file, args.max_manifest_size))
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    diagnostic(&format!(
                        "error: {}: {}",
                        shown(path),
                        sanitize(&e.to_string())
                    ));
                    return ExitCode::from(EXIT_FAILED);
                }
            };
            match parse_build_definition(&bytes, &opts) {
                // A recipe TrustForge cannot read would be embedded unchecked;
                // a misspelled build type must not turn into that.
                Ok((BuildDefinition::Unsupported { build_type, .. }, _)) => {
                    diagnostic(&format!(
                        "error: {}: build type {} is not supported; the only one that can be embedded is {CARGO_BUILD_TYPE_V0}",
                        shown(path),
                        sanitize(&build_type)
                    ));
                    return ExitCode::from(EXIT_USAGE);
                }
                Ok((definition, warnings)) => {
                    for warning in warnings {
                        diagnostic(&format!(
                            "warning: {}: {}",
                            shown(path),
                            sanitize(&warning.to_string())
                        ));
                    }
                    Some(definition)
                }
                Err(e) => {
                    diagnostic(&format!(
                        "error: {}: {}",
                        shown(path),
                        sanitize(&e.to_string())
                    ));
                    return ExitCode::from(EXIT_USAGE);
                }
            }
        }
        None => None,
    };
    if args.artifact.is_stdin() && args.name.is_none() {
        diagnostic("error: a manifest for standard input needs a subject name: use --name");
        return ExitCode::from(EXIT_USAGE);
    }
    // Checked again when writing; checking now avoids a long inspection.
    if let Some(path) = &args.output
        && let Err(e) = output::check_destination(path)
    {
        diagnostic(&format!(
            "error: {}: {}",
            shown(path),
            sanitize(&e.to_string())
        ));
        return ExitCode::from(EXIT_FAILED);
    }

    let Some(inspection) = args.artifact.inspect() else {
        return ExitCode::from(EXIT_FAILED);
    };
    let mut manifest = match Manifest::from_inspection(&inspection, args.name.as_deref()) {
        Ok(manifest) => manifest,
        Err(e) => {
            diagnostic(&format!("error: {}", sanitize(&e.to_string())));
            let usage = matches!(
                &e,
                ManifestError::Invalid {
                    problem: Problem::Name(_),
                    ..
                }
            ) && args.name.is_some();
            return ExitCode::from(if usage { EXIT_USAGE } else { EXIT_FAILED });
        }
    };
    if let Some(definition) = definition {
        manifest = manifest.with_build_definition(definition);
    }
    if !args.artifact.algorithms().contains(DigestAlgorithm::Sha256) {
        diagnostic("warning: without sha256, other in-toto tools may not recognize the subjects");
    }

    let bytes = if args.canonical {
        manifest.to_canonical_json()
    } else {
        manifest.to_pretty_json()
    };
    if bytes.len() > args.max_manifest_size {
        diagnostic(&format!(
            "error: the manifest would be {} bytes, more than the limit of {}",
            bytes.len(),
            args.max_manifest_size
        ));
        diagnostic(
            "hint: raise the limit with --max-manifest-size; readers need the same limit to read it",
        );
        return ExitCode::from(EXIT_FAILED);
    }
    // A manifest TrustForge writes must pass its own validation.
    if let Err(e) = parse_manifest(&bytes, &opts) {
        diagnostic(&format!(
            "error: internal error: the created manifest does not validate: {}",
            sanitize(&e.to_string())
        ));
        return ExitCode::from(EXIT_FAILED);
    }
    match &args.output {
        Some(path) => match output::to_file(path, &bytes) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                diagnostic(&format!(
                    "error: {}: {}",
                    shown(path),
                    sanitize(&e.to_string())
                ));
                ExitCode::from(EXIT_FAILED)
            }
        },
        None => output::to_stdout(&bytes, ExitCode::SUCCESS),
    }
}

fn validate(args: &ValidateArgs) -> ExitCode {
    let (label, read) = if args.path == "-" {
        (
            "(standard input)".to_owned(),
            read_limited(io::stdin().lock(), args.max_manifest_size),
        )
    } else {
        (
            sanitize(&args.path),
            File::open(&args.path).and_then(|file| read_limited(file, args.max_manifest_size)),
        )
    };
    let bytes = match read {
        Ok(bytes) => bytes,
        Err(e) => {
            diagnostic(&format!("error: {label}: {}", sanitize(&e.to_string())));
            return ExitCode::from(EXIT_FAILED);
        }
    };
    let result = parse_manifest(&bytes, &parse_options(args.max_manifest_size, args.strict));
    let code = if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_USAGE)
    };
    match args.format {
        Format::Text => match result {
            Ok(parsed) => output::to_stdout(validation_text(&label, &parsed).as_bytes(), code),
            Err(e) => {
                diagnostic(&format!("error: {label}: {}", sanitize(&e.to_string())));
                code
            }
        },
        Format::Json => {
            // An oversized document is not hashed: only part of it was read.
            let digest = (bytes.len() <= args.max_manifest_size)
                .then(|| Digest::of(DigestAlgorithm::Sha256, &bytes));
            let document = validation_json(digest.as_ref(), &result);
            match serde_json::to_string_pretty(&document) {
                Ok(text) => {
                    output::to_stdout(format!("{}\n", escape_for_terminal(&text)).as_bytes(), code)
                }
                Err(e) => {
                    diagnostic(&format!(
                        "error: cannot write the output: {}",
                        sanitize(&e.to_string())
                    ));
                    ExitCode::from(EXIT_FAILED)
                }
            }
        }
    }
}

fn validation_text(label: &str, parsed: &ParsedManifest) -> String {
    let manifest = &parsed.manifest;
    let mut lines = vec![
        format!("Manifest   {label}"),
        format!(
            "SHA-256    {} (identifies these exact bytes)",
            parsed.file_digest.to_hex()
        ),
    ];
    let subjects = manifest.subjects();
    lines.push(match manifest.artifact() {
        ArtifactClaim::Directory { size, tree, .. } => format!(
            "Artifact   directory: {} entries{}, {} subjects",
            tree.len(),
            size.map(|s| format!(", {s} bytes in regular files"))
                .unwrap_or_default(),
            subjects.len()
        ),
        ArtifactClaim::File { size } => format!(
            "Artifact   file{}, subject {}",
            size.map(|s| format!(" of {s} bytes")).unwrap_or_default(),
            subjects
                .first()
                .map(|s| sanitize(s.name().as_str()))
                .unwrap_or_default()
        ),
        _ => "Artifact   (not described by this version)".to_owned(),
    });
    match manifest.build_definition() {
        Some(BuildDefinition::Cargo(recipe)) => {
            lines.push(format!(
                "Recipe     cargo/v0: binary {} for {}, toolchain {}",
                sanitize(recipe.bin()),
                sanitize(recipe.target()),
                sanitize(recipe.toolchain())
            ));
            lines.push(format!(
                "Source     {}{}, commit {}",
                sanitize(recipe.repository()),
                recipe
                    .git_ref()
                    .map(|r| format!(" at {}", sanitize(r)))
                    .unwrap_or_default(),
                sanitize(recipe.source_commit())
            ));
            lines.push(format!(
                "Image      {}, {}",
                sanitize(recipe.image()),
                recipe.image_digest()
            ));
        }
        Some(BuildDefinition::Unsupported { build_type, .. }) => {
            lines.push(format!(
                "Recipe     unsupported build type {}",
                sanitize(build_type)
            ));
        }
        Some(_) => lines.push("Recipe     (not described by this version)".to_owned()),
        None => lines.push("Recipe     none".to_owned()),
    }
    if parsed.warnings.is_empty() {
        lines.push("Warnings   none".to_owned());
    } else {
        lines.push(format!("Warnings   {}", parsed.warnings.len()));
        for warning in &parsed.warnings {
            lines.push(format!("  {}", sanitize(&warning.to_string())));
        }
    }
    lines.push(String::new());
    lines.push(
        "Valid: well-formed and follows the manifest v0 rules. A manifest is a claim, not evidence: \
         validation does not look at the artifact, and an unsigned manifest does not show who wrote it."
            .to_owned(),
    );
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

fn validation_json(
    digest: Option<&Digest>,
    result: &Result<ParsedManifest, ManifestError>,
) -> serde_json::Value {
    let manifest_digest = digest.map(|d| json!({ "sha256": d.to_hex() }));
    match result {
        Ok(parsed) => {
            let manifest = &parsed.manifest;
            let artifact = match manifest.artifact() {
                ArtifactClaim::File { size } => json!({ "kind": "file", "size": size }),
                ArtifactClaim::Directory { size, tree, .. } => {
                    json!({ "kind": "directory", "size": size, "entries": tree.len() })
                }
                _ => json!({}),
            };
            let build_type = match manifest.build_definition() {
                Some(BuildDefinition::Cargo(_)) => {
                    Some(trustforge_core::manifest::CARGO_BUILD_TYPE_V0.to_owned())
                }
                Some(BuildDefinition::Unsupported { build_type, .. }) => Some(build_type.clone()),
                _ => None,
            };
            let warnings: Vec<_> = parsed
                .warnings
                .iter()
                .map(
                    |w| json!({ "pointer": w.pointer.to_rfc6901(), "message": w.kind.to_string() }),
                )
                .collect();
            json!({
                "valid": true,
                "manifestDigest": manifest_digest,
                "predicateType": trustforge_core::manifest::PREDICATE_TYPE_V0,
                "subjects": manifest.subjects().len(),
                "artifact": artifact,
                "buildType": build_type,
                "warnings": warnings,
            })
        }
        Err(e) => {
            let pointer = match e {
                ManifestError::Invalid { pointer, .. }
                | ManifestError::Unsupported { pointer, .. }
                | ManifestError::Json(JsonError::Strict { pointer, .. }) => {
                    Some(pointer.to_rfc6901())
                }
                _ => None,
            };
            json!({
                "valid": false,
                "manifestDigest": manifest_digest,
                "error": { "message": e.to_string(), "pointer": pointer },
            })
        }
    }
}
