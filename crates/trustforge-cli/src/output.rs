//! Writing results: standard output, standard error and output files.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use clap::ValueEnum;

use crate::EXIT_FAILED;
use crate::sanitize::sanitize;

/// Output format of commands that report a result.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Format {
    /// Human-readable text.
    Text,
    /// One JSON document.
    Json,
}

/// Writes one line to standard error. Unlike `eprintln!`, it does not panic
/// if standard error is closed, which would turn a failure (exit code 4)
/// into an internal error (101).
pub fn diagnostic(line: &str) {
    let _ = writeln!(io::stderr(), "{line}");
}

/// Writes `bytes` to standard output and returns the exit code for success
/// or for a failed write.
pub fn to_stdout(bytes: &[u8], success: ExitCode) -> ExitCode {
    let mut stdout = io::stdout().lock();
    match stdout.write_all(bytes).and_then(|()| stdout.flush()) {
        Ok(()) => success,
        // A reader that stopped early, such as `head`, wants no message.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::from(EXIT_FAILED),
        Err(e) => {
            diagnostic(&format!(
                "error: cannot write the output: {}",
                sanitize(&e.to_string())
            ));
            ExitCode::from(EXIT_FAILED)
        }
    }
}

/// Whether `path` may be written by [`to_file`]: it must not exist, or be a
/// regular file.
///
/// Renaming replaces whatever entry is at `path`, so anything else would be
/// replaced rather than written to: a device such as `/dev/null`, a FIFO, or
/// a symbolic link such as `/dev/stdout`, which as root breaks the system.
/// A symbolic link elsewhere is refused too, rather than followed (which
/// would let whoever planted it choose the file written) or replaced.
pub fn check_destination(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "exists and is not a regular file; only a regular file is replaced",
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Writes `bytes` to `path` all at once: into a new temporary file in the
/// same directory, which then replaces `path` by renaming. Readers never see
/// a partial file. Only a missing path or a regular file is accepted (see
/// [`check_destination`]).
pub fn to_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    check_destination(path)?;
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Temporary files are created private; a manifest is not secret.
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    file.persist(path).map_err(|e| e.error)?;
    Ok(())
}
