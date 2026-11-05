//! Directory traversal on Unix: one pass that produces the tree digests (of
//! the NAR serialization), the per-file digests and the entry listing.
//!
//! Below the root, nothing is ever resolved by path. Each entry is examined
//! by its single name relative to its parent directory's descriptor, with
//! `fstatat(AT_SYMLINK_NOFOLLOW)`, then opened with `O_NOFOLLOW` and checked
//! with `fstat` to be the same object. Symbolic links are recorded, never
//! followed. FIFOs, sockets and devices are never opened.
//!
//! Concurrent modification is detected on a best-effort basis:
//! - a file must read exactly its reported size, then report the same
//!   identity, permissions, link count, size and timestamps (including the
//!   status-change time, which a writer cannot reset), and its name must
//!   still refer to it;
//! - a directory must report unchanged metadata after it is listed and after
//!   its subtree is done, and its name must still refer to it;
//! - after the walk, every entry is examined once more and must still match
//!   what was recorded. Each entry was unchanged while it was read, so the
//!   result describes the tree as it was at one moment (between the walk and
//!   this final pass) rather than a mix of states, for example a file that
//!   was moved from a finished directory into one not yet listed.
//!
//! The traversal is iterative. One descriptor is open per directory level
//! (the root, and at most `max_depth` levels below it), plus one for the file
//! or listing in progress and a second one for the root, kept for the final
//! pass.

use std::fs::File;
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags};
use rustix::io::{Errno, fcntl_dupfd_cloexec, retry_on_intr};

use super::unix::{Meta, describe, fstat_meta, meta_from, open_error};
use super::{
    EntryCounts, EntryKind, ErrorPath, InspectError, InspectOptions, Limit, TreeEntry,
    charge_bytes, read_exact_len,
};
use crate::digest::{DigestSet, MultiHasher, READ_BUFFER_SIZE};
use crate::name::{RelPath, validate_name, validate_symlink_target};
use crate::nar::NarWriter;

/// Symlink targets longer than this are never read in full; see
/// [`super::Limits::max_symlink_target_len`].
const SYMLINK_BUFFER_CAP: usize = 65_536;

/// Points in the traversal where tests can change the tree. The production
/// walker uses [`NoHooks`].
pub(crate) trait WalkHooks {
    /// A directory has just been listed (`None`: the root).
    fn after_list(&mut self, _dir: Option<&RelPath>) {}
    /// A regular file has just been opened, before it is read.
    fn after_open(&mut self, _file: &RelPath) {}
    /// A regular file has been read to its end, before it is re-checked.
    fn after_read(&mut self, _file: &RelPath) {}
    /// All of a directory's entries are done, before it is re-checked.
    fn before_finish(&mut self, _dir: Option<&RelPath>) {}
}

pub(crate) struct NoHooks;

impl WalkHooks for NoHooks {}

/// The result of a walk.
pub(crate) struct TreeOutput {
    pub(crate) digests: DigestSet,
    pub(crate) entries: Vec<TreeEntry>,
    pub(crate) counts: EntryCounts,
    /// Total size of the regular files.
    pub(crate) size: u64,
}

/// Flags for opening a directory below the root.
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);

/// A second descriptor for an open directory, closed on `exec` so that a
/// program embedding this library cannot leak it to child processes.
fn duplicate(fd: &OwnedFd) -> rustix::io::Result<OwnedFd> {
    fcntl_dupfd_cloexec(fd, 0)
}

/// Why a directory may not be entered.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    MountPoint,
    Cycle,
}

/// A directory may only be entered if it is on its parent's file system and
/// is not one of its own ancestors (as a bind mount can make it).
fn refuse_entry<'m>(
    meta: &Meta,
    parent: &Meta,
    mut ancestors: impl Iterator<Item = &'m Meta>,
) -> Option<Refusal> {
    if meta.dev != parent.dev {
        Some(Refusal::MountPoint)
    } else if ancestors.any(|ancestor| ancestor.same_object(meta)) {
        Some(Refusal::Cycle)
    } else {
        None
    }
}

/// Whether a directory still looks as it did: still linked, with identical
/// metadata. Listing it or walking below it changes nothing compared here.
fn directory_unchanged(before: &Meta, now: &Meta) -> bool {
    now.nlink != 0 && now == before
}

/// An open directory on the traversal stack.
struct Frame {
    fd: OwnedFd,
    meta: Meta,
    /// `None` for the root.
    path: Option<RelPath>,
    /// The name in the parent directory; `None` for the root.
    name: Option<String>,
    /// Number of path components; 0 for the root.
    depth: u32,
    /// Entry names, sorted by bytes.
    names: Vec<String>,
    next: usize,
}

struct Walker<'a, H> {
    root: &'a Path,
    opts: &'a InspectOptions,
    hooks: &'a mut H,
    nar: NarWriter<MultiHasher>,
    buf: Vec<u8>,
    link_buf: Vec<u8>,
    entries: Vec<TreeEntry>,
    /// The metadata of each entry when it was read, for the final pass.
    metas: Vec<Meta>,
    counts: EntryCounts,
    size: u64,
    /// Content bytes charged against the limit.
    bytes: u64,
    /// Entries listed so far.
    listed: u64,
    /// Total length of the entry paths listed so far.
    path_bytes: u64,
}

/// Walks the directory open as `fd`, whose metadata is `meta`.
pub(crate) fn walk<H: WalkHooks>(
    root: &Path,
    fd: OwnedFd,
    meta: Meta,
    opts: &InspectOptions,
    hooks: &mut H,
) -> Result<TreeOutput, InspectError> {
    let nar =
        NarWriter::new(MultiHasher::new(&opts.algorithms)).map_err(|source| InspectError::Io {
            path: ErrorPath::root(root),
            source,
        })?;
    let mut w = Walker {
        root,
        opts,
        hooks,
        nar,
        buf: vec![0; READ_BUFFER_SIZE],
        link_buf: vec![0; opts.limits.max_symlink_target_len.min(SYMLINK_BUFFER_CAP) + 1],
        entries: Vec::new(),
        metas: Vec::new(),
        counts: EntryCounts::default(),
        size: 0,
        bytes: 0,
        listed: 0,
        path_bytes: 0,
    };
    // The root's frame closes its descriptor when it is done; the final pass
    // needs one of its own.
    let root_again = duplicate(&fd).map_err(|e| InspectError::Io {
        path: ErrorPath::root(root),
        source: e.into(),
    })?;
    let names = w.list(&fd, &meta, None)?;
    w.hooks.after_list(None);
    w.nar_op(None, |nar| nar.begin_directory())?;
    let mut stack = vec![Frame {
        fd,
        meta,
        path: None,
        name: None,
        depth: 0,
        names,
        next: 0,
    }];

    while let Some(top) = stack.last_mut() {
        let Some(name) = top.names.get(top.next).cloned() else {
            if let Some(frame) = stack.pop() {
                w.finish_directory(&frame, stack.last())?;
            }
            continue;
        };
        top.next += 1;
        if let Some(frame) = w.entry(&stack, name)? {
            stack.push(frame);
        }
    }
    w.verify_snapshot(&root_again, &meta)?;

    let hasher = w.nar.finish().map_err(|source| InspectError::Io {
        path: ErrorPath::root(root),
        source,
    })?;
    Ok(TreeOutput {
        digests: hasher.finalize(),
        entries: w.entries,
        counts: w.counts,
        size: w.size,
    })
}

impl<H: WalkHooks> Walker<'_, H> {
    fn at(&self, path: Option<&RelPath>) -> ErrorPath {
        match path {
            Some(path) => ErrorPath::entry(self.root, path),
            None => ErrorPath::root(self.root),
        }
    }

    fn changed(&self, path: Option<&RelPath>, detail: &'static str) -> InspectError {
        InspectError::ConcurrentModification {
            path: self.at(path),
            detail,
        }
    }

    fn limit(&self, path: Option<&RelPath>, limit: Limit, max: u64) -> InspectError {
        InspectError::LimitExceeded {
            path: self.at(path),
            limit,
            max,
        }
    }

    /// Runs a NAR operation. The writer only fails if the framing rules are
    /// broken, which would be a bug: the walk stops rather than produce a
    /// digest of a malformed archive.
    fn nar_op(
        &mut self,
        path: Option<&RelPath>,
        op: impl FnOnce(&mut NarWriter<MultiHasher>) -> std::io::Result<()>,
    ) -> Result<(), InspectError> {
        op(&mut self.nar).map_err(|source| InspectError::Io {
            path: self.at(path),
            source,
        })
    }

    /// `fstatat(dirfd, name, AT_SYMLINK_NOFOLLOW)`.
    fn stat_entry(
        &self,
        dirfd: &OwnedFd,
        name: &str,
        path: &RelPath,
    ) -> Result<Meta, InspectError> {
        match fs::statat(dirfd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => {
                Err(self.changed(Some(path), "it disappeared after its directory was listed"))
            }
            result => meta_from(result, || self.at(Some(path))),
        }
    }

    /// Reads, validates and sorts the names in a directory, then checks that
    /// the directory did not change meanwhile.
    fn list(
        &mut self,
        fd: &OwnedFd,
        meta: &Meta,
        path: Option<&RelPath>,
    ) -> Result<Vec<String>, InspectError> {
        let io = |w: &Self, e: Errno| InspectError::Io {
            path: w.at(path),
            source: e.into(),
        };
        // A duplicate of the descriptor, unlike reopening ".", needs no
        // search permission, so readable directories list as they do in Nix.
        let mut dir = Dir::new(duplicate(fd).map_err(|e| io(self, e))?).map_err(|e| io(self, e))?;
        let prefix_len = path.map_or(0, |p| p.as_str().len() + 1) as u64;
        let mut names = Vec::new();
        while let Some(item) = dir.read() {
            let item = item.map_err(|e| io(self, e))?;
            let raw = item.file_name().to_bytes();
            if raw == b"." || raw == b".." {
                continue;
            }
            let name = validate_name(raw).map_err(|reason| InspectError::InvalidName {
                path: ErrorPath::raw_entry(self.root, path, raw),
                reason,
            })?;
            self.listed += 1;
            if self.listed > self.opts.limits.max_entries {
                return Err(self.limit(path, Limit::Entries, self.opts.limits.max_entries));
            }
            self.path_bytes = self
                .path_bytes
                .saturating_add(prefix_len + name.len() as u64);
            if self.path_bytes > self.opts.limits.max_path_bytes {
                return Err(self.limit(path, Limit::PathBytes, self.opts.limits.max_path_bytes));
            }
            names.push(name.to_owned());
        }
        drop(dir);
        // A directory that changes while it is listed can repeat a name, so
        // rule that out before blaming the file system for a duplicate.
        if !directory_unchanged(meta, &fstat_meta(fd, || self.at(path))?) {
            return Err(self.changed(path, "the directory changed while it was being listed"));
        }
        names.sort_unstable();
        if let Some(pair) = names.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(InspectError::DuplicateEntry {
                path: ErrorPath::entry(self.root, &RelPath::child(path, &pair[0])),
            });
        }
        Ok(names)
    }

    /// Processes the next entry of the directory at the top of `stack`.
    /// Returns a new frame if the entry is a directory.
    fn entry(&mut self, stack: &[Frame], name: String) -> Result<Option<Frame>, InspectError> {
        let Some(parent) = stack.last() else {
            return Ok(None);
        };
        let path = RelPath::child(parent.path.as_ref(), &name);
        let depth = parent.depth + 1;
        if depth > self.opts.limits.max_depth {
            return Err(self.limit(
                Some(&path),
                Limit::Depth,
                u64::from(self.opts.limits.max_depth),
            ));
        }
        self.nar_op(Some(&path), |nar| nar.begin_entry(name.as_bytes()))?;
        let st = self.stat_entry(&parent.fd, &name, &path)?;
        match st.file_type {
            FileType::RegularFile => self.file(parent, &name, path, &st).map(|()| None),
            FileType::Symlink => self.symlink(parent, &name, path, &st).map(|()| None),
            FileType::Directory => self
                .directory(stack, parent, name, path, depth, &st)
                .map(Some),
            other => Err(InspectError::UnsupportedFileType {
                path: self.at(Some(&path)),
                kind: describe(other),
            }),
        }
    }

    fn file(
        &mut self,
        parent: &Frame,
        name: &str,
        path: RelPath,
        st: &Meta,
    ) -> Result<(), InspectError> {
        let flags =
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
        let fd = retry_on_intr(|| fs::openat(&parent.fd, name, flags, Mode::empty()))
            .map_err(|e| open_error(e, self.at(Some(&path))))?;
        let meta = fstat_meta(&fd, || self.at(Some(&path)))?;
        if meta.file_type != FileType::RegularFile || !meta.same_object(st) {
            return Err(self.changed(Some(&path), "it was replaced before it could be read"));
        }
        self.hooks.after_open(&path);
        self.bytes = charge_bytes(self.bytes, meta.size, &self.opts.limits, || {
            self.at(Some(&path))
        })?;

        self.nar_op(Some(&path), |nar| {
            nar.begin_regular(meta.owner_executable, meta.size)
        })?;
        let mut file = File::from(fd);
        let mut hasher = MultiHasher::new(&self.opts.algorithms);
        let nar = &mut self.nar;
        read_exact_len(&mut file, meta.size, &mut self.buf, |chunk| {
            hasher.update(chunk);
            nar.contents(chunk)
        })
        .map_err(|e| e.into_inspect_error(ErrorPath::entry(self.root, &path)))?;
        self.hooks.after_read(&path);

        if fstat_meta(&file, || self.at(Some(&path)))? != meta {
            return Err(self.changed(Some(&path), "it was modified while being read"));
        }
        // While the file is still open, its inode cannot be reused: if the
        // name refers to it now, it did so throughout.
        if !self.stat_entry(&parent.fd, name, &path)?.same_object(&meta) {
            return Err(self.changed(Some(&path), "it was replaced while being read"));
        }
        drop(file);
        self.nar_op(Some(&path), |nar| nar.end_regular())?;

        self.counts.files += 1;
        self.size += meta.size;
        self.metas.push(meta);
        self.entries.push(TreeEntry {
            path,
            kind: EntryKind::File {
                executable: meta.owner_executable,
                size: meta.size,
                digest: hasher.finalize(),
            },
        });
        Ok(())
    }

    fn symlink(
        &mut self,
        parent: &Frame,
        name: &str,
        path: RelPath,
        st: &Meta,
    ) -> Result<(), InspectError> {
        let len = match fs::readlinkat_raw(&parent.fd, name, &mut self.link_buf[..]) {
            Ok(len) => len,
            Err(Errno::NOENT | Errno::INVAL) => {
                return Err(self.changed(Some(&path), "it stopped being a symbolic link"));
            }
            Err(e) => {
                return Err(InspectError::Io {
                    path: self.at(Some(&path)),
                    source: e.into(),
                });
            }
        };
        let max = self
            .opts
            .limits
            .max_symlink_target_len
            .min(SYMLINK_BUFFER_CAP);
        if len > max {
            return Err(self.limit(Some(&path), Limit::SymlinkTargetLength, max as u64));
        }
        let raw = &self.link_buf[..len];
        let target = validate_symlink_target(raw)
            .map_err(|reason| InspectError::InvalidSymlinkTarget {
                path: self.at(Some(&path)),
                reason,
            })?
            .to_owned();
        if self.stat_entry(&parent.fd, name, &path)? != *st {
            return Err(self.changed(Some(&path), "the symbolic link changed while being read"));
        }
        self.nar_op(Some(&path), |nar| nar.symlink(target.as_bytes()))?;

        self.counts.symlinks += 1;
        let target_leaves_tree = leaves_tree(&path, &target);
        self.metas.push(*st);
        self.entries.push(TreeEntry {
            path,
            kind: EntryKind::Symlink {
                target,
                target_leaves_tree,
            },
        });
        Ok(())
    }

    fn directory(
        &mut self,
        stack: &[Frame],
        parent: &Frame,
        name: String,
        path: RelPath,
        depth: u32,
        st: &Meta,
    ) -> Result<Frame, InspectError> {
        let fd =
            retry_on_intr(|| fs::openat(&parent.fd, name.as_str(), DIRECTORY_FLAGS, Mode::empty()))
                .map_err(|e| open_error(e, self.at(Some(&path))))?;
        let meta = fstat_meta(&fd, || self.at(Some(&path)))?;
        if meta.file_type != FileType::Directory || !meta.same_object(st) {
            return Err(self.changed(Some(&path), "it was replaced before it could be listed"));
        }
        match refuse_entry(&meta, &parent.meta, stack.iter().map(|frame| &frame.meta)) {
            Some(Refusal::MountPoint) => {
                return Err(InspectError::MountPoint {
                    path: self.at(Some(&path)),
                });
            }
            Some(Refusal::Cycle) => {
                return Err(InspectError::DirectoryCycle {
                    path: self.at(Some(&path)),
                });
            }
            None => {}
        }
        self.counts.directories += 1;
        self.metas.push(meta);
        self.entries.push(TreeEntry {
            path: path.clone(),
            kind: EntryKind::Directory,
        });
        let names = self.list(&fd, &meta, Some(&path))?;
        self.hooks.after_list(Some(&path));
        self.nar_op(Some(&path), |nar| nar.begin_directory())?;
        Ok(Frame {
            fd,
            meta,
            path: Some(path),
            name: Some(name),
            depth,
            names,
            next: 0,
        })
    }

    /// Closes a directory whose entries are all done.
    fn finish_directory(
        &mut self,
        frame: &Frame,
        parent: Option<&Frame>,
    ) -> Result<(), InspectError> {
        let path = frame.path.as_ref();
        self.hooks.before_finish(path);
        if !directory_unchanged(&frame.meta, &fstat_meta(&frame.fd, || self.at(path))?) {
            return Err(self.changed(path, "the directory changed while its entries were read"));
        }
        if let (Some(parent), Some(name), Some(rel)) = (parent, &frame.name, path)
            && !self
                .stat_entry(&parent.fd, name, rel)?
                .same_object(&frame.meta)
        {
            return Err(self.changed(path, "the directory was moved or replaced"));
        }
        self.nar_op(path, |nar| nar.end_directory())
    }

    /// Examines every entry once more, after the walk, through descriptors
    /// opened the same way as during the walk.
    fn verify_snapshot(&self, root_fd: &OwnedFd, root_meta: &Meta) -> Result<(), InspectError> {
        const DETAIL: &str =
            "it changed after it was read, while the rest of the tree was inspected";
        if !directory_unchanged(root_meta, &fstat_meta(root_fd, || self.at(None))?) {
            return Err(self.changed(None, DETAIL));
        }
        // Open directories below the root, outermost first.
        let mut open: Vec<OwnedFd> = Vec::new();
        for (entry, recorded) in self.entries.iter().zip(&self.metas) {
            let path = entry.path();
            // Entries come depth-first, so the directories still needed are
            // exactly this entry's ancestors.
            open.truncate(path.as_str().matches('/').count());
            let parent = open.last().unwrap_or(root_fd);
            let name = path
                .as_str()
                .rsplit_once('/')
                .map_or(path.as_str(), |(_, name)| name);
            let now = match fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
                Err(Errno::NOENT) => return Err(self.changed(Some(path), DETAIL)),
                result => meta_from(result, || self.at(Some(path)))?,
            };
            let is_directory = matches!(entry.kind(), EntryKind::Directory);
            let unchanged = if is_directory {
                directory_unchanged(recorded, &now)
            } else {
                now == *recorded
            };
            if !unchanged {
                return Err(self.changed(Some(path), DETAIL));
            }
            if is_directory {
                let fd = retry_on_intr(|| fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty()))
                    .map_err(|e| open_error(e, self.at(Some(path))))?;
                if !directory_unchanged(recorded, &fstat_meta(&fd, || self.at(Some(path)))?) {
                    return Err(self.changed(Some(path), DETAIL));
                }
                open.push(fd);
            }
        }
        Ok(())
    }
}

/// Whether a symlink target, read as text relative to the link's directory,
/// is absolute or climbs above the tree's root. Other symlinks on the way
/// are not considered, so this is informational only.
fn leaves_tree(link: &RelPath, target: &str) -> bool {
    if target.starts_with('/') {
        return true;
    }
    let mut depth = link.as_str().matches('/').count();
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => match depth.checked_sub(1) {
                Some(d) => depth = d,
                None => return true,
            },
            _ => depth += 1,
        }
    }
    false
}

#[cfg(test)]
// Tests that skip themselves say so on stderr.
#[allow(clippy::print_stderr)]
mod tests {
    use super::*;
    use crate::inspect::{ArtifactDigests, inspect_path};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::{Duration, SystemTime};

    fn rel(path: &str) -> RelPath {
        let mut parts = path.split('/');
        let first = RelPath::child(None, parts.next().unwrap());
        parts.fold(first, |parent, name| RelPath::child(Some(&parent), name))
    }

    #[test]
    fn symlink_targets_that_leave_the_tree() {
        assert!(leaves_tree(&rel("a"), "/etc/passwd"));
        assert!(leaves_tree(&rel("a"), ".."));
        assert!(leaves_tree(&rel("d/a"), "../../x"));
        assert!(leaves_tree(&rel("d/a"), "x/../../../y"));
        assert!(!leaves_tree(&rel("a"), "b"));
        assert!(!leaves_tree(&rel("d/a"), "../b"));
        assert!(!leaves_tree(&rel("d/a"), "./x/../y"));
        assert!(!leaves_tree(&rel("d/e/a"), "../../b"));
    }

    /// Opens `dir` the way `inspect_path` does and walks it with `hooks`.
    fn walk_with(dir: &Path, hooks: &mut impl WalkHooks) -> Result<TreeOutput, InspectError> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let fd = fs::openat(fs::CWD, dir, flags, Mode::empty()).unwrap();
        let meta = Meta::from_stat(&fs::fstat(&fd).unwrap()).unwrap();
        walk(dir, fd, meta, &InspectOptions::default(), hooks)
    }

    /// Sets a file's or directory's modification time to an hour ago, so that
    /// any later change is visible whatever the timestamp granularity.
    fn backdate(path: &Path) {
        let an_hour_ago = SystemTime::now() - Duration::from_secs(3600);
        File::open(path).unwrap().set_modified(an_hour_ago).unwrap();
    }

    struct OnOpen<F: FnMut(&RelPath)>(F);
    impl<F: FnMut(&RelPath)> WalkHooks for OnOpen<F> {
        fn after_open(&mut self, file: &RelPath) {
            (self.0)(file)
        }
    }

    struct OnRead<F: FnMut(&RelPath)>(F);
    impl<F: FnMut(&RelPath)> WalkHooks for OnRead<F> {
        fn after_read(&mut self, file: &RelPath) {
            (self.0)(file)
        }
    }

    struct OnList<F: FnMut(Option<&RelPath>)>(F);
    impl<F: FnMut(Option<&RelPath>)> WalkHooks for OnList<F> {
        fn after_list(&mut self, dir: Option<&RelPath>) {
            (self.0)(dir)
        }
    }

    fn assert_changed(result: Result<TreeOutput, InspectError>, expected_detail: &str) {
        match result {
            Err(InspectError::ConcurrentModification { detail, .. }) => {
                assert!(
                    detail.contains(expected_detail),
                    "unexpected detail: {detail}"
                )
            }
            Err(other) => panic!("expected a concurrent modification, got {other}"),
            Ok(_) => panic!("expected a concurrent modification, got a result"),
        }
    }

    #[test]
    fn a_file_that_grows_while_open_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("f"), b"original").unwrap();
        let target = tmp.path().join("f");
        let mut grow = OnOpen(|_: &RelPath| std::fs::write(&target, b"original and more").unwrap());
        assert_changed(
            walk_with(tmp.path(), &mut grow),
            "more data than its reported size",
        );
    }

    #[test]
    fn a_file_that_shrinks_while_open_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("f");
        std::fs::write(&target, b"original").unwrap();
        let mut shrink = OnOpen(|_: &RelPath| std::fs::write(&target, b"orig").unwrap());
        assert_changed(
            walk_with(tmp.path(), &mut shrink),
            "ended before its reported size",
        );
    }

    #[test]
    fn a_file_replaced_by_rename_while_read_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("f"), b"original").unwrap();
        std::fs::write(tmp.path().join("other"), b"replaced").unwrap();
        let (target, other) = (tmp.path().join("f"), tmp.path().join("other"));
        let mut replace = OnRead(|_: &RelPath| std::fs::rename(&other, &target).unwrap());
        // Unlinking the open file changes its link count and status-change
        // time, so the metadata re-check usually fires before the name check.
        assert_changed(walk_with(tmp.path(), &mut replace), "");
    }

    #[test]
    fn a_same_size_rewrite_with_restored_mtime_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("f");
        std::fs::write(&target, b"original").unwrap();
        backdate(&target);
        let ctime_before = std::fs::metadata(&target).unwrap();
        let mut rewrite = OnRead(|_: &RelPath| {
            let mtime = std::fs::metadata(&target).unwrap().modified().unwrap();
            std::fs::write(&target, b"ORIGINAL").unwrap();
            File::options()
                .write(true)
                .open(&target)
                .unwrap()
                .set_modified(mtime)
                .unwrap();
        });
        let result = walk_with(tmp.path(), &mut rewrite);
        // The status-change time reveals the rewrite, unless this file
        // system's ctime is too coarse to have moved.
        use std::os::unix::fs::MetadataExt;
        let after = std::fs::metadata(&target).unwrap();
        if (after.ctime(), after.ctime_nsec()) == (ctime_before.ctime(), ctime_before.ctime_nsec())
        {
            eprintln!("skipped: ctime did not change on this file system");
            return;
        }
        assert_changed(result, "modified while being read");
    }

    #[test]
    fn an_entry_added_after_listing_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a"), b"a").unwrap();
        backdate(tmp.path());
        let added = tmp.path().join("b");
        let mut add = OnList(|dir: Option<&RelPath>| {
            if dir.is_none() {
                std::fs::write(&added, b"b").unwrap();
            }
        });
        assert_changed(
            walk_with(tmp.path(), &mut add),
            "changed while its entries were read",
        );
    }

    #[test]
    fn an_entry_removed_after_listing_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a"), b"a").unwrap();
        let removed = tmp.path().join("a");
        let mut remove = OnList(|dir: Option<&RelPath>| {
            if dir.is_none() {
                std::fs::remove_file(&removed).unwrap();
            }
        });
        assert_changed(
            walk_with(tmp.path(), &mut remove),
            "disappeared after its directory was listed",
        );
    }

    #[test]
    fn a_subdirectory_replaced_during_its_walk_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("d")).unwrap();
        std::fs::write(tmp.path().join("d/f"), b"f").unwrap();
        std::fs::create_dir(tmp.path().join("e")).unwrap();
        let (d, e, moved) = (
            tmp.path().join("d"),
            tmp.path().join("e"),
            tmp.path().join("old"),
        );
        let mut swap = OnRead(|_: &RelPath| {
            std::fs::rename(&d, &moved).unwrap();
            std::fs::rename(&e, &d).unwrap();
        });
        let result = walk_with(tmp.path(), &mut swap);
        assert!(
            matches!(result, Err(InspectError::ConcurrentModification { .. })),
            "{:?}",
            result.err()
        );
    }

    #[test]
    fn a_file_moved_between_directories_mid_walk_is_rejected() {
        // Walk order: a, a/f, a0, b. While a0 is read, `a` is already done
        // and `b` is not yet listed, so only the final pass can notice.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir(root.join("a")).unwrap();
        std::fs::write(root.join("a/f"), b"f").unwrap();
        std::fs::write(root.join("a0"), b"a0").unwrap();
        std::fs::create_dir(root.join("b")).unwrap();
        backdate(&root.join("a"));
        let (from, to) = (root.join("a/f"), root.join("b/f"));
        let mut mv = OnRead(|file: &RelPath| {
            if file.as_str() == "a0" {
                std::fs::rename(&from, &to).unwrap();
            }
        });
        assert_changed(walk_with(root, &mut mv), "changed after it was read");
    }

    #[test]
    fn a_file_edited_after_it_was_hashed_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("a"), b"first").unwrap();
        std::fs::write(root.join("b"), b"second").unwrap();
        backdate(&root.join("a"));
        let earlier = root.join("a");
        let mut edit = OnRead(|file: &RelPath| {
            if file.as_str() == "b" {
                std::fs::write(&earlier, b"FIRST").unwrap();
            }
        });
        assert_changed(walk_with(root, &mut edit), "changed after it was read");
    }

    #[test]
    fn listing_descriptors_are_closed_on_exec() {
        use rustix::io::{FdFlags, fcntl_getfd};
        let dir = fs::openat(
            fs::CWD,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let copy = duplicate(&dir).unwrap();
        assert!(fcntl_getfd(&copy).unwrap().contains(FdFlags::CLOEXEC));
    }

    #[test]
    fn unreadable_entries_are_errors_naming_the_path() {
        let tmp = tempfile::tempdir().unwrap();
        let secret = tmp.path().join("secret");
        std::fs::write(&secret, b"x").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).unwrap();
        if File::open(&secret).is_ok() {
            eprintln!("skipped: running with permission to read anything (root?)");
            return;
        }
        let err = inspect_path(tmp.path(), &InspectOptions::default()).unwrap_err();
        assert!(matches!(err, InspectError::Io { .. }), "{err}");
        assert!(err.to_string().contains("secret"), "{err}");
    }

    #[test]
    fn an_empty_readable_but_unsearchable_directory_lists_like_nix() {
        let tmp = tempfile::tempdir().unwrap();
        let locked = tmp.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o400)).unwrap();
        let result = inspect_path(tmp.path(), &InspectOptions::default());
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        let inspection = result.unwrap();
        assert!(matches!(inspection.digests(), ArtifactDigests::Tree(_)));
        assert_eq!(inspection.counts().unwrap().directories, 1);
    }

    fn meta(dev: i128, ino: i128) -> Meta {
        Meta {
            file_type: FileType::Directory,
            dev,
            ino,
            permissions: 0o755,
            owner_executable: true,
            nlink: 2,
            size: 4096,
            mtime: (1, 0),
            ctime: (1, 0),
        }
    }

    #[test]
    fn mount_points_and_cycles_are_refused() {
        let root = meta(1, 10);
        let child = meta(1, 11);
        assert_eq!(refuse_entry(&child, &root, [&root].into_iter()), None);
        assert_eq!(
            refuse_entry(&meta(2, 11), &root, [&root].into_iter()),
            Some(Refusal::MountPoint)
        );
        // A bind mount of an ancestor keeps the device number.
        let grandchild = meta(1, 12);
        assert_eq!(
            refuse_entry(
                &meta(1, 10),
                &grandchild,
                [&root, &child, &grandchild].into_iter()
            ),
            Some(Refusal::Cycle)
        );
    }

    #[test]
    fn a_directory_that_was_unlinked_is_changed() {
        let before = meta(1, 10);
        assert!(directory_unchanged(&before, &before));
        let unlinked = Meta { nlink: 0, ..before };
        assert!(!directory_unchanged(&unlinked, &unlinked));
        let touched = Meta {
            ctime: (2, 0),
            ..before
        };
        assert!(!directory_unchanged(&before, &touched));
    }

    #[test]
    fn symlink_is_recorded_but_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        symlink("/dev/zero", tmp.path().join("zero")).unwrap();
        let out = walk_with(tmp.path(), &mut NoHooks).unwrap();
        assert_eq!(out.entries.len(), 1);
        assert_eq!(
            out.entries[0].kind(),
            &EntryKind::Symlink {
                target: "/dev/zero".into(),
                target_leaves_tree: true
            }
        );
    }
}
