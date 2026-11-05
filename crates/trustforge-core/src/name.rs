//! Names and relative paths inside artifact trees.
//!
//! Names are compared byte for byte and are never converted lossily, so a
//! name that cannot be represented exactly as text, or displayed safely, is
//! rejected rather than altered (`docs/architecture.md`, traversal rule 4).
//! The forbidden characters are a fixed list; it does not grow with new
//! Unicode versions.

use std::fmt;

/// Why a name or symlink target was rejected.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    /// The name has no bytes.
    #[error("is empty")]
    Empty,
    /// The name is `.` or `..`.
    #[error("is \".\" or \"..\"")]
    DotOrDotDot,
    /// The name is not valid UTF-8.
    #[error("is not valid UTF-8")]
    InvalidUtf8,
    /// The name contains a character that is never allowed.
    #[error("contains the forbidden character U+{code:04X}")]
    ForbiddenChar {
        /// The character's code point.
        code: u32,
    },
}

/// Characters that are escaped whenever untrusted text is displayed: C0 and
/// C1 control characters (including ESC, which starts terminal escape
/// sequences), DEL, Unicode bidirectional controls, and the line and
/// paragraph separators.
pub const fn is_unsafe_to_display(c: char) -> bool {
    matches!(
        c,
        '\u{0}'..='\u{1f}'
            | '\u{7f}'..='\u{9f}'
            | '\u{61c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

/// Characters never allowed in a name or a symlink target: everything that
/// is unsafe to display, plus the backslash, which is a path separator on
/// Windows.
const fn is_forbidden(c: char) -> bool {
    c == '\\' || is_unsafe_to_display(c)
}

/// Validates one path component: a file, directory or symlink name.
///
/// A valid name is non-empty UTF-8, is not `.` or `..`, and contains no `/`
/// and no forbidden character: U+0000–U+001F, U+007F–U+009F, `\`, U+061C,
/// U+200E, U+200F, U+202A–U+202E, U+2066–U+2069, U+2028 or U+2029.
pub fn validate_name(bytes: &[u8]) -> Result<&str, NameError> {
    let name = validate_text(bytes)?;
    if name == "." || name == ".." {
        return Err(NameError::DotOrDotDot);
    }
    if name.contains('/') {
        return Err(NameError::ForbiddenChar {
            code: u32::from('/'),
        });
    }
    Ok(name)
}

/// Validates the text of a symbolic link target. The rules are those of
/// [`validate_name`], except that `/`, `.` and `..` are allowed.
pub fn validate_symlink_target(bytes: &[u8]) -> Result<&str, NameError> {
    validate_text(bytes)
}

fn validate_text(bytes: &[u8]) -> Result<&str, NameError> {
    let text = std::str::from_utf8(bytes).map_err(|_| NameError::InvalidUtf8)?;
    if text.is_empty() {
        return Err(NameError::Empty);
    }
    match text.chars().find(|&c| is_forbidden(c)) {
        Some(c) => Err(NameError::ForbiddenChar { code: u32::from(c) }),
        None => Ok(text),
    }
}

/// A relative path inside an artifact tree: one or more valid names joined
/// with `/`, with no leading `./`.
///
/// Its derived string order is *not* the order of entries in a tree, which is
/// depth-first with siblings sorted by name, so it deliberately does not
/// implement `Ord`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(transparent)]
pub struct RelPath(String);

impl RelPath {
    /// The path as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `parent/name`, or just `name` at the top of the tree. The caller has
    /// validated `name`.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn child(parent: Option<&RelPath>, name: &str) -> RelPath {
        match parent {
            Some(parent) => RelPath(format!("{}/{name}", parent.0)),
            None => RelPath(name.to_owned()),
        }
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Displays bytes that may be neither valid UTF-8 nor safe for a terminal.
///
/// Valid characters are shown as they are, except those in
/// [the display-unsafe list](validate_name), which are shown as `\u{…}`.
/// Bytes that are not valid UTF-8 are shown as `\xNN`. The output never
/// contains a control character, so it cannot inject terminal escape
/// sequences or reorder text.
#[derive(Clone, Copy)]
pub struct EscapedBytes<'a>(pub &'a [u8]);

impl fmt::Display for EscapedBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.utf8_chunks() {
            for c in chunk.valid().chars() {
                if is_unsafe_to_display(c) {
                    write!(f, "\\u{{{:x}}}", u32::from(c))?;
                } else {
                    fmt::Write::write_char(f, c)?;
                }
            }
            for b in chunk.invalid() {
                write!(f, "\\x{b:02x}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for EscapedBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{self}\"")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The forbidden list, written out independently of the implementation.
    fn forbidden_by_spec(c: char) -> bool {
        let code = u32::from(c);
        code <= 0x1f
            || (0x7f..=0x9f).contains(&code)
            || c == '\\'
            || [0x061c, 0x200e, 0x200f, 0x2028, 0x2029].contains(&code)
            || (0x202a..=0x202e).contains(&code)
            || (0x2066..=0x2069).contains(&code)
    }

    #[test]
    fn ordinary_names_are_accepted() {
        for name in [
            "a",
            "README.md",
            "a-b",
            "a.b",
            "ä",
            "日本語",
            "😀",
            ".hidden",
            "...",
            "a b",
        ] {
            assert_eq!(validate_name(name.as_bytes()), Ok(name));
        }
    }

    #[test]
    fn each_rule_rejects_what_it_should() {
        assert_eq!(validate_name(b""), Err(NameError::Empty));
        assert_eq!(validate_name(b"."), Err(NameError::DotOrDotDot));
        assert_eq!(validate_name(b".."), Err(NameError::DotOrDotDot));
        assert_eq!(validate_name(b"a\xffb"), Err(NameError::InvalidUtf8));
        assert_eq!(validate_name(b"\xed\xa0\x80"), Err(NameError::InvalidUtf8)); // surrogate
        assert_eq!(
            validate_name(b"a/b"),
            Err(NameError::ForbiddenChar { code: 0x2f })
        );
        for c in [
            '\0', '\t', '\n', '\r', '\u{1b}', '\u{7f}', '\u{80}', '\u{9b}', '\u{9f}', '\\',
            '\u{61c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202e}', '\u{2066}', '\u{2069}',
            '\u{2028}', '\u{2029}',
        ] {
            let name = format!("x{c}y");
            assert_eq!(
                validate_name(name.as_bytes()),
                Err(NameError::ForbiddenChar { code: u32::from(c) }),
                "{c:?}"
            );
        }
    }

    #[test]
    fn symlink_targets_allow_separators_and_dots() {
        for target in ["/usr/lib/libc.so.6", "../x", ".", "..", "a/./b"] {
            assert_eq!(validate_symlink_target(target.as_bytes()), Ok(target));
        }
        assert_eq!(validate_symlink_target(b""), Err(NameError::Empty));
        assert!(validate_symlink_target("a\\b".as_bytes()).is_err());
        assert!(validate_symlink_target("x\u{202e}".as_bytes()).is_err());
    }

    #[test]
    fn escaping_neutralizes_terminal_sequences_and_invalid_bytes() {
        let hostile = b"a\x1b]8;;http://x\x07\xe2\x80\xaeb\xff\\c";
        let shown = EscapedBytes(hostile).to_string();
        assert_eq!(shown, r"a\u{1b}]8;;http://x\u{7}\u{202e}b\xff\c");
        assert!(!shown.chars().any(is_unsafe_to_display));
    }

    #[test]
    fn rel_paths_join_with_slashes() {
        let a = RelPath::child(None, "a");
        let ab = RelPath::child(Some(&a), "b");
        assert_eq!(ab.as_str(), "a/b");
        assert_eq!(serde_json::to_string(&ab).unwrap(), "\"a/b\"");
    }

    proptest! {
        #[test]
        fn validator_matches_the_spec(s in "\\PC{0,4}|[\\x00-\\x{30}\\x{7e}-\\x{a0}\\x{600}-\\x{620}\\x{2000}-\\x{2070}\\\\/.]{0,4}") {
            let expected_ok = !s.is_empty()
                && s != "."
                && s != ".."
                && !s.contains('/')
                && !s.chars().any(forbidden_by_spec);
            prop_assert_eq!(validate_name(s.as_bytes()).is_ok(), expected_ok, "{:?}", s);
        }

        #[test]
        fn validator_and_escaping_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = validate_name(&bytes);
            let _ = validate_symlink_target(&bytes);
            let shown = EscapedBytes(&bytes).to_string();
            prop_assert!(!shown.chars().any(is_unsafe_to_display));
        }
    }
}
