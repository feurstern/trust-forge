//! The one sanitizer for text that reaches a terminal (`docs/architecture.md`,
//! "Output discipline").
//!
//! Artifact names, symlink targets and error messages can carry
//! attacker-chosen characters. Control characters (including the ESC that
//! starts ANSI and OSC sequences, such as OSC 8 hyperlinks and OSC 52
//! clipboard writes), bidi controls and line separators are escaped as
//! `\u{…}`, so they can neither drive the terminal nor reorder the text.

use trustforge_core::name::EscapedBytes;

/// `text` with every character unsafe for a terminal escaped.
pub fn sanitize(text: &str) -> String {
    EscapedBytes(text.as_bytes()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_sequences_cannot_pass() {
        let cases = [
            ("\u{1b}[2J\u{1b}[31mred", r"\u{1b}[2J\u{1b}[31mred"),
            (
                "\u{1b}]8;;https://evil\u{1b}\\link\u{1b}]8;;\u{1b}\\",
                r"\u{1b}]8;;https://evil\u{1b}\link\u{1b}]8;;\u{1b}\",
            ),
            ("\u{1b}]52;c;aGk=\u{7}", r"\u{1b}]52;c;aGk=\u{7}"),
            ("\u{9b}31m", r"\u{9b}31m"),
            ("abc\u{202e}fdp.exe", r"abc\u{202e}fdp.exe"),
            ("line\u{2028}break\r\n", r"line\u{2028}break\u{d}\u{a}"),
        ];
        for (input, expected) in cases {
            assert_eq!(sanitize(input), expected);
        }
    }

    #[test]
    fn ordinary_text_is_unchanged() {
        for text in [
            "dist/app-1.2.3.tar.gz",
            r"C:\Users\me\app.exe",
            "名前 ä 😀",
            "a b",
        ] {
            assert_eq!(sanitize(text), text);
        }
    }
}
