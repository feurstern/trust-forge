//! Deterministic JSON output.
//!
//! [`to_canonical`] writes the JSON Canonicalization Scheme (RFC 8785, JCS)
//! for the values [`StrictValue`] can hold:
//! - object members sorted by their keys' UTF-16 code units;
//! - no insignificant whitespace;
//! - strings escaped exactly as ECMAScript's `JSON.stringify` does: `"` and
//!   `\` with a backslash, U+0008, U+0009, U+000A, U+000C and U+000D as
//!   `\b \t \n \f \r`, other characters below U+0020 as `\u00xx`, and
//!   everything else as itself;
//! - integers in plain decimal.
//!
//! [`to_pretty`] writes the same tokens with two-space indentation, a space
//! after each colon, and a final newline, which is also what
//! `JSON.stringify(value, null, 2)` produces for sorted input. Both forms are
//! a pure function of the value, and they never depend on a JSON library's
//! map order.

use super::StrictValue;

/// The RFC 8785 (JCS) canonical form of `value`.
pub fn to_canonical(value: &StrictValue) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(&mut out, value, None);
    out
}

/// The deterministic human-readable form of `value`: canonical member order
/// and escaping, two-space indentation, LF line endings and a final newline.
pub fn to_pretty(value: &StrictValue) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(&mut out, value, Some(0));
    out.push(b'\n');
    out
}

/// Writes `value`; `indent` is `None` for the canonical form, otherwise the
/// current indentation level.
fn write_value(out: &mut Vec<u8>, value: &StrictValue, indent: Option<usize>) {
    match value {
        StrictValue::Null => out.extend_from_slice(b"null"),
        StrictValue::Bool(true) => out.extend_from_slice(b"true"),
        StrictValue::Bool(false) => out.extend_from_slice(b"false"),
        StrictValue::Integer(n) => out.extend_from_slice(n.to_string().as_bytes()),
        StrictValue::String(s) => write_string(out, s),
        StrictValue::Array(items) => {
            write_container(out, b'[', b']', items.iter(), indent, |out, item, inner| {
                write_value(out, item, inner);
            });
        }
        StrictValue::Object(members) => {
            let mut sorted: Vec<_> = members.iter().collect();
            sorted.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            write_container(
                out,
                b'{',
                b'}',
                sorted.into_iter(),
                indent,
                |out, (key, value), inner| {
                    write_string(out, key);
                    out.push(b':');
                    if inner.is_some() {
                        out.push(b' ');
                    }
                    write_value(out, value, inner);
                },
            );
        }
    }
}

fn write_container<T>(
    out: &mut Vec<u8>,
    open: u8,
    close: u8,
    mut items: impl ExactSizeIterator<Item = T>,
    indent: Option<usize>,
    mut write_item: impl FnMut(&mut Vec<u8>, T, Option<usize>),
) {
    out.push(open);
    if items.len() == 0 {
        out.push(close);
        return;
    }
    let inner = indent.map(|level| level + 1);
    let mut first = true;
    for item in &mut items {
        if !first {
            out.push(b',');
        }
        first = false;
        newline(out, inner);
        write_item(out, item, inner);
    }
    newline(out, indent);
    out.push(close);
}

fn newline(out: &mut Vec<u8>, indent: Option<usize>) {
    if let Some(level) = indent {
        out.push(b'\n');
        out.extend(std::iter::repeat_n(b' ', level * 2));
    }
}

fn write_string(out: &mut Vec<u8>, s: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    let mut buf = [0; 4];
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            c if c < ' ' => {
                let byte = c as u8;
                out.extend_from_slice(b"\\u00");
                out.push(HEX[usize::from(byte >> 4)]);
                out.push(HEX[usize::from(byte & 0xf)]);
            }
            c => out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes()),
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::{JsonLimits, parse};
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    fn object(members: &[(&str, StrictValue)]) -> StrictValue {
        StrictValue::Object(
            members
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        )
    }

    fn string(s: &str) -> StrictValue {
        StrictValue::String(s.to_owned())
    }

    #[test]
    fn canonical_form_has_no_whitespace_and_sorted_keys() {
        let value = object(&[
            (
                "b",
                StrictValue::Array(vec![StrictValue::Integer(1), StrictValue::Null]),
            ),
            (
                "a",
                object(&[
                    ("y", StrictValue::Bool(false)),
                    ("x", StrictValue::Bool(true)),
                ]),
            ),
            ("c", StrictValue::Array(vec![])),
            ("d", object(&[])),
        ]);
        assert_eq!(
            to_canonical(&value),
            br#"{"a":{"x":true,"y":false},"b":[1,null],"c":[],"d":{}}"#
        );
    }

    /// The key-sorting example of RFC 8785, section 3.2.3: keys are ordered
    /// by UTF-16 code units, which puts U+1F600 (a surrogate pair) before
    /// U+FB33, unlike ordering by code point or UTF-8 bytes.
    #[test]
    fn keys_sort_by_utf16_code_units_as_in_rfc_8785() {
        let keys = [
            "\u{20ac}",
            "\r",
            "\u{fb33}",
            "1",
            "\u{1f600}",
            "\u{80}",
            "\u{f6}",
        ];
        let value =
            StrictValue::Object(keys.iter().map(|k| ((*k).to_owned(), string(k))).collect());
        let expected_order = [
            "\r",
            "1",
            "\u{80}",
            "\u{f6}",
            "\u{20ac}",
            "\u{1f600}",
            "\u{fb33}",
        ];
        let mut expected = String::from("{");
        for (i, key) in expected_order.iter().enumerate() {
            if i > 0 {
                expected.push(',');
            }
            let escaped = if *key == "\r" {
                "\\r".to_owned()
            } else {
                (*key).to_owned()
            };
            expected.push_str(&format!("\"{escaped}\":\"{escaped}\""));
        }
        expected.push('}');
        assert_eq!(String::from_utf8(to_canonical(&value)).unwrap(), expected);
    }

    #[test]
    fn strings_are_escaped_like_json_stringify() {
        let value = string("\"\\\u{8}\t\n\u{c}\r\u{0}\u{1f}\u{7f}é€😀/");
        assert_eq!(
            String::from_utf8(to_canonical(&value)).unwrap(),
            "\"\\\"\\\\\\b\\t\\n\\f\\r\\u0000\\u001f\u{7f}é€😀/\""
        );
    }

    #[test]
    fn integers_are_plain_decimal() {
        for (n, text) in [
            (0, "0"),
            (7, "7"),
            (1_730_678_400, "1730678400"),
            (crate::json::MAX_SAFE_INTEGER, "9007199254740991"),
        ] {
            assert_eq!(to_canonical(&StrictValue::Integer(n)), text.as_bytes());
        }
    }

    #[test]
    fn pretty_form_indents_by_two_and_ends_with_a_newline() {
        let value = object(&[
            (
                "z",
                StrictValue::Array(vec![StrictValue::Integer(1), object(&[])]),
            ),
            ("a", string("x")),
            ("e", StrictValue::Array(vec![])),
        ]);
        assert_eq!(
            String::from_utf8(to_pretty(&value)).unwrap(),
            "{\n  \"a\": \"x\",\n  \"e\": [],\n  \"z\": [\n    1,\n    {}\n  ]\n}\n"
        );
        assert_eq!(to_pretty(&StrictValue::Null), b"null\n");
    }

    fn value_strategy() -> impl Strategy<Value = StrictValue> {
        let leaf = prop_oneof![
            Just(StrictValue::Null),
            any::<bool>().prop_map(StrictValue::Bool),
            (0..=crate::json::MAX_SAFE_INTEGER).prop_map(StrictValue::Integer),
            "[a-zA-Z0-9 äé€😀\"\\\\/]{0,12}".prop_map(StrictValue::String),
        ];
        leaf.prop_recursive(4, 48, 6, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..6).prop_map(StrictValue::Array),
                proptest::collection::btree_map("[a-zA-Z0-9_äé€😀]{0,8}", inner, 0..6)
                    .prop_map(|m: BTreeMap<String, StrictValue>| StrictValue::Object(m)),
            ]
        })
    }

    proptest! {
        /// Both forms parse back, strictly, to the same value, and writing
        /// is a fixed point.
        #[test]
        fn writing_round_trips(value in value_strategy()) {
            let canonical = to_canonical(&value);
            let pretty = to_pretty(&value);
            prop_assert_eq!(parse(&canonical, &JsonLimits::default()).unwrap(), value.clone());
            prop_assert_eq!(parse(&pretty, &JsonLimits::default()).unwrap(), value.clone());
            prop_assert_eq!(&to_canonical(&parse(&canonical, &JsonLimits::default()).unwrap()), &canonical);
            // The canonical form is the pretty form without its whitespace,
            // which only ever appears outside strings in the pretty form.
            prop_assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&pretty).unwrap(),
                serde_json::from_slice::<serde_json::Value>(&canonical).unwrap()
            );
        }
    }
}
