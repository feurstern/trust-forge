//! Strict JSON: the parsing layer under every document TrustForge reads, and
//! the deterministic writers for every document it produces.
//!
//! General-purpose JSON libraries accept inputs that different parsers read
//! differently: duplicate object keys (one parser keeps the first value,
//! another the last), unpaired surrogates, numbers beyond what a double can
//! hold. A signed document that two tools read differently can mean two
//! different things. [`parse`] therefore accepts only strict I-JSON
//! (RFC 7493) and rejects everything ambiguous, before any field is
//! interpreted (`docs/architecture.md`, decision 6):
//!
//! - UTF-8 only: no byte-order mark, no invalid sequences, no unpaired
//!   surrogate escapes;
//! - no data after the top-level value;
//! - no duplicate object keys at any depth, compared after unescaping;
//! - no control characters, bidi controls, line separators or
//!   noncharacters in any string or key ([`is_unsafe_to_display`]);
//! - numbers only as integers from 0 to 2^53 − 1;
//! - nesting at most [`JsonLimits::max_depth`] levels, and the whole
//!   document at most [`JsonLimits::max_bytes`], checked before parsing.
//!
//! Tokenizing is done by `serde_json`; every value is built by this module's
//! own visitor, which enforces the rules above. The result is a
//! [`StrictValue`] tree, which typed readers then convert by hand.

mod write;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::name::{EscapedBytes, is_unsafe_to_display};

pub use write::{to_canonical, to_pretty};

/// The largest integer every JSON implementation represents exactly
/// (2^53 − 1).
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// A JSON value that passed strict parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StrictValue {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer from 0 to [`MAX_SAFE_INTEGER`].
    Integer(u64),
    /// A string with no character that is unsafe to display.
    String(String),
    /// An array.
    Array(Vec<StrictValue>),
    /// An object with unique keys.
    Object(BTreeMap<String, StrictValue>),
}

/// Limits applied while parsing.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonLimits {
    /// Size of the whole document in bytes, checked before parsing.
    /// Default: 4 MiB.
    pub max_bytes: usize,
    /// Nesting depth of arrays and objects. Default: 64.
    pub max_depth: usize,
}

impl Default for JsonLimits {
    fn default() -> Self {
        Self {
            max_bytes: 4 << 20,
            max_depth: 64,
        }
    }
}

/// One step of a [`Pointer`].
#[derive(Clone, Debug, PartialEq, Eq)]
enum Segment {
    Key(String),
    Index(usize),
}

/// The location of a value in a document, as a JSON Pointer (RFC 6901).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Pointer(Vec<Segment>);

impl Pointer {
    /// The whole document.
    pub fn root() -> Self {
        Self::default()
    }

    /// The member `key` of the object at this pointer.
    pub fn key(&self, key: &str) -> Self {
        let mut segments = self.0.clone();
        segments.push(Segment::Key(key.to_owned()));
        Self(segments)
    }

    /// The element `index` of the array at this pointer.
    pub fn index(&self, index: usize) -> Self {
        let mut segments = self.0.clone();
        segments.push(Segment::Index(index));
        Self(segments)
    }

    /// The RFC 6901 form: `""` for the whole document, otherwise `/` before
    /// each step, with `~` written as `~0` and `/` as `~1`.
    pub fn to_rfc6901(&self) -> String {
        let mut out = String::new();
        for segment in &self.0 {
            out.push('/');
            match segment {
                Segment::Key(key) => out.push_str(&key.replace('~', "~0").replace('/', "~1")),
                Segment::Index(index) => out.push_str(&index.to_string()),
            }
        }
        out
    }
}

/// Shows the RFC 6901 form with unsafe characters escaped, and `/` for the
/// whole document.
impl fmt::Display for Pointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("/");
        }
        write!(f, "{}", EscapedBytes(self.to_rfc6901().as_bytes()))
    }
}

impl fmt::Debug for Pointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{self}\"")
    }
}

/// A rule of strict parsing that a document broke.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Violation {
    /// An object has two members with the same key (after unescaping).
    #[error("duplicate key \"{shown}\"", shown = EscapedBytes(.0.as_bytes()))]
    DuplicateKey(String),
    /// A string or key contains a character that is unsafe to display.
    #[error("contains the forbidden character U+{code:04X}")]
    ForbiddenCharacter {
        /// The character's code point.
        code: u32,
    },
    /// A negative number, including `-0`.
    #[error("numbers must not be negative")]
    NegativeNumber,
    /// A number with a fraction or exponent, or too large for an integer.
    #[error("numbers must be integers from 0 to 2^53 - 1")]
    NotAnInteger,
    /// An integer above [`MAX_SAFE_INTEGER`].
    #[error("integers must not exceed 2^53 - 1")]
    IntegerTooLarge,
    /// Arrays and objects nested too deeply.
    #[error("nesting deeper than {max} levels")]
    TooDeep {
        /// The limit.
        max: usize,
    },
}

/// Why a document is not strict JSON.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum JsonError {
    /// The document is larger than [`JsonLimits::max_bytes`].
    #[error("the document is larger than the limit of {max} bytes")]
    TooLarge {
        /// How many bytes were passed in. A caller that reads at most one
        /// byte past the limit passes `max + 1`, not the document's size.
        size: usize,
        /// The limit.
        max: usize,
    },
    /// The document starts with a UTF-8 byte-order mark.
    #[error("the document starts with a byte-order mark")]
    ByteOrderMark,
    /// The document is not well-formed JSON.
    #[error("line {line}, column {column}: {message}")]
    Syntax {
        /// 1-based line.
        line: usize,
        /// 1-based column.
        column: usize,
        /// What the tokenizer reported.
        message: String,
    },
    /// The document is well-formed but breaks a strict rule.
    #[error("{pointer}: {violation}")]
    Strict {
        /// Where.
        pointer: Pointer,
        /// Which rule.
        violation: Violation,
    },
}

/// Parses `bytes` as strict JSON.
pub fn parse(bytes: &[u8], limits: &JsonLimits) -> Result<StrictValue, JsonError> {
    if bytes.len() > limits.max_bytes {
        return Err(JsonError::TooLarge {
            size: bytes.len(),
            max: limits.max_bytes,
        });
    }
    if bytes.starts_with(b"\xef\xbb\xbf") {
        return Err(JsonError::ByteOrderMark);
    }
    let ctx = Context {
        max_depth: limits.max_depth,
        path: RefCell::new(Vec::new()),
        violation: RefCell::new(None),
    };
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let result = Seed {
        ctx: &ctx,
        depth: 0,
    }
    .deserialize(&mut de)
    .and_then(|value| de.end().map(|()| value));
    match (result, ctx.violation.into_inner()) {
        // A strict violation is reported as such, not as the generic error
        // the visitor raised to stop the tokenizer.
        (_, Some((pointer, violation))) => Err(JsonError::Strict { pointer, violation }),
        (Ok(value), None) => Ok(value),
        (Err(e), None) => Err(JsonError::Syntax {
            line: e.line(),
            column: e.column(),
            message: syntax_message(&e),
        }),
    }
}

/// The tokenizer's message without its " at line L column C" suffix, which
/// [`JsonError::Syntax`] carries separately.
fn syntax_message(error: &serde_json::Error) -> String {
    let text = error.to_string();
    match text.rfind(" at line ") {
        Some(at) => text[..at].to_owned(),
        None => text,
    }
}

/// State shared by every visitor of one parse.
struct Context {
    max_depth: usize,
    /// The path to the value being visited.
    path: RefCell<Vec<Segment>>,
    /// The first violation found.
    violation: RefCell<Option<(Pointer, Violation)>>,
}

impl Context {
    /// Records a violation at the current path and returns the error that
    /// stops the tokenizer.
    fn fail<E: de::Error>(&self, violation: Violation) -> E {
        let mut slot = self.violation.borrow_mut();
        if slot.is_none() {
            *slot = Some((Pointer(self.path.borrow().clone()), violation));
        }
        E::custom("strict JSON violation")
    }

    fn check_text<E: de::Error>(&self, text: &str) -> Result<(), E> {
        match text.chars().find(|&c| is_unsafe_to_display(c)) {
            Some(c) => Err(self.fail(Violation::ForbiddenCharacter { code: u32::from(c) })),
            None => Ok(()),
        }
    }
}

/// Builds one value at nesting depth `depth` (0 for the top level).
struct Seed<'c> {
    ctx: &'c Context,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = StrictValue;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<StrictValue, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = StrictValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<StrictValue, E> {
        Ok(StrictValue::Null)
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<StrictValue, E> {
        Ok(StrictValue::Bool(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<StrictValue, E> {
        if v > MAX_SAFE_INTEGER {
            return Err(self.ctx.fail(Violation::IntegerTooLarge));
        }
        Ok(StrictValue::Integer(v))
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<StrictValue, E> {
        // The tokenizer reports every number with a minus sign this way.
        Err(self.ctx.fail(Violation::NegativeNumber))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<StrictValue, E> {
        // Fractions, exponents, and integers beyond 64 bits.
        Err(self.ctx.fail(Violation::NotAnInteger))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<StrictValue, E> {
        self.ctx.check_text(v)?;
        Ok(StrictValue::String(v.to_owned()))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<StrictValue, A::Error> {
        let depth = self.enter()?;
        let mut items = Vec::new();
        loop {
            self.ctx.path.borrow_mut().push(Segment::Index(items.len()));
            let item = seq.next_element_seed(Seed {
                ctx: self.ctx,
                depth,
            })?;
            self.ctx.path.borrow_mut().pop();
            match item {
                Some(item) => items.push(item),
                None => return Ok(StrictValue::Array(items)),
            }
        }
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<StrictValue, A::Error> {
        let depth = self.enter()?;
        let mut object = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            self.ctx.path.borrow_mut().push(Segment::Key(key.clone()));
            self.ctx.check_text(&key)?;
            if object.contains_key(&key) {
                return Err(self.ctx.fail(Violation::DuplicateKey(key)));
            }
            let value = map.next_value_seed(Seed {
                ctx: self.ctx,
                depth,
            })?;
            self.ctx.path.borrow_mut().pop();
            object.insert(key, value);
        }
        Ok(StrictValue::Object(object))
    }
}

impl Seed<'_> {
    /// The depth of the members of a container opened here.
    fn enter<E: de::Error>(&self) -> Result<usize, E> {
        let depth = self.depth + 1;
        if depth > self.ctx.max_depth {
            return Err(self.ctx.fail(Violation::TooDeep {
                max: self.ctx.max_depth,
            }));
        }
        Ok(depth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn strict(text: &str) -> Result<StrictValue, JsonError> {
        parse(text.as_bytes(), &JsonLimits::default())
    }

    fn violation(text: &str) -> (String, Violation) {
        match strict(text) {
            Err(JsonError::Strict { pointer, violation }) => (pointer.to_rfc6901(), violation),
            other => panic!("expected a strict violation for {text:?}, got {other:?}"),
        }
    }

    #[test]
    fn well_formed_documents_parse() {
        let value = strict(r#"{"a": [1, true, null, "x"], "b": {"c": 9007199254740991}}"#).unwrap();
        let StrictValue::Object(object) = value else {
            panic!("not an object")
        };
        assert_eq!(
            object["a"],
            StrictValue::Array(vec![
                StrictValue::Integer(1),
                StrictValue::Bool(true),
                StrictValue::Null,
                StrictValue::String("x".into()),
            ])
        );
        assert!(strict("[]").is_ok());
        assert!(strict("\"just a string\"").is_ok());
        assert!(
            strict(" {} \n\t").is_ok(),
            "surrounding whitespace is allowed"
        );
    }

    #[test]
    fn duplicate_keys_are_rejected_after_unescaping() {
        assert_eq!(
            violation(r#"{"a": 1, "a": 2}"#),
            ("/a".into(), Violation::DuplicateKey("a".into()))
        );
        assert_eq!(
            violation(r#"{"sha256": "x", "sha\u0032\u0035\u0036": "y"}"#),
            ("/sha256".into(), Violation::DuplicateKey("sha256".into()))
        );
        assert_eq!(
            violation(r#"{"outer": [{"k": 1}, {"k": 1, "k": 1}]}"#),
            ("/outer/1/k".into(), Violation::DuplicateKey("k".into()))
        );
    }

    #[test]
    fn unsafe_characters_are_rejected_in_values_and_keys() {
        for escaped in [
            "\\u0000", "\\u001b", "\\n", "\\u007f", "\\u0085", "\\u202e", "\\u2028", "\\u2066",
        ] {
            let (pointer, v) = violation(&format!(r#"{{"name": "x{escaped}y"}}"#));
            assert_eq!(pointer, "/name", "{escaped}");
            assert!(
                matches!(v, Violation::ForbiddenCharacter { .. }),
                "{escaped}"
            );
            let (pointer, _) = violation(&format!(r#"{{"x{escaped}": 1}}"#));
            assert!(pointer.starts_with("/x"), "{escaped}");
        }
        // Raw (unescaped) bidi controls are rejected too.
        assert!(matches!(
            violation("{\"name\": \"a\u{202e}b\"}").1,
            Violation::ForbiddenCharacter { code: 0x202e }
        ));
    }

    #[test]
    fn only_safe_integers_are_numbers() {
        assert_eq!(violation(r#"{"n": -1}"#).1, Violation::NegativeNumber);
        // The tokenizer reads -0 as a floating-point number.
        assert_eq!(violation(r#"{"n": -0}"#).1, Violation::NotAnInteger);
        for text in ["1.0", "1e3", "0.5", "1E-2", "18446744073709551616"] {
            assert_eq!(
                violation(&format!(r#"{{"n": {text}}}"#)).1,
                Violation::NotAnInteger,
                "{text}"
            );
        }
        assert_eq!(
            violation(r#"{"n": 9007199254740992}"#).1,
            Violation::IntegerTooLarge
        );
        assert_eq!(
            strict(r#"{"n": 9007199254740991}"#).unwrap(),
            StrictValue::Object(BTreeMap::from([(
                "n".into(),
                StrictValue::Integer(MAX_SAFE_INTEGER)
            )]))
        );
    }

    #[test]
    fn nesting_is_limited() {
        let limits = JsonLimits {
            max_depth: 3,
            ..JsonLimits::default()
        };
        assert!(parse(b"[[[1]]]", &limits).is_ok());
        assert_eq!(
            parse(b"[[[[1]]]]", &limits),
            Err(JsonError::Strict {
                pointer: Pointer::root().index(0).index(0).index(0),
                violation: Violation::TooDeep { max: 3 },
            })
        );
        // Far beyond the tokenizer's own recursion limit: still a clean error.
        let deep = "[".repeat(100_000);
        assert!(matches!(
            strict(&deep),
            Err(JsonError::Strict {
                violation: Violation::TooDeep { .. },
                ..
            })
        ));
    }

    #[test]
    fn malformed_input_is_a_syntax_error() {
        for text in [
            "",
            "{",
            "{\"a\": 1,}",
            "[1,]",
            "{'a': 1}",
            "{\"a\": 01}",
            "{\"a\": NaN}",
            "{\"a\": \"\\ud800\"}",
            "{\"a\": \"\\udc00\\ud800\"}",
            "{\"a\": \"\t\"}",
            "{} {}",
            "{}x",
            "// comment\n{}",
        ] {
            assert!(
                matches!(strict(text), Err(JsonError::Syntax { .. })),
                "{text:?}: {:?}",
                strict(text)
            );
        }
        assert!(matches!(
            parse(b"{\"a\": \"\xff\"}", &JsonLimits::default()),
            Err(JsonError::Syntax { .. })
        ));
        assert_eq!(
            parse(b"\xef\xbb\xbf{}", &JsonLimits::default()),
            Err(JsonError::ByteOrderMark)
        );
    }

    #[test]
    fn size_is_checked_before_parsing() {
        let limits = JsonLimits {
            max_bytes: 4,
            ..JsonLimits::default()
        };
        assert_eq!(
            parse(b"[1,2]", &limits),
            Err(JsonError::TooLarge { size: 5, max: 4 })
        );
        assert!(parse(b"[12]", &limits).is_ok());
    }

    #[test]
    fn syntax_errors_carry_a_location_and_no_duplicate_suffix() {
        let Err(JsonError::Syntax {
            line,
            column,
            message,
        }) = strict("{\n  \"a\": x\n}")
        else {
            panic!("expected a syntax error")
        };
        assert_eq!((line, column), (2, 8));
        assert!(!message.contains(" at line "), "{message}");
    }

    #[test]
    fn pointers_follow_rfc_6901() {
        let pointer = Pointer::root().key("a/b").key("c~d").index(3);
        assert_eq!(pointer.to_rfc6901(), "/a~1b/c~0d/3");
        assert_eq!(Pointer::root().to_rfc6901(), "");
        assert_eq!(Pointer::root().to_string(), "/");
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse(&bytes, &JsonLimits::default());
        }

        #[test]
        fn json_like_text_never_panics(text in r#"[\[\]{}",:0-9a-z\\ .eE+-]{0,200}"#) {
            let _ = parse(text.as_bytes(), &JsonLimits::default());
        }
    }
}
