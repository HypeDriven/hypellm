//! The JSON value tree and typed accessors.
//!
//! Objects preserve insertion order (a `Vec` of pairs, not a hash map) because
//! specification 6 forbids inferring administrative ordering from map iteration
//! order, and specification 11.1 requires the management API to emit canonical
//! ordering — both need a deterministic, inspectable sequence.
//!
//! Object lookup is linear. Entry counts are bounded by
//! [`crate::Limits::max_object_entries`], and real payloads have tens of keys,
//! so a map would cost more in allocation than it saves in comparisons.

use core::fmt;

/// A JSON number.
///
/// Integers are kept exact. Token counts, context sizes, and budget values are
/// integers and must not round-trip through `f64` — at 2^53 that silently
/// corrupts, and usage accounting is money.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Number {
    /// A signed integer that fit in `i64`.
    Int(i64),
    /// Anything with a fraction or exponent, or an integer too large for `i64`.
    Float(f64),
}

impl Number {
    /// Exact `i64` if this is an integer in range.
    #[must_use]
    pub fn as_i64(self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(i),
            Self::Float(_) => None,
        }
    }

    /// Exact `u64` if this is a non-negative integer in range.
    #[must_use]
    pub fn as_u64(self) -> Option<u64> {
        match self {
            Self::Int(i) => u64::try_from(i).ok(),
            Self::Float(_) => None,
        }
    }

    /// Value as `f64`. Lossy for integers above 2^53.
    #[must_use]
    // The standard library offers no `From<i64> for f64`, because the
    // conversion rounds — which is exactly what this accessor documents and
    // what its callers ask for. `as` here is total: every `i64` has a nearest
    // `f64`, so it cannot panic, wrap, or produce a non-finite value.
    #[allow(clippy::as_conversions)]
    pub fn as_f64(self) -> f64 {
        match self {
            Self::Int(i) => i as f64,
            Self::Float(f) => f,
        }
    }

    /// True when the number is an integer.
    #[must_use]
    pub fn is_int(self) -> bool {
        matches!(self, Self::Int(_))
    }
}

impl From<i64> for Number {
    fn from(v: i64) -> Self {
        Self::Int(v)
    }
}

impl From<u32> for Number {
    fn from(v: u32) -> Self {
        Self::Int(i64::from(v))
    }
}

impl From<f64> for Number {
    fn from(v: f64) -> Self {
        Self::Float(v)
    }
}

/// A JSON value.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Value {
    /// `null`
    #[default]
    Null,
    /// `true` / `false`
    Bool(bool),
    /// A number.
    Number(Number),
    /// A string. Always valid UTF-8; the parser rejects anything else.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object, in insertion order.
    Object(Object),
}

/// An ordered JSON object.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Object {
    entries: Vec<(String, Value)>,
}

impl Object {
    /// Empty object.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Empty object with capacity.
    #[must_use]
    pub fn with_capacity(n: usize) -> Self {
        Self {
            entries: Vec::with_capacity(n),
        }
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Append an entry without checking for duplicates.
    ///
    /// The parser checks duplicates against [`crate::Limits`]; builders
    /// constructing responses control their own keys.
    pub fn push(&mut self, key: impl Into<String>, value: Value) {
        self.entries.push((key.into(), value));
    }

    /// Append an entry only when `value` is `Some`.
    ///
    /// Specification 5.1 distinguishes "unset" from zero for sampling
    /// parameters; emitting `null` and omitting a key are different messages to
    /// a provider, so optional fields must be omitted rather than nulled.
    pub fn push_opt(&mut self, key: impl Into<String>, value: Option<Value>) {
        if let Some(v) = value {
            self.entries.push((key.into(), v));
        }
    }

    /// Look up a key, first occurrence.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    /// True when the key is present.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Iterate entries in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Consume into the underlying entry vector.
    #[must_use]
    pub fn into_entries(self) -> Vec<(String, Value)> {
        self.entries
    }

    /// Sort entries by key. Used for canonical serialization
    /// (specification 11.1) and for digest stability.
    pub fn sort_keys(&mut self) {
        self.entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (_, v) in &mut self.entries {
            v.sort_keys_recursive();
        }
    }
}

impl<'a> IntoIterator for &'a Object {
    type Item = (&'a str, &'a Value);
    type IntoIter = std::iter::Map<
        std::slice::Iter<'a, (String, Value)>,
        fn(&'a (String, Value)) -> (&'a str, &'a Value),
    >;

    fn into_iter(self) -> Self::IntoIter {
        fn project(pair: &(String, Value)) -> (&str, &Value) {
            (pair.0.as_str(), &pair.1)
        }
        self.entries.iter().map(project)
    }
}

impl FromIterator<(String, Value)> for Object {
    fn from_iter<T: IntoIterator<Item = (String, Value)>>(iter: T) -> Self {
        Self {
            entries: iter.into_iter().collect(),
        }
    }
}

/// Error produced by the typed accessors in [`Value`].
///
/// The message names the field and the expectation but never echoes the value:
/// specification 10 makes request bodies sensitive by default, so a type error
/// on a prompt field must not print the prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeError {
    /// Dotted path of the offending field, for example `messages.0.role`.
    pub path: String,
    /// What was expected, for example `string`.
    pub expected: &'static str,
    /// What was found, for example `number`, or `missing`.
    pub found: &'static str,
}

impl fmt::Display for TypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "field '{}': expected {}, found {}",
            self.path, self.expected, self.found
        )
    }
}

impl std::error::Error for TypeError {}

impl Value {
    /// Name of this value's type, for error messages.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "boolean",
            Self::Number(_) => "number",
            Self::String(_) => "string",
            Self::Array(_) => "array",
            Self::Object(_) => "object",
        }
    }

    /// String contents, if this is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Boolean contents, if this is a boolean.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Number, if this is a number.
    #[must_use]
    pub fn as_number(&self) -> Option<Number> {
        match self {
            Self::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Exact `i64`, if this is an integral number in range.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        self.as_number().and_then(Number::as_i64)
    }

    /// Exact `u64`, if this is a non-negative integral number in range.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        self.as_number().and_then(Number::as_u64)
    }

    /// `f64`, if this is any number.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        self.as_number().map(Number::as_f64)
    }

    /// Array contents, if this is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(a) => Some(a.as_slice()),
            _ => None,
        }
    }

    /// Object contents, if this is an object.
    #[must_use]
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Self::Object(o) => Some(o),
            _ => None,
        }
    }

    /// True when this value is `null`.
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Look up an object key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object().and_then(|o| o.get(key))
    }

    /// Look up an object key, treating an explicit `null` as absent.
    ///
    /// Clients routinely send `"seed": null` to mean "unset"; the router treats
    /// that identically to omitting the key rather than as a type error.
    #[must_use]
    pub fn get_present(&self, key: &str) -> Option<&Value> {
        match self.get(key) {
            Some(Value::Null) | None => None,
            Some(v) => Some(v),
        }
    }

    /// Index into an array.
    #[must_use]
    pub fn index(&self, i: usize) -> Option<&Value> {
        self.as_array().and_then(|a| a.get(i))
    }

    fn sort_keys_recursive(&mut self) {
        match self {
            Self::Object(o) => o.sort_keys(),
            Self::Array(a) => {
                for v in a {
                    v.sort_keys_recursive();
                }
            }
            _ => {}
        }
    }

    /// Recursively sort every object key. Used before canonical serialization.
    pub fn sort_keys(&mut self) {
        self.sort_keys_recursive();
    }

    // -- Strict accessors -------------------------------------------------
    //
    // Adapters and the management API use these so that a malformed payload
    // becomes a typed error at the field, not a panic or a silent default.

    /// Require a string field.
    pub fn field_str(&self, key: &str) -> Result<&str, TypeError> {
        match self.get(key) {
            Some(Value::String(s)) => Ok(s.as_str()),
            other => Err(TypeError {
                path: key.to_owned(),
                expected: "string",
                found: other.map_or("missing", Value::type_name),
            }),
        }
    }

    /// Optional string field; `null` and absent are both `None`.
    pub fn opt_field_str(&self, key: &str) -> Result<Option<&str>, TypeError> {
        match self.get_present(key) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.as_str())),
            Some(other) => Err(TypeError {
                path: key.to_owned(),
                expected: "string",
                found: other.type_name(),
            }),
        }
    }

    /// Require an integer field.
    pub fn field_i64(&self, key: &str) -> Result<i64, TypeError> {
        match self.get(key) {
            Some(Value::Number(n)) => n.as_i64().ok_or_else(|| TypeError {
                path: key.to_owned(),
                expected: "integer",
                found: "number",
            }),
            other => Err(TypeError {
                path: key.to_owned(),
                expected: "integer",
                found: other.map_or("missing", Value::type_name),
            }),
        }
    }

    /// Optional integer field.
    pub fn opt_field_i64(&self, key: &str) -> Result<Option<i64>, TypeError> {
        match self.get_present(key) {
            None => Ok(None),
            Some(Value::Number(n)) => n.as_i64().map(Some).ok_or_else(|| TypeError {
                path: key.to_owned(),
                expected: "integer",
                found: "number",
            }),
            Some(other) => Err(TypeError {
                path: key.to_owned(),
                expected: "integer",
                found: other.type_name(),
            }),
        }
    }

    /// Optional number field, accepting integers and floats.
    pub fn opt_field_f64(&self, key: &str) -> Result<Option<f64>, TypeError> {
        match self.get_present(key) {
            None => Ok(None),
            Some(Value::Number(n)) => Ok(Some(n.as_f64())),
            Some(other) => Err(TypeError {
                path: key.to_owned(),
                expected: "number",
                found: other.type_name(),
            }),
        }
    }

    /// Optional boolean field.
    pub fn opt_field_bool(&self, key: &str) -> Result<Option<bool>, TypeError> {
        match self.get_present(key) {
            None => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(*b)),
            Some(other) => Err(TypeError {
                path: key.to_owned(),
                expected: "boolean",
                found: other.type_name(),
            }),
        }
    }

    /// Require an array field.
    pub fn field_array(&self, key: &str) -> Result<&[Value], TypeError> {
        match self.get(key) {
            Some(Value::Array(a)) => Ok(a.as_slice()),
            other => Err(TypeError {
                path: key.to_owned(),
                expected: "array",
                found: other.map_or("missing", Value::type_name),
            }),
        }
    }

    /// Optional array field.
    pub fn opt_field_array(&self, key: &str) -> Result<Option<&[Value]>, TypeError> {
        match self.get_present(key) {
            None => Ok(None),
            Some(Value::Array(a)) => Ok(Some(a.as_slice())),
            Some(other) => Err(TypeError {
                path: key.to_owned(),
                expected: "array",
                found: other.type_name(),
            }),
        }
    }

    /// Optional object field.
    pub fn opt_field_object(&self, key: &str) -> Result<Option<&Object>, TypeError> {
        match self.get_present(key) {
            None => Ok(None),
            Some(Value::Object(o)) => Ok(Some(o)),
            Some(other) => Err(TypeError {
                path: key.to_owned(),
                expected: "object",
                found: other.type_name(),
            }),
        }
    }
}

// -- Ergonomic construction ------------------------------------------------

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Self::Number(Number::Int(v))
    }
}

impl From<u64> for Value {
    // Above `i64::MAX` the value can only be carried as a float, and the
    // standard library has no `From<u64> for f64` because that step rounds.
    // The `as` is reached only on the `try_from` error path, is total for every
    // `u64`, and always yields a finite float.
    #[allow(clippy::as_conversions)]
    fn from(v: u64) -> Self {
        i64::try_from(v).map_or_else(|_| Self::Number(Number::Float(v as f64)), Value::from)
    }
}

impl From<u32> for Value {
    fn from(v: u32) -> Self {
        Self::Number(Number::Int(i64::from(v)))
    }
}

impl From<usize> for Value {
    fn from(v: usize) -> Self {
        // `usize` is at most 64 bits on every supported target, so the
        // conversion succeeds; saturating keeps the trait total without a
        // panic should a wider target ever appear.
        Self::from(u64::try_from(v).unwrap_or(u64::MAX))
    }
}

impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Self::Number(Number::Float(v))
    }
}

impl From<String> for Value {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Self::String(v.to_owned())
    }
}

impl From<Object> for Value {
    fn from(v: Object) -> Self {
        Self::Object(v)
    }
}

impl From<Vec<Value>> for Value {
    fn from(v: Vec<Value>) -> Self {
        Self::Array(v)
    }
}

impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Self {
        v.map_or(Self::Null, Into::into)
    }
}

/// Build an object from key/value pairs.
#[must_use]
pub fn object(pairs: Vec<(&str, Value)>) -> Value {
    let mut o = Object::with_capacity(pairs.len());
    for (k, v) in pairs {
        o.push(k, v);
    }
    Value::Object(o)
}

/// Build an array.
#[must_use]
pub fn array(items: Vec<Value>) -> Value {
    Value::Array(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Value {
        object(vec![
            ("model", Value::from("code-premium")),
            ("stream", Value::from(true)),
            ("max_tokens", Value::from(1024i64)),
            ("temperature", Value::from(0.7f64)),
            ("seed", Value::Null),
            (
                "messages",
                array(vec![object(vec![
                    ("role", Value::from("user")),
                    ("content", Value::from("hi")),
                ])]),
            ),
        ])
    }

    #[test]
    fn typed_accessors() {
        let v = sample();
        assert_eq!(v.field_str("model").unwrap(), "code-premium");
        assert_eq!(v.opt_field_bool("stream").unwrap(), Some(true));
        assert_eq!(v.field_i64("max_tokens").unwrap(), 1024);
        assert_eq!(v.opt_field_f64("temperature").unwrap(), Some(0.7));
        assert_eq!(v.field_array("messages").unwrap().len(), 1);
    }

    #[test]
    fn null_reads_as_unset_not_as_type_error() {
        let v = sample();
        assert_eq!(v.opt_field_i64("seed").unwrap(), None);
        assert_eq!(v.opt_field_str("seed").unwrap(), None);
        assert_eq!(v.opt_field_i64("absent").unwrap(), None);
    }

    #[test]
    fn type_error_names_field_without_echoing_value() {
        let v = sample();
        let err = v.field_i64("model").unwrap_err();
        assert_eq!(err.path, "model");
        assert_eq!(err.expected, "integer");
        assert_eq!(err.found, "string");
        let msg = err.to_string();
        assert!(!msg.contains("code-premium"), "error must not echo the value");
    }

    #[test]
    fn missing_field_is_reported_as_missing() {
        let v = sample();
        let err = v.field_str("nope").unwrap_err();
        assert_eq!(err.found, "missing");
    }

    #[test]
    fn integers_stay_exact() {
        let big = 9_007_199_254_740_993i64; // 2^53 + 1, not representable in f64
        let v = Value::from(big);
        assert_eq!(v.as_i64(), Some(big));
    }

    #[test]
    fn float_is_not_an_integer() {
        let v = Value::from(1.5f64);
        assert_eq!(v.as_i64(), None);
        assert_eq!(v.as_f64(), Some(1.5));
    }

    #[test]
    fn object_preserves_insertion_order() {
        let mut o = Object::new();
        o.push("z", Value::from(1i64));
        o.push("a", Value::from(2i64));
        o.push("m", Value::from(3i64));
        let keys: Vec<&str> = o.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["z", "a", "m"]);
    }

    #[test]
    fn sort_keys_is_recursive() {
        let mut v = object(vec![
            ("z", Value::from(1i64)),
            ("a", object(vec![("y", Value::Null), ("b", Value::Null)])),
        ]);
        v.sort_keys();
        let o = v.as_object().unwrap();
        let keys: Vec<&str> = o.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["a", "z"]);
        let inner = o.get("a").unwrap().as_object().unwrap();
        let inner_keys: Vec<&str> = inner.iter().map(|(k, _)| k).collect();
        assert_eq!(inner_keys, vec!["b", "y"]);
    }

    #[test]
    fn push_opt_omits_none() {
        let mut o = Object::new();
        o.push_opt("a", Some(Value::from(1i64)));
        o.push_opt("b", None);
        assert_eq!(o.len(), 1);
        assert!(!o.contains_key("b"));
    }

    #[test]
    fn u64_above_i64_range_falls_back_to_float() {
        let v = Value::from(u64::MAX);
        assert!(v.as_i64().is_none());
        assert!(v.as_f64().unwrap() > 1.8e19);
    }
}
