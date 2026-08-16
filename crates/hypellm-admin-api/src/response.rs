//! Management API responses: errors, ETags, and pagination.
//!
//! Specification 15.4 requires "explicit JSON schemas, ETags, If-Match on
//! mutation, pagination cursors, stable error codes, and request IDs". Each of
//! those is a type here rather than an ad-hoc string at a call site, so a
//! handler cannot forget one.

use hypellm_crypto::Digest;
use core::fmt;
use wire_json::{Object, Value, to_canonical_vec, to_string};

/// A stable management error code.
///
/// Distinct from the inference error contract (specification 8.2): a management
/// client is an operator's browser, not a coding harness, and the failures it
/// needs to distinguish are different.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiErrorCode {
    /// The request body or a parameter was malformed.
    InvalidRequest,
    /// No session or key was presented.
    Unauthenticated,
    /// The caller lacks the permission this action requires.
    Forbidden,
    /// The action needs a more recent authentication.
    ReauthenticationRequired,
    /// The resource does not exist.
    NotFound,
    /// The `If-Match` precondition did not hold.
    PreconditionFailed,
    /// `If-Match` was required and absent.
    PreconditionRequired,
    /// The resource already exists.
    Conflict,
    /// The CSRF token was absent or wrong.
    CsrfRequired,
    /// The request origin is not on the allowlist.
    OriginNotPermitted,
    /// The configuration failed validation.
    ValidationFailed,
    /// An internal fault.
    InternalFault,
}

impl ApiErrorCode {
    /// The wire code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unauthenticated => "unauthenticated",
            Self::Forbidden => "forbidden",
            Self::ReauthenticationRequired => "reauthentication_required",
            Self::NotFound => "not_found",
            Self::PreconditionFailed => "precondition_failed",
            Self::PreconditionRequired => "precondition_required",
            Self::Conflict => "conflict",
            Self::CsrfRequired => "csrf_required",
            Self::OriginNotPermitted => "origin_not_permitted",
            Self::ValidationFailed => "validation_failed",
            Self::InternalFault => "internal_fault",
        }
    }

    /// The HTTP status.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::InvalidRequest | Self::ValidationFailed => 400,
            Self::Unauthenticated => 401,
            Self::Forbidden
            | Self::ReauthenticationRequired
            | Self::CsrfRequired
            | Self::OriginNotPermitted => 403,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::PreconditionFailed => 412,
            Self::PreconditionRequired => 428,
            Self::InternalFault => 500,
        }
    }

    /// Every code, for exhaustiveness tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::InvalidRequest,
            Self::Unauthenticated,
            Self::Forbidden,
            Self::ReauthenticationRequired,
            Self::NotFound,
            Self::PreconditionFailed,
            Self::PreconditionRequired,
            Self::Conflict,
            Self::CsrfRequired,
            Self::OriginNotPermitted,
            Self::ValidationFailed,
            Self::InternalFault,
        ]
    }
}

impl fmt::Display for ApiErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A management API error.
#[derive(Debug, Clone)]
pub struct ApiError {
    /// The stable code.
    pub code: ApiErrorCode,
    /// A message safe to show an operator.
    pub message: String,
    /// Per-field validation problems, for a draft that did not validate.
    pub details: Vec<ApiErrorDetail>,
    /// Headers to emit alongside the error body.
    ///
    /// Needed for cross-origin correctness: a browser can only read a response
    /// body — including an error body — when the response carries the
    /// `Access-Control-*` grant. Without this a 401, 403, 412 or 428 reaches an
    /// allowlisted admin origin as an opaque network failure, and the operator
    /// sees "something went wrong" instead of "your session expired".
    ///
    /// Deliberately not populated by the constructors. The grant depends on the
    /// request's `Origin`, which an error raised deep in a handler has no
    /// access to; [`crate::AdminApi::handle`] attaches it on the way out.
    pub headers: Vec<(String, String)>,
}

/// One validation problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiErrorDetail {
    /// A stable code for the specific problem.
    pub code: String,
    /// Where the problem is.
    pub location: String,
    /// What is wrong.
    pub message: String,
}

impl ApiError {
    /// Construct.
    #[must_use]
    pub fn new(code: ApiErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: Vec::new(),
            headers: Vec::new(),
        }
    }

    /// Attach validation details.
    #[must_use]
    pub fn with_details(mut self, details: Vec<ApiErrorDetail>) -> Self {
        self.details = details;
        self
    }

    /// A 404.
    #[must_use]
    pub fn not_found(what: &str) -> Self {
        Self::new(ApiErrorCode::NotFound, format!("no such {what}"))
    }

    /// A 403 for a missing permission.
    #[must_use]
    pub fn forbidden() -> Self {
        Self::new(
            ApiErrorCode::Forbidden,
            "the session does not hold the permission this action requires",
        )
    }

    /// The HTTP status.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.code.status()
    }

    /// The JSON body.
    #[must_use]
    pub fn to_json(&self, request_id: &str) -> String {
        let mut inner = Object::new();
        inner.push("code", Value::from(self.code.as_str()));
        inner.push("message", Value::from(self.message.as_str()));
        if !self.details.is_empty() {
            let details: Vec<Value> = self
                .details
                .iter()
                .map(|d| {
                    let mut object = Object::new();
                    object.push("code", Value::from(d.code.as_str()));
                    object.push("location", Value::from(d.location.as_str()));
                    object.push("message", Value::from(d.message.as_str()));
                    Value::Object(object)
                })
                .collect();
            inner.push("details", Value::Array(details));
        }

        let mut root = Object::new();
        root.push("error", Value::Object(inner));
        root.push("request_id", Value::from(request_id));
        to_string(&Value::Object(root))
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

/// A successful management response.
#[derive(Debug, Clone)]
pub struct ApiResponse {
    /// The status.
    pub status: u16,
    /// The JSON body.
    pub body: String,
    /// The entity tag, when the resource has one.
    pub etag: Option<String>,
    /// Extra headers, such as `Set-Cookie` or `Location`.
    pub headers: Vec<(String, String)>,
}

impl ApiResponse {
    /// A 200 with a body.
    #[must_use]
    pub fn ok(value: &Value) -> Self {
        Self {
            status: 200,
            body: to_string(value),
            etag: None,
            headers: Vec::new(),
        }
    }

    /// A 200 whose body also carries an entity tag.
    #[must_use]
    pub fn ok_with_etag(value: &Value) -> Self {
        let etag = etag_for(value);
        Self {
            status: 200,
            body: to_string(value),
            etag: Some(etag),
            headers: Vec::new(),
        }
    }

    /// A 201.
    #[must_use]
    pub fn created(value: &Value) -> Self {
        Self {
            status: 201,
            body: to_string(value),
            etag: Some(etag_for(value)),
            headers: Vec::new(),
        }
    }

    /// A 204.
    #[must_use]
    pub fn no_content() -> Self {
        Self {
            status: 204,
            body: String::new(),
            etag: None,
            headers: Vec::new(),
        }
    }

    /// Add a header.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_owned(), value.into()));
        self
    }
}

/// Compute an entity tag for a resource.
///
/// The tag is a digest of the resource's **canonical** JSON, so it is stable
/// across key ordering and changes exactly when the resource does. A tag based
/// on a timestamp or a counter would either change spuriously — defeating the
/// optimistic concurrency it exists for — or fail to change when it should.
#[must_use]
pub fn etag_for(value: &Value) -> String {
    let digest = hypellm_crypto::digest(&to_canonical_vec(value));
    format!("\"{}\"", digest.to_hex())
}

/// Compare an `If-Match` header against a resource's current tag.
///
/// Specification 15.4 requires `If-Match` on mutation. The comparison is exact
/// and a `*` matches anything, per RFC 9110.
pub fn if_match_satisfied(if_match: Option<&str>, current: &str) -> Result<(), ApiError> {
    match if_match {
        None => Err(ApiError::new(
            ApiErrorCode::PreconditionRequired,
            "this mutation requires an If-Match header carrying the resource's current ETag",
        )),
        Some("*") => Ok(()),
        Some(presented) => {
            // A header may carry a list of tags.
            let matched = presented
                .split(',')
                .map(str::trim)
                .any(|candidate| candidate == current);
            if matched {
                Ok(())
            } else {
                Err(ApiError::new(
                    ApiErrorCode::PreconditionFailed,
                    "the resource changed since it was read; re-read it and retry",
                ))
            }
        }
    }
}

/// A page of results.
#[derive(Debug, Clone)]
pub struct Pagination {
    /// Maximum items to return.
    pub limit: usize,
    /// The opaque cursor to resume from.
    pub after: Option<String>,
}

impl Pagination {
    /// The default page size.
    pub const DEFAULT_LIMIT: usize = 50;
    /// The largest page a caller may request.
    pub const MAX_LIMIT: usize = 500;

    /// Parse from a query string.
    ///
    /// An out-of-range limit is clamped rather than rejected: a management UI
    /// asking for too much should get a bounded answer, not an error.
    #[must_use]
    pub fn from_query(query: Option<&str>) -> Self {
        let mut limit = Self::DEFAULT_LIMIT;
        let mut after = None;
        if let Some(query) = query {
            for pair in query.split('&') {
                match pair.split_once('=') {
                    Some(("limit", value)) => {
                        if let Ok(parsed) = value.parse::<usize>() {
                            limit = parsed.clamp(1, Self::MAX_LIMIT);
                        }
                    }
                    Some(("after", value)) if !value.is_empty() && value.len() <= 256 => {
                        after = Some(value.to_owned());
                    }
                    _ => {}
                }
            }
        }
        Self { limit, after }
    }

    /// Apply the page to a sorted list of identifiers.
    ///
    /// The cursor is the last identifier of the previous page, so paging is
    /// stable across insertions — an offset-based cursor would skip or repeat
    /// items when the underlying set changes between pages.
    pub fn apply<'a, T, F>(&self, items: &'a [T], key: F) -> (Vec<&'a T>, Option<String>)
    where
        F: Fn(&T) -> &str,
    {
        let start = match &self.after {
            None => 0,
            Some(cursor) => items
                .iter()
                .position(|item| key(item) == cursor.as_str())
                .map_or(items.len(), |position| position + 1),
        };
        // `skip`/`take` expresses the same window as `items[start..start +
        // limit]` without a slice index, and saturates naturally when the
        // cursor lands on the last item.
        let page: Vec<&T> = items.iter().skip(start).take(self.limit).collect();
        let end = start.saturating_add(page.len());
        let next = if end < items.len() {
            page.last().map(|item| key(item).to_owned())
        } else {
            None
        };
        (page, next)
    }
}

/// Wrap a list plus its cursor in the standard envelope.
#[must_use]
pub fn list_envelope(items: Vec<Value>, next_cursor: Option<String>) -> Value {
    let mut root = Object::new();
    root.push("object", Value::from("list"));
    root.push("data", Value::Array(items));
    root.push_opt("next_cursor", next_cursor.map(Value::from));
    root.push("has_more", Value::from(next_cursor_present(&root)));
    Value::Object(root)
}

fn next_cursor_present(root: &Object) -> bool {
    root.get("next_cursor").is_some_and(|v| !v.is_null())
}

/// A short digest for display.
#[must_use]
pub fn short_digest(digest: Digest) -> String {
    digest.short()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wire_json::{Limits, parse_str};

    fn value(text: &str) -> Value {
        parse_str(text, &Limits::SMALL).expect("valid JSON")
    }

    #[test]
    fn error_codes_and_statuses_are_distinct_and_sensible() {
        let mut codes: Vec<&str> = ApiErrorCode::all().iter().map(|c| c.as_str()).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), before);

        for code in ApiErrorCode::all() {
            let status = code.status();
            assert!(
                (400..=500).contains(&status),
                "{code} maps to unexpected status {status}"
            );
        }
        assert_eq!(ApiErrorCode::PreconditionFailed.status(), 412);
        assert_eq!(ApiErrorCode::PreconditionRequired.status(), 428);
        assert_eq!(ApiErrorCode::Conflict.status(), 409);
    }

    #[test]
    fn an_error_body_carries_the_code_and_request_id() {
        let error = ApiError::new(ApiErrorCode::NotFound, "no such target");
        let body = error.to_json("0123456789abcdef0123456789abcdef");
        let parsed = value(&body);
        assert_eq!(
            parsed.get("error").unwrap().field_str("code").unwrap(),
            "not_found"
        );
        assert_eq!(parsed.field_str("request_id").unwrap().len(), 32);
    }

    #[test]
    fn validation_details_are_included_when_present() {
        let error = ApiError::new(ApiErrorCode::ValidationFailed, "the draft did not validate")
            .with_details(vec![ApiErrorDetail {
                code: "unresolved_reference".to_owned(),
                location: "line 12".to_owned(),
                message: "target names a provider that is not defined".to_owned(),
            }]);
        let parsed = value(&error.to_json("r"));
        let details = parsed
            .get("error")
            .unwrap()
            .field_array("details")
            .unwrap();
        assert_eq!(details.len(), 1);
        assert_eq!(
            details[0].field_str("code").unwrap(),
            "unresolved_reference"
        );
    }

    #[test]
    fn an_etag_changes_only_when_the_resource_does() {
        let a = value(r#"{"id":"t1","enabled":true}"#);
        let b = value(r#"{"enabled":true,"id":"t1"}"#);
        assert_eq!(
            etag_for(&a),
            etag_for(&b),
            "key order must not change the tag"
        );

        let changed = value(r#"{"id":"t1","enabled":false}"#);
        assert_ne!(etag_for(&a), etag_for(&changed));

        // The format is a quoted strong tag.
        assert!(etag_for(&a).starts_with('"'));
        assert!(etag_for(&a).ends_with('"'));
    }

    #[test]
    fn a_mutation_without_if_match_is_refused() {
        // Specification 15.4: If-Match on mutation. Without it, two operators
        // editing the same target silently overwrite each other.
        let current = etag_for(&value(r#"{"id":"t1"}"#));
        let error = if_match_satisfied(None, &current).expect_err("must require If-Match");
        assert_eq!(error.code, ApiErrorCode::PreconditionRequired);
        assert_eq!(error.status(), 428);
    }

    #[test]
    fn a_stale_if_match_is_refused() {
        let current = etag_for(&value(r#"{"id":"t1","version":2}"#));
        let stale = etag_for(&value(r#"{"id":"t1","version":1}"#));
        let error = if_match_satisfied(Some(&stale), &current).expect_err("must fail");
        assert_eq!(error.code, ApiErrorCode::PreconditionFailed);
        assert_eq!(error.status(), 412);
    }

    #[test]
    fn a_current_if_match_is_accepted() {
        let current = etag_for(&value(r#"{"id":"t1"}"#));
        assert!(if_match_satisfied(Some(&current), &current).is_ok());
        assert!(if_match_satisfied(Some("*"), &current).is_ok());

        // A list of candidates matches if any does.
        let list = format!("\"other\", {current}");
        assert!(if_match_satisfied(Some(&list), &current).is_ok());
    }

    #[test]
    fn pagination_defaults_and_clamps() {
        let page = Pagination::from_query(None);
        assert_eq!(page.limit, Pagination::DEFAULT_LIMIT);
        assert_eq!(page.after, None);

        assert_eq!(Pagination::from_query(Some("limit=10")).limit, 10);
        assert_eq!(
            Pagination::from_query(Some("limit=99999")).limit,
            Pagination::MAX_LIMIT,
            "an oversized page is clamped, not refused"
        );
        assert_eq!(Pagination::from_query(Some("limit=0")).limit, 1);
        assert_eq!(
            Pagination::from_query(Some("limit=notanumber")).limit,
            Pagination::DEFAULT_LIMIT
        );
        assert_eq!(
            Pagination::from_query(Some("after=abc&limit=5")).after.as_deref(),
            Some("abc")
        );
        // An absurd cursor is ignored rather than stored.
        assert_eq!(
            Pagination::from_query(Some(&format!("after={}", "x".repeat(1000)))).after,
            None
        );
    }

    #[test]
    fn cursor_paging_is_stable_across_insertions() {
        // An offset cursor would skip or repeat when the set changes; a
        // key-based cursor does not.
        let first_pass = vec!["a".to_owned(), "b".to_owned(), "c".to_owned(), "d".to_owned()];
        let page = Pagination {
            limit: 2,
            after: None,
        };
        let (items, cursor) = page.apply(&first_pass, |s| s.as_str());
        assert_eq!(items, vec!["a", "b"]);
        assert_eq!(cursor.as_deref(), Some("b"));

        // A new item is inserted before the cursor between requests.
        let second_pass = vec![
            "a".to_owned(),
            "aa".to_owned(),
            "b".to_owned(),
            "c".to_owned(),
            "d".to_owned(),
        ];
        let next = Pagination {
            limit: 2,
            after: cursor,
        };
        let (items, cursor) = next.apply(&second_pass, |s| s.as_str());
        assert_eq!(items, vec!["c", "d"], "no item is skipped or repeated");
        assert_eq!(cursor, None, "the last page has no cursor");
    }

    #[test]
    fn an_unknown_cursor_yields_an_empty_page() {
        // A cursor pointing at a deleted item must not silently restart from
        // the beginning, which would repeat everything.
        let items = vec!["a".to_owned(), "b".to_owned()];
        let page = Pagination {
            limit: 10,
            after: Some("deleted".to_owned()),
        };
        let (result, cursor) = page.apply(&items, |s| s.as_str());
        assert!(result.is_empty());
        assert_eq!(cursor, None);
    }

    #[test]
    fn the_list_envelope_reports_more_pages() {
        let envelope = list_envelope(
            vec![Value::from("a"), Value::from("b")],
            Some("b".to_owned()),
        );
        assert_eq!(envelope.field_str("object").unwrap(), "list");
        assert_eq!(envelope.field_array("data").unwrap().len(), 2);
        assert_eq!(envelope.opt_field_bool("has_more").unwrap(), Some(true));
        assert_eq!(envelope.field_str("next_cursor").unwrap(), "b");

        let last = list_envelope(vec![Value::from("a")], None);
        assert_eq!(last.opt_field_bool("has_more").unwrap(), Some(false));
        assert!(last.get("next_cursor").is_none());
    }

    #[test]
    fn responses_carry_an_etag_when_the_resource_has_one() {
        let resource = value(r#"{"id":"t1"}"#);
        assert!(ApiResponse::ok_with_etag(&resource).etag.is_some());
        assert!(ApiResponse::created(&resource).etag.is_some());
        assert!(ApiResponse::ok(&resource).etag.is_none());
        assert_eq!(ApiResponse::no_content().status, 204);
    }
}
