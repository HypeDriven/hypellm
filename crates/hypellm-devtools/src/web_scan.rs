//! Policy rules over the static admin application.
//!
//! Specification 15: "only first-party static HTML, CSS, JavaScript, SVG, and
//! optional WOFF2 assets… no build-time or runtime package dependencies, CDN
//! assets, remote fonts, telemetry SDKs, service-worker code execution, eval,
//! or WebAssembly."
//!
//! Specification 15.1 adds: "Semantic shell, CSP-compatible external
//! first-party files, no inline event handlers", and the DOM rule that markup
//! is built as nodes rather than assembled from strings.
//!
//! The last rule here — [`check_module_resolution`] — is the one with teeth in
//! practice: it verifies that every module, stylesheet, and image the
//! application references actually exists in the tree. A dangling `<script
//! type="module" src="/app.js">` produces a blank page with a console error and
//! no server-side signal at all.

use crate::findings::{Finding, Report, relative};
use crate::walk;
use std::path::{Component, Path, PathBuf};

/// Script constructs that execute strings as code, or assign markup as text.
///
/// `innerHTML` and friends are included because specification 15.1 requires
/// DOM nodes to be constructed, not injected: an escaping mistake in a string
/// template is the standard route to admin-console cross-site scripting.
const FORBIDDEN_JS: &[(&str, &str)] = &[
    ("eval(", "executes a string as code"),
    ("new Function(", "executes a string as code"),
    ("innerHTML", "assigns markup from a string (build DOM nodes instead)"),
    ("outerHTML", "assigns markup from a string (build DOM nodes instead)"),
    ("insertAdjacentHTML", "assigns markup from a string (build DOM nodes instead)"),
    ("document.write", "assigns markup from a string (build DOM nodes instead)"),
    ("serviceWorker", "service-worker code execution is forbidden"),
    ("WebAssembly", "WebAssembly is forbidden"),
    ("importScripts", "loads code outside the module graph"),
];

/// URL schemes that would reach a third party.
const REMOTE_SCHEMES: &[&str] = &["http://", "https://", "ftp://", "ws://", "wss://"];

/// XML namespace URIs, which are identifiers rather than fetches.
///
/// `xmlns='http://www.w3.org/2000/svg'` names the SVG namespace; nothing is
/// retrieved. Excluding these keeps the remote-origin rule honest instead of
/// forcing an exemption comment onto every inline SVG.
const NAMESPACE_URIS: &[&str] =
    &["http://www.w3.org/2000/svg", "http://www.w3.org/1999/xhtml", "http://www.w3.org/1999/xlink"];

/// Replace every comment with spaces, preserving line structure so reported
/// line numbers stay correct.
///
/// Comments must be removed before matching, and the modules here name the
/// forbidden constructs in their own header comments precisely because they
/// avoid them — `dom.js` explains at length that it never touches `innerHTML`.
/// A gate that flags the explanation is a gate people learn to ignore.
///
/// String literals are tracked, because `//` inside `"https://example"` is not
/// a comment and treating it as one would hide a remote origin — the failure
/// direction that matters.
fn strip_js_comments(text: &str) -> String {
    enum State {
        Code,
        Line,
        Block,
        Str(char),
    }

    let mut state = State::Code;
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        match state {
            State::Code => match ch {
                '/' if chars.peek() == Some(&'/') => {
                    state = State::Line;
                    out.push(' ');
                }
                '/' if chars.peek() == Some(&'*') => {
                    state = State::Block;
                    out.push(' ');
                }
                '"' | '\'' | '`' => {
                    state = State::Str(ch);
                    out.push(ch);
                }
                _ => out.push(ch),
            },
            State::Line => {
                if ch == '\n' {
                    state = State::Code;
                    out.push('\n');
                } else {
                    out.push(' ');
                }
            }
            State::Block => {
                if ch == '*' && chars.peek() == Some(&'/') {
                    let _ = chars.next();
                    state = State::Code;
                    out.push(' ');
                    out.push(' ');
                } else if ch == '\n' {
                    out.push('\n');
                } else {
                    out.push(' ');
                }
            }
            State::Str(quote) => {
                out.push(ch);
                if ch == '\\' {
                    if let Some(next) = chars.next() {
                        out.push(next);
                    }
                } else if ch == quote {
                    state = State::Code;
                }
            }
        }
    }

    out
}

/// Strip `/* … */` only. CSS has no line comments, so the JavaScript stripper
/// would read the `//` in `url(https://…)` as one and hide a remote font.
fn strip_css_comments(text: &str) -> String {
    blank_between(text, "/*", "*/")
}

/// Strip `<!-- … -->`.
fn strip_html_comments(text: &str) -> String {
    blank_between(text, "<!--", "-->")
}

fn blank_between(text: &str, open: &str, close: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let Some(start) = rest.find(open) else {
            out.push_str(rest);
            return out;
        };
        out.push_str(rest.get(..start).unwrap_or_default());
        let after = rest.get(start..).unwrap_or_default();
        let end = after.find(close).map_or(after.len(), |e| e.saturating_add(close.len()));
        for ch in after.get(..end).unwrap_or_default().chars() {
            out.push(if ch == '\n' { '\n' } else { ' ' });
        }
        rest = after.get(end..).unwrap_or_default();
    }
}

/// Remove comments according to the file type.
fn code_of(path: &Path, text: &str) -> String {
    if walk::has_extension(path, "css") {
        strip_css_comments(text)
    } else if walk::has_extension(path, "html") || walk::has_extension(path, "svg") {
        strip_html_comments(text)
    } else {
        strip_js_comments(text)
    }
}

/// Run every web-side rule against `web_root`.
pub(crate) fn scan(root: &Path, web_root: &Path) -> std::io::Result<Report> {
    let mut report = Report::new();
    report.ran("web-first-party-only");
    report.ran("web-no-code-from-strings");
    report.ran("web-no-inline-handlers");
    report.ran("web-no-inline-script");
    report.ran("web-references-resolve");
    report.ran("web-labelled-controls");

    if !web_root.is_dir() {
        report.push(Finding::file(
            "web-first-party-only",
            relative(root, web_root),
            "the static application directory does not exist",
        ));
        return Ok(report);
    }

    // Specification 15: there is no vendor directory, ever.
    let vendor = web_root.join("vendor");
    if vendor.exists() {
        report.push(Finding::file(
            "web-first-party-only",
            relative(root, &vendor),
            "a vendor directory implies third-party assets, forbidden by specification 15",
        ));
    }

    let files = walk::files(web_root)?;
    report.examined(files.len());

    for path in &files {
        let shown = relative(root, path);
        let is_html = walk::has_extension(path, "html");
        let is_js = walk::has_extension(path, "js");
        let is_css = walk::has_extension(path, "css");

        if !(is_html || is_js || is_css || walk::has_extension(path, "svg")) {
            // WOFF2 is permitted by 15 but must be first-party; anything else
            // is unexpected and reported rather than ignored.
            if !walk::has_extension(path, "woff2") {
                report.push(Finding::file(
                    "web-first-party-only",
                    &shown,
                    "unexpected asset type; specification 15 permits HTML, CSS, JS, SVG, WOFF2",
                ));
            }
            continue;
        }

        let text = walk::read_text(path)?;
        let code = code_of(path, &text);

        for (index, raw) in code.lines().enumerate() {
            let line_no = index.saturating_add(1);

            check_remote_origins(&shown, line_no, raw, &mut report);

            if is_js {
                for (pattern, reason) in FORBIDDEN_JS {
                    if raw.contains(pattern) {
                        report.push(Finding::at(
                            "web-no-code-from-strings",
                            &shown,
                            line_no,
                            format!("`{pattern}` {reason} (specification 15, 15.1)"),
                        ));
                    }
                }
            }

            if is_html {
                check_inline_handler(&shown, line_no, raw, &mut report);
            }
        }

        if is_html {
            check_inline_script(&shown, &code, &mut report);
        }
        if is_js {
            check_labelled_controls(&shown, &code, &mut report);
        }
    }

    check_module_resolution(root, web_root, &files, &mut report)?;

    Ok(report)
}

/// Rule `web-labelled-controls`: every named form control carries an
/// accessible name.
///
/// Appendix C's definition of done requires the static application to pass
/// "accessibility, CSP, injection, CSRF/CORS, and privilege tests". Four of
/// those five had coverage — injection and inline script through the rules
/// above, CSP and CSRF/CORS through the management API's own tests. The
/// accessibility item had none: the application is built correctly today
/// (`components/table.js`'s `field` pairs a `<label for>` with each control and
/// wires `aria-describedby`) but nothing stopped the next view from creating a
/// bare `el('input', …)` and leaving it unnamed.
///
/// A control with no accessible name is not a cosmetic problem. A screen reader
/// announces it as "edit text, blank", so a form that reads perfectly on screen
/// becomes a sequence of unlabelled boxes — and this application's forms revoke
/// API keys and publish routing policy.
///
/// Three labelling forms are accepted, all of them in use:
///
/// 1. the control is passed as `control:` to `field` / `inlineField`, which
///    attaches a `<label for>`;
/// 2. it carries `aria-label` or `aria-labelledby` in its own attributes;
/// 3. it carries an `id` and the file builds an `el('label', { for: … })`.
///
/// # What this rule cannot see
///
/// Only *named* controls (`const x = el('input', …)`) are checked. A factory
/// that ends `return el('input', …)` — `credentials.js`'s `secretInput` — is
/// exempt, because its label attaches at the call site and a syntactic scan
/// cannot follow the value there. And no static rule can judge colour contrast,
/// focus order, or whether a label's wording is meaningful. This checks the
/// part that is mechanically decidable, which is the part that regresses
/// silently.
fn check_labelled_controls(shown: &Path, text: &str, report: &mut Report) {
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        // `const name = el('input', {` — the declaration form. Anything else
        // (an inline argument, a bare `return`) is out of scope, stated above.
        let Some(rest) = trimmed
            .strip_prefix("const ")
            .or_else(|| trimmed.strip_prefix("let "))
        else {
            continue;
        };
        let Some((name, tail)) = rest.split_once(" = el(") else {
            continue;
        };
        let name = name.trim();
        if !["'input'", "'select'", "'textarea'"]
            .iter()
            .any(|tag| tail.starts_with(tag))
        {
            continue;
        }

        // The attribute object may span lines, so the whole file is searched
        // for the evidence rather than just this one.
        let passed_to_field = text.contains(&format!("control: {name}"));
        // This declaration's own attribute object: from here to the nearest
        // `});`. Scoping matters — a file-wide search would let one correctly
        // labelled control vouch for every other control beside it, which is an
        // escape hatch that makes the rule unfalsifiable.
        let block = {
            let start = text.find(trimmed).unwrap_or(0);
            let end = text
                .get(start..)
                .and_then(|rest| rest.find("});"))
                .map_or(text.len(), |offset| start.saturating_add(offset));
            text.get(start..end).unwrap_or("")
        };
        let has_aria = block.contains("aria-label") || block.contains("aria-labelledby");
        // A `<label for=…>` counts only when it names *this* control's id.
        let has_label_for = control_id(block).is_some_and(|id| {
            text.contains(&format!("el('label', {{ for: {id}"))
                || text.contains(&format!("for: {id},"))
                || text.contains(&format!("for: {id} "))
        });

        if !(passed_to_field || has_aria || has_label_for) {
            report.push(Finding::at(
                "web-labelled-controls",
                shown,
                index.saturating_add(1),
                format!(
                    "the control `{name}` has no accessible name: pass it as `control:` to \
                     `field`/`inlineField`, give it `aria-label`, or pair it with an \
                     `el('label', {{ for: … }})`. A screen reader announces an unnamed \
                     control as \"edit text, blank\" (Appendix C)"
                ),
            ));
        }
    }
}

/// The `id` a control declares, as written.
///
/// Handles both `id: expr` and the `id,` shorthand, because the application
/// uses both and a rule that saw only one would pass the other by accident.
fn control_id(block: &str) -> Option<&str> {
    for line in block.lines() {
        let trimmed = line.trim().trim_end_matches(',');
        if trimmed == "id" {
            return Some("id");
        }
        if let Some(value) = trimmed.strip_prefix("id: ") {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn check_remote_origins(shown: &Path, line: usize, raw: &str, report: &mut Report) {
    for scheme in REMOTE_SCHEMES {
        let mut from = 0usize;
        while let Some(offset) = raw.get(from..).and_then(|s| s.find(scheme)) {
            let at = from.saturating_add(offset);
            let tail = raw.get(at..).unwrap_or_default();
            if !NAMESPACE_URIS.iter().any(|ns| tail.starts_with(ns)) {
                let shown_url: String = tail.chars().take(60).collect();
                report.push(Finding::at(
                    "web-first-party-only",
                    shown,
                    line,
                    format!(
                        "reference to a remote origin `{shown_url}`; specification 15 forbids \
                         CDN assets, remote fonts, and telemetry SDKs"
                    ),
                ));
            }
            from = at.saturating_add(scheme.len());
        }
    }
}

/// Every HTML event handler content attribute.
///
/// An explicit list rather than an `on[a-z]+=` pattern, because ordinary
/// attribute names begin with those two letters too — `one`, `only`, and any
/// `data-`-adjacent name a component invents. Matching the pattern would make
/// the rule cry wolf, and a gate that cries wolf gets switched off.
const EVENT_ATTRIBUTES: &[&str] = &[
    "onabort", "onafterprint", "onauxclick", "onbeforeinput", "onbeforematch", "onbeforeprint",
    "onbeforetoggle", "onbeforeunload", "onblur", "oncancel", "oncanplay", "oncanplaythrough",
    "onchange", "onclick", "onclose", "oncontextlost", "oncontextmenu", "oncontextrestored",
    "oncopy", "oncuechange", "oncut", "ondblclick", "ondrag", "ondragend", "ondragenter",
    "ondragleave", "ondragover", "ondragstart", "ondrop", "ondurationchange", "onemptied",
    "onended", "onerror", "onfocus", "onformdata", "onhashchange", "oninput", "oninvalid",
    "onkeydown", "onkeypress", "onkeyup", "onlanguagechange", "onload", "onloadeddata",
    "onloadedmetadata", "onloadstart", "onmessage", "onmessageerror", "onmousedown",
    "onmouseenter", "onmouseleave", "onmousemove", "onmouseout", "onmouseover", "onmouseup",
    "onoffline", "ononline", "onpagehide", "onpageshow", "onpaste", "onpause", "onplay",
    "onplaying", "onpopstate", "onprogress", "onratechange", "onrejectionhandled", "onreset",
    "onresize", "onscroll", "onscrollend", "onsecuritypolicyviolation", "onseeked", "onseeking",
    "onselect", "onslotchange", "onstalled", "onstorage", "onsubmit", "onsuspend", "ontimeupdate",
    "ontoggle", "onunhandledrejection", "onunload", "onvolumechange", "onwaiting", "onwheel",
];

/// Detect inline event handler attributes. Specification 15.1: "no inline
/// event handlers".
fn check_inline_handler(shown: &Path, line: usize, raw: &str, report: &mut Report) {
    let lower = raw.to_ascii_lowercase();
    for name in EVENT_ATTRIBUTES {
        let mut from = 0usize;
        while let Some(offset) = lower.get(from..).and_then(|s| s.find(name)) {
            let at = from.saturating_add(offset);
            let after = at.saturating_add(name.len());

            // The name must be a whole attribute: preceded by whitespace or a
            // tag opening, and followed by `=`.
            let before_ok = at == 0
                || lower
                    .get(..at)
                    .and_then(|s| s.chars().next_back())
                    .is_some_and(|c| c.is_ascii_whitespace() || c == '<' || c == '"' || c == '\'');
            let after_ok = lower
                .get(after..)
                .map(|s| s.trim_start())
                .is_some_and(|s| s.starts_with('='));

            if before_ok && after_ok {
                report.push(Finding::at(
                    "web-no-inline-handlers",
                    shown,
                    line,
                    format!("inline event handler `{name}=` (specification 15.1)"),
                ));
            }
            from = after;
        }
    }
}

/// A `<script>` element must carry `src` and have an empty body, so that the
/// content security policy can forbid inline script outright.
fn check_inline_script(shown: &Path, text: &str, report: &mut Report) {
    let mut search = 0usize;
    while let Some(offset) = text.get(search..).and_then(|s| s.find("<script")) {
        let open = search.saturating_add(offset);
        let after_tag = text.get(open..).and_then(|s| s.find('>')).map(|e| open.saturating_add(e));
        let Some(tag_end) = after_tag else {
            return;
        };
        let close = text.get(tag_end..).and_then(|s| s.find("</script>"));
        if let Some(close_offset) = close {
            let body_start = tag_end.saturating_add(1);
            let body_end = tag_end.saturating_add(close_offset);
            let body = text.get(body_start..body_end).unwrap_or_default();
            if !body.trim().is_empty() {
                let line = text.get(..open).unwrap_or_default().lines().count();
                report.push(Finding::at(
                    "web-no-inline-script",
                    shown,
                    line,
                    "inline script body; specification 15.1 requires external first-party files \
                     so the content security policy can forbid inline script",
                ));
            }
        }
        search = tag_end.saturating_add(1);
    }
}

/// Every referenced module, stylesheet, and image must exist in the tree.
fn check_module_resolution(
    root: &Path,
    web_root: &Path,
    files: &[PathBuf],
    report: &mut Report,
) -> std::io::Result<()> {
    for path in files {
        let is_js = walk::has_extension(path, "js");
        let is_html = walk::has_extension(path, "html");
        if !(is_js || is_html) {
            continue;
        }

        let shown = relative(root, path);
        let text = walk::read_text(path)?;
        let code = code_of(path, &text);

        for (index, raw) in code.lines().enumerate() {
            let line_no = index.saturating_add(1);
            let refs = if is_js { js_references(raw) } else { html_references(raw) };

            for reference in refs {
                let Some(resolved) = resolve(web_root, path, &reference) else {
                    report.push(Finding::at(
                        "web-references-resolve",
                        &shown,
                        line_no,
                        format!(
                            "`{reference}` escapes the application directory or is not a \
                             same-origin path"
                        ),
                    ));
                    continue;
                };
                if !resolved.is_file() {
                    report.push(Finding::at(
                        "web-references-resolve",
                        &shown,
                        line_no,
                        format!(
                            "`{reference}` does not exist ({}); the application cannot load",
                            relative(root, &resolved).display()
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Extract ES-module specifiers: `import … from "x"`, `import "x"`,
/// and `import("x")`.
fn js_references(line: &str) -> Vec<String> {
    let trimmed = line.trim_start();
    let mut out = Vec::new();

    if trimmed.starts_with("import") || trimmed.starts_with("export") {
        if let Some(spec) = trimmed.rsplit_once(" from ").and_then(|(_, s)| first_string(s)) {
            out.push(spec);
        } else if trimmed.starts_with("import ") || trimmed.starts_with("import\"") {
            if let Some(spec) = first_string(trimmed) {
                out.push(spec);
            }
        }
    }

    if let Some(rest) = line.split_once("import(") {
        if let Some(spec) = first_string(rest.1) {
            out.push(spec);
        }
    }

    // Only relative or absolute same-origin paths are module specifiers here;
    // a bare specifier would require a package resolver, which does not exist.
    out.into_iter().filter(|s| s.starts_with('/') || s.starts_with('.')).collect()
}

/// Extract `src=` and `href=` targets from HTML.
fn html_references(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    for attr in ["src=\"", "href=\""] {
        let mut from = 0usize;
        while let Some(offset) = line.get(from..).and_then(|s| s.find(attr)) {
            let start = from.saturating_add(offset).saturating_add(attr.len());
            if let Some(end_offset) = line.get(start..).and_then(|s| s.find('"')) {
                let value = line.get(start..start.saturating_add(end_offset)).unwrap_or_default();
                // Fragments, data URIs and mailto are not files.
                if value.starts_with('/') || value.starts_with('.') {
                    out.push(value.to_string());
                }
                from = start.saturating_add(end_offset);
            } else {
                break;
            }
        }
    }
    out
}

fn first_string(s: &str) -> Option<String> {
    let bytes = s.char_indices();
    let mut quote = None;
    for (i, ch) in bytes {
        match quote {
            None if ch == '"' || ch == '\'' => quote = Some((ch, i.saturating_add(1))),
            Some((q, start)) if ch == q => return s.get(start..i).map(str::to_string),
            _ => {}
        }
    }
    None
}

/// Resolve a reference against the application root, refusing traversal.
fn resolve(web_root: &Path, from: &Path, reference: &str) -> Option<PathBuf> {
    let without_query =
        reference.split('?').next().unwrap_or(reference).split('#').next().unwrap_or(reference);

    let candidate = if let Some(rest) = without_query.strip_prefix('/') {
        web_root.join(rest)
    } else {
        from.parent()?.join(without_query)
    };

    // Normalise without touching the filesystem, then confirm containment.
    let mut normalised = PathBuf::new();
    for component in candidate.components() {
        match component {
            Component::ParentDir => {
                if !normalised.pop() {
                    return None;
                }
            }
            Component::CurDir => {}
            other => normalised.push(other.as_os_str()),
        }
    }
    if !normalised.starts_with(web_root) {
        return None;
    }
    Some(normalised)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_forbidden_name_inside_a_comment_is_not_a_violation() {
        // `web/components/dom.js` explains in its header that it never touches
        // `innerHTML`. Flagging that sentence would be a false positive.
        let js = "/**\n * never touches innerHTML or document.write.\n */\nconst a = 1;\n";
        let code = strip_js_comments(js);
        assert!(!code.contains("innerHTML"));
        assert!(code.contains("const a = 1;"));
    }

    #[test]
    fn stripping_comments_preserves_line_numbers() {
        let js = "/* one\n   two */\nconst a = 1;\n";
        assert_eq!(strip_js_comments(js).lines().count(), js.lines().count());
        assert_eq!(strip_js_comments(js).lines().nth(2), Some("const a = 1;"));
    }

    #[test]
    fn a_double_slash_inside_a_string_does_not_start_a_comment() {
        // This is the failure direction that matters: treating the `//` in a
        // URL as a comment would hide the remote origin behind it.
        let js = "const u = \"https://cdn.example.com/x.js\";\n";
        assert!(strip_js_comments(js).contains("https://cdn.example.com"));
    }

    #[test]
    fn css_url_values_survive_stripping() {
        // CSS has no line comments, so `url(https://…)` must not be eaten.
        let css = "@font-face { src: url(https://fonts.example.com/a.woff2); }\n";
        assert!(strip_css_comments(css).contains("https://fonts.example.com"));
    }

    #[test]
    fn a_script_tag_inside_an_html_comment_is_not_an_inline_script() {
        let html = "<!--\n  there is no <script> with a body here\n-->\n<p>hi</p>\n";
        let code = strip_html_comments(html);
        let mut report = Report::new();
        check_inline_script(Path::new("i.html"), &code, &mut report);
        assert!(report.is_clean(), "{:?}", report.findings());
    }

    #[test]
    fn an_unterminated_comment_swallows_the_remainder_rather_than_panicking() {
        let js = "const a = 1;\n/* unterminated\nmore text\n";
        let code = strip_js_comments(js);
        assert!(code.contains("const a = 1;"));
        assert!(!code.contains("more text"));
    }

    #[test]
    fn module_specifiers_are_extracted() {
        assert_eq!(js_references("import { a } from \"./x.js\";"), vec!["./x.js"]);
        assert_eq!(js_references("import \"/y.js\";"), vec!["/y.js"]);
        assert_eq!(js_references("export { a } from '../z.js';"), vec!["../z.js"]);
    }

    #[test]
    fn bare_specifiers_are_not_treated_as_paths() {
        // There is no package resolver, so a bare specifier is a different
        // failure, caught by the browser rather than by path existence.
        assert!(js_references("import x from \"lodash\";").is_empty());
    }

    #[test]
    fn html_src_and_href_are_extracted() {
        assert_eq!(html_references("<script src=\"/app.js\"></script>"), vec!["/app.js"]);
        assert_eq!(html_references("<link href=\"/styles/main.css\">"), vec!["/styles/main.css"]);
    }

    #[test]
    fn data_uris_and_fragments_are_not_files() {
        assert!(html_references("<link href=\"data:image/svg+xml,<svg/>\">").is_empty());
        assert!(html_references("<a href=\"#main\">").is_empty());
    }

    #[test]
    fn references_resolve_against_the_application_root() {
        let web = Path::new("/repo/web");
        let from = Path::new("/repo/web/components/table.js");
        assert_eq!(resolve(web, from, "/api.js"), Some(PathBuf::from("/repo/web/api.js")));
        assert_eq!(resolve(web, from, "./dom.js"), Some(PathBuf::from("/repo/web/components/dom.js")));
        assert_eq!(resolve(web, from, "../api.js"), Some(PathBuf::from("/repo/web/api.js")));
    }

    #[test]
    fn traversal_outside_the_application_root_is_refused() {
        let web = Path::new("/repo/web");
        let from = Path::new("/repo/web/api.js");
        assert_eq!(resolve(web, from, "../../etc/passwd"), None);
    }

    #[test]
    fn query_strings_are_stripped_before_resolution() {
        let web = Path::new("/repo/web");
        let from = Path::new("/repo/web/index.html");
        assert_eq!(resolve(web, from, "/app.js?v=2"), Some(PathBuf::from("/repo/web/app.js")));
    }

    #[test]
    fn xml_namespaces_are_not_remote_fetches() {
        let mut report = Report::new();
        check_remote_origins(
            Path::new("i.html"),
            1,
            "<svg xmlns='http://www.w3.org/2000/svg'>",
            &mut report,
        );
        assert!(report.is_clean());
    }

    #[test]
    fn a_cdn_reference_is_reported() {
        let mut report = Report::new();
        check_remote_origins(
            Path::new("i.html"),
            1,
            "<script src=\"https://cdn.example.com/x.js\">",
            &mut report,
        );
        assert!(!report.is_clean());
    }

    #[test]
    fn inline_handlers_are_reported() {
        let mut report = Report::new();
        check_inline_handler(Path::new("i.html"), 1, "<button onclick=\"go()\">", &mut report);
        assert!(!report.is_clean());
    }

    #[test]
    fn attributes_merely_starting_with_on_are_not_handlers() {
        // `one=` and `once=` begin with the same two letters as every event
        // handler. Only names on the HTML event list count.
        let mut report = Report::new();
        check_inline_handler(Path::new("i.html"), 1, "<div one=\"1\" once=\"2\">", &mut report);
        assert!(report.is_clean(), "{:?}", report.findings());
    }

    #[test]
    fn handler_detection_is_case_insensitive_and_tolerates_spacing() {
        for markup in ["<b OnClick=\"x\">", "<b onclick =\"x\">", "<b\nonload=\"x\">"] {
            let mut report = Report::new();
            check_inline_handler(Path::new("i.html"), 1, markup, &mut report);
            assert!(!report.is_clean(), "missed handler in {markup}");
        }
    }

    #[test]
    fn a_handler_name_appearing_inside_a_longer_word_is_not_matched() {
        let mut report = Report::new();
        check_inline_handler(Path::new("i.html"), 1, "<div data-onclick=\"x\">", &mut report);
        assert!(report.is_clean(), "{:?}", report.findings());
    }

    #[test]
    fn a_script_with_a_body_is_reported_but_an_empty_one_is_not() {
        let mut report = Report::new();
        check_inline_script(Path::new("i.html"), "<script>alert(1)</script>", &mut report);
        assert!(!report.is_clean());

        let mut clean = Report::new();
        check_inline_script(
            Path::new("i.html"),
            "<script type=\"module\" src=\"/app.js\"></script>",
            &mut clean,
        );
        assert!(clean.is_clean());
    }
}
