/**
 * Settings.
 *
 * Specification 15.3: "Settings — OIDC, retention, CORS/origins, break-glass,
 * safe deployment parameters."
 *
 * All five now come from one request, `GET /admin/v1/settings` (`settings_view`
 * in `crates/hypellm-admin-api/src/handlers.rs`), and this screen is a rendering
 * of that one response and nothing else. There is no second endpoint to
 * reconcile and no value on the page that was derived from anywhere but the
 * body the router returned, so "what is this router configured with" and "what
 * does this screen say" are the same question.
 *
 * Four things about the response shape the screen, and each is a deliberate
 * property of the endpoint rather than an omission to be worked around:
 *
 * - **It is read-only, by design and not by absence.** The body carries
 *   `read_only: true` and a `note` saying why: settings are configuration, and
 *   configuration changes through a policy draft and a publish so that the
 *   change is reviewed, recorded, and activated atomically (specification 11.2,
 *   19). This screen therefore offers no edit control at all — not a disabled
 *   one, which would suggest the missing part is a permission rather than the
 *   route. The note is rendered where an editor would otherwise be.
 * - **It deliberately omits local socket paths.** The TLS helper, identity
 *   verifier, and control sockets are reported as *wired or not*, never as
 *   paths; the control socket in particular is unauthenticated, so anything
 *   that can open it can stop the router. The screen shows the booleans it is
 *   given and invents no path.
 * - **Break-glass is reported as two facts, not one.** The sign-in exists on
 *   every router (`POST /admin/v1/auth/break-glass`, and the sign-in screen
 *   offers it); whether *this* deployment preprovisioned a token is
 *   `break_glass.configured`, and that is the one that decides whether the
 *   recovery path can actually be used. The absent case is given the weight of
 *   a banner rather than a table row, because a screen that read as a working
 *   escape hatch would be believed during exactly the incident where it is not.
 * - **Retention is the caller's own tenant's**, not a fleet-wide value, so the
 *   panel names the tenant it is reporting for.
 *
 * `prompt_capture_enabled` gets the same banner treatment for the opposite
 * reason: specification 10 says prompt and completion bodies are not logged by
 * default, so a `true` here means an operator has turned that default off and
 * every request body is now within reach of whoever can read the logs. A row in
 * a table is not enough weight for a change in what the system retains.
 *
 * The screen requires `manage_settings` because that is what the endpoint
 * requires (`self.require(session, Permission::ManageSettings)`). Gating it any
 * lower would put the screen in the navigation for principals whose only
 * request from it is a 403.
 *
 * `ManageSettings` also carries `requires_reauthentication`, so holding the
 * permission is not sufficient: a session past the freshness window is refused
 * at load with `reauthentication_required`. That refusal is a 403, exactly like
 * a permission denial, and the two are distinguished by code rather than by
 * status — see [`reauthenticationRequired`]. It is a recoverable condition and
 * is rendered as one.
 */

import { el, formatCount, formatDuration, formatTime, pill } from '../components/dom.js';
import { banner, buttonRow, card, pageHeader, render, table } from '../components/table.js';
import { actionButton, definitionList, emptyState, panel, toolbar } from '../components/layout.js';

/** Screen metadata, read by the router to build navigation. */
export const meta = {
  path: '/settings',
  title: 'Settings',
  lede:
    'The sign-in, retention, cross-origin, break-glass, and deployment parameters this router is running with. Read-only: settings change through a policy draft and publish.',
  permission: 'manage_settings',
};

// ------------------------------------------------------------- value shapes -

/**
 * One line an operator can act on, for a failure shown in place.
 *
 * The shell has a richer version of this, but it is private to `app.js` and it
 * writes to the banner. A screen that has lost its data has to say why *where
 * the data would have been*: a banner at the top of the page and an unexplained
 * blank below it is exactly the shape that gets misread as "nothing is
 * configured".
 *
 * @param {unknown} error
 * @returns {string}
 */
function reason(error) {
  const parts = [];
  if (error && error.message) {
    parts.push(String(error.message));
  }
  if (error && error.requestId) {
    // The only handle that ties what the operator saw to the structured log
    // and the audit record (specification 17).
    parts.push(`request ${error.requestId}`);
  }
  if (error && error.code && error.code !== 'unknown') {
    parts.push(`code ${error.code}`);
  }
  return parts.length > 0 ? parts.join(' — ') : 'the router gave no reason';
}

/** @param {unknown} value @returns {HTMLElement} A digest, origin, or other fixed-width token. */
function mono(value) {
  return el('span', { class: 'mono', text: String(value) });
}

/**
 * A boolean the router reported, as a pill.
 *
 * Returns `null` — which [`definitionList`] renders as an em dash — when the
 * field is not a boolean, so a field the router omitted is never shown as
 * "No". "Off" and "absent" are different facts, and on this screen the
 * difference is the difference between a setting that was considered and one
 * that was never reported.
 *
 * @param {unknown} value
 * @param {object} labels
 * @param {string} labels.on
 * @param {string} labels.off
 * @param {'ok'|'warn'|'danger'|'neutral'} [labels.onTone]
 * @param {'ok'|'warn'|'danger'|'neutral'} [labels.offTone]
 * @returns {HTMLElement|null}
 */
function flag(value, { on, off, onTone = 'neutral', offTone = 'neutral' }) {
  if (typeof value !== 'boolean') {
    return null;
  }
  return value ? pill(on, onTone) : pill(off, offTone);
}

/**
 * A count of seconds as something an operator reads without arithmetic.
 *
 * Session lifetimes are configured in seconds and are naturally minutes or
 * hours; the exact figure stays in the string so that comparing the screen to
 * the configuration record needs no conversion either.
 *
 * @param {unknown} seconds
 * @returns {string|null}
 */
function formatSeconds(seconds) {
  if (typeof seconds !== 'number' || !Number.isFinite(seconds)) {
    return null;
  }
  if (seconds < 120) {
    return `${formatCount(seconds)} s`;
  }
  if (seconds < 7200) {
    return `${(seconds / 60).toFixed(seconds % 60 === 0 ? 0 : 1)} min (${formatCount(seconds)} s)`;
  }
  return `${(seconds / 3600).toFixed(seconds % 3600 === 0 ? 0 : 1)} h (${formatCount(seconds)} s)`;
}

/**
 * A byte limit in both the unit it was configured in and the one it is read in.
 *
 * The exact byte count is what appears in a rejection and in the configuration
 * record, so it is never replaced by the rounded form — only accompanied by it.
 *
 * @param {unknown} bytes
 * @returns {string|null}
 */
function formatBytes(bytes) {
  if (typeof bytes !== 'number' || !Number.isFinite(bytes)) {
    return null;
  }
  const exact = `${formatCount(bytes)} bytes`;
  if (bytes < 1024) {
    return exact;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KiB (${exact})`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB (${exact})`;
}

/** @param {unknown} millis @returns {string|null} */
function formatMillis(millis) {
  if (typeof millis !== 'number' || !Number.isFinite(millis)) {
    return null;
  }
  return `${formatDuration(millis)} (${formatCount(millis)} ms)`;
}

/** @param {unknown} value @returns {string|null} */
function formatNumber(value) {
  return typeof value === 'number' && Number.isFinite(value) ? formatCount(value) : null;
}

/** @param {unknown} value @returns {object} The object, or an empty one. */
function object(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

/** @param {unknown} value @returns {unknown[]} */
function array(value) {
  return Array.isArray(value) ? value : [];
}

// ----------------------------------------------------------------- sections -

/**
 * What this response is, and which configuration produced it.
 *
 * The version and digest identify the snapshot every other value on the page
 * was read from. When they differ from the ones the session was issued against,
 * configuration has been activated under the operator (specification 11.2:
 * in-flight work keeps its prior snapshot), and someone comparing this screen
 * to a change they just published is entitled to know which side is behind.
 *
 * @param {object} settings
 * @param {object} session
 * @returns {HTMLElement}
 */
function identityPanel(settings, session) {
  const drifted =
    settings.config_version !== undefined &&
    session.config_version !== undefined &&
    (settings.config_version !== session.config_version ||
      settings.config_digest !== session.config_digest);

  return panel({
    title: 'Active configuration',
    note: 'The snapshot every value on this page was read from.',
    content: [
      drifted
        ? banner(
            'warn',
            `This session was issued against v${session.config_version} · ${session.config_digest}; the router is now serving v${settings.config_version} · ${settings.config_digest}. Reload the page to refresh the session's copy.`,
          )
        : null,
      definitionList([
        ['Tenant', settings.tenant],
        [
          'Version',
          settings.config_version === undefined ? null : `v${settings.config_version}`,
        ],
        ['Digest', settings.config_digest ? mono(settings.config_digest) : null],
        [
          'Mutable here',
          flag(settings.read_only, {
            on: 'No — read-only',
            off: 'Yes',
            onTone: 'neutral',
            offTone: 'warn',
          }),
        ],
      ]),
    ],
  });
}

/**
 * Sign-in: the OIDC binding and the session lifetimes it issues.
 *
 * Specification 9.1 treats these as one policy — a pinned issuer, the client it
 * authenticates as, the domains it will accept, and how long the session it
 * produces survives — so they are one panel rather than two.
 *
 * `configured` is whether the router holds an OIDC configuration at all;
 * `verifier_configured` is whether the local verifier that checks the returned
 * claims is wired. Both must be true for a sign-in to complete, and the second
 * fails late — at the callback, after the operator has already been sent to
 * Google — so it is worth showing separately rather than folding into one
 * "sign-in works" line.
 *
 * @param {object} oidc
 * @param {object} sessions
 * @returns {HTMLElement}
 */
function signInPanel(oidc, sessions) {
  // An absent list and an empty one mean different things and are kept apart
  // below; `null` here is "the router did not report the field".
  const domains = Array.isArray(oidc.hosted_domains)
    ? oidc.hosted_domains.map((domain) => String(domain))
    : null;

  return panel({
    title: 'Sign-in (OIDC)',
    note: 'Specification 9.1. The issuer is pinned in configuration; no value here is supplied by the browser.',
    content: [
      oidc.configured === false
        ? banner(
            'warn',
            'No OIDC configuration is loaded, so this router cannot start a sign-in. Any session in use was established some other way.',
          )
        : null,
      oidc.configured === true && oidc.verifier_configured === false
        ? banner(
            'warn',
            'Sign-in is configured but no local identity verifier is wired. The authorization redirect will succeed and the callback will then fail, because the returned claims cannot be verified.',
          )
        : null,
      definitionList(
        [
          [
            'Sign-in configured',
            flag(oidc.configured, { on: 'Yes', off: 'No', onTone: 'ok', offTone: 'warn' }),
          ],
          ['Issuer', oidc.issuer ? mono(oidc.issuer) : null],
          ['Client id', oidc.client_id ? mono(oidc.client_id) : null],
          ['Redirect URI', oidc.redirect_uri ? mono(oidc.redirect_uri) : null],
          [
            'Permitted hosted domains',
            // An empty list is not "none permitted": `oidc.rs` applies the check
            // only when the list is non-empty, so an empty list accepts every
            // domain the issuer will authenticate. Rendering that as "—" would
            // read as the safer of the two. A list the router did not report at
            // all stays "—", because that is a different fact again.
            domains === null
              ? null
              : domains.length > 0
                ? domains.join(', ')
                : 'Any domain the issuer accepts — no hosted-domain restriction is configured',
          ],
          [
            'Local identity verifier',
            flag(oidc.verifier_configured, {
              on: 'Wired',
              off: 'Not wired',
              onTone: 'ok',
              offTone: 'warn',
            }),
          ],
          ['Session idle timeout', formatSeconds(sessions.idle_seconds)],
          ['Session absolute lifetime', formatSeconds(sessions.absolute_seconds)],
        ],
        { wide: true },
      ),
    ],
  });
}

/**
 * Retention, for the tenant the caller belongs to.
 *
 * The endpoint answers with the caller's own tenant's profile and nothing
 * else, so the panel says whose it is. When the tenant carries no profile the
 * fields are absent rather than zero, and that is stated instead of being
 * rendered as a row of em dashes that could be read as "retain nothing".
 *
 * @param {object} retention
 * @param {unknown} tenant
 * @returns {HTMLElement}
 */
function retentionPanel(retention, tenant) {
  const named = tenant ? String(tenant) : 'this tenant';
  const hasProfile =
    retention.days !== undefined ||
    retention.residency !== undefined ||
    retention.max_cost_class !== undefined;

  return panel({
    title: 'Retention',
    note: `Specification 5 and 17, for tenant ${named}. Another tenant's profile is not readable here.`,
    content: hasProfile
      ? definitionList([
          ['Retention window', retention.days === undefined ? null : `${formatCount(retention.days)} days`],
          [
            'Residency',
            retention.residency
              ? String(retention.residency)
              : 'Unconstrained — no residency class is declared for this tenant',
          ],
          [
            'Maximum cost class',
            retention.max_cost_class === undefined
              ? 'Unconstrained — no ceiling is declared for this tenant'
              : formatNumber(retention.max_cost_class),
          ],
          [
            'Prompt and completion capture',
            flag(retention.prompt_capture_enabled, {
              on: 'Enabled',
              off: 'Disabled (default)',
              onTone: 'danger',
              offTone: 'ok',
            }),
          ],
        ])
      : [
          emptyState(
            `No retention profile is declared for tenant ${named}`,
            'The router returned no retention window, residency class, or cost ceiling for this tenant. This is what the configuration says, not a failed read: a tenant with no declared profile inherits the router-wide defaults.',
          ),
          definitionList([
            [
              'Prompt and completion capture',
              flag(retention.prompt_capture_enabled, {
                on: 'Enabled',
                off: 'Disabled (default)',
                onTone: 'danger',
                offTone: 'ok',
              }),
            ],
          ]),
        ],
  });
}

/**
 * The exact cross-origin allowlist.
 *
 * Specification 15.4 requires exact origins, credentials mode, and preflight
 * validation, and forbids a wildcard alongside cookies. `cors.rs` compares
 * origins byte-for-byte — no suffix match, no scheme coercion, no case folding
 * — so an entry such as `*` is not a wildcard here but a literal string no
 * browser will ever send. That is called out rather than left to look
 * permissive.
 *
 * @param {string[]} origins
 * @returns {HTMLElement}
 */
function corsPanel(origins) {
  if (origins.length === 0) {
    return panel({
      title: 'Cross-origin access',
      note: 'Specification 15.4.',
      content: emptyState(
        'No cross-origin origin is allowed',
        'The allowlist is empty, which is the correct setting when this console is served from the same origin as the management API: every cross-origin request is refused. This is a configured value, not a missing one.',
      ),
    });
  }

  return panel({
    title: 'Cross-origin access',
    note: 'Specification 15.4. Origins are matched exactly; the router never emits a wildcard.',
    content: table({
      caption:
        'Origins permitted to call the management API with credentials. Anything not listed is refused.',
      columns: [
        { label: 'Allowed origin', cell: (row) => mono(row.origin) },
        {
          label: 'Note',
          cell: (row) =>
            row.origin === '*'
              ? pill('Matched literally, not as a wildcard', 'warn')
              : pill('Exact match', 'neutral'),
        },
      ],
      rows: origins.map((origin) => ({ origin })),
      // Unreachable — the empty case returned above — but a silent blank table
      // is never the right fallback.
      empty: 'The allowlist could not be read from the response.',
    }),
  });
}

/**
 * Break-glass, stated as it is rather than as it sounds.
 *
 * @param {object} breakGlass
 * @param {object} session
 * @returns {HTMLElement}
 */
function breakGlassPanel(breakGlass, session) {
  const ttl =
    typeof breakGlass.session_ttl_seconds === 'number'
      ? formatDuration(breakGlass.session_ttl_seconds * 1000)
      : null;

  return panel({
    title: 'Break-glass',
    note: 'Specification 9.3 and 22.4.',
    content: [
      session.break_glass
        ? banner(
            'warn',
            'You are in a break-glass session right now: it is time-limited, separately audited, and subject to mandatory review.',
          )
        : null,
      definitionList(
        [
          [
            'Role bindable',
            flag(breakGlass.role_available, { on: 'Yes', off: 'No', onTone: 'neutral', offTone: 'warn' }),
          ],
          [
            'Local break-glass sign-in',
            flag(breakGlass.local_authentication_implemented, {
              on: 'Implemented',
              off: 'Not implemented',
              onTone: 'ok',
              offTone: 'danger',
            }),
          ],
          // The one that decides whether the recovery path works here. A token
          // is preprovisioned by `--generate-secrets` and printed once; a
          // router that never had one, or whose operator lost it, reports
          // `false` and cannot be given another without a new key bundle.
          [
            'Token preprovisioned',
            flag(breakGlass.configured, {
              on: 'Yes',
              off: 'No',
              onTone: 'ok',
              offTone: 'danger',
            }),
          ],
          ['Session lifetime', ttl],
          ['What that means', breakGlass.note ? String(breakGlass.note) : null],
        ],
        { wide: true },
      ),
    ],
  });
}

/**
 * The bounded-work parameters of specification 3.2 and 12.
 *
 * Every one of these is a ceiling on what a single request may consume, so they
 * are read together — a deadline without a body limit and a body limit without
 * a retry budget each leave a different way to spend the router's resources.
 *
 * The three local sockets are reported here as wired or not. The endpoint does
 * not disclose their paths and this screen does not invent them: each names a
 * local attack surface, and the control socket is unauthenticated, so anything
 * that can open it can stop the router.
 *
 * @param {object} deployment
 * @returns {HTMLElement}
 */
function deploymentPanel(deployment) {
  return panel({
    title: 'Deployment parameters',
    note: 'Specification 3.2, 6.5, and 12. Local socket paths are deliberately not disclosed by the endpoint; what is reported is whether each is wired.',
    content: [
      deployment.allow_generic_adapter === true
        ? banner(
            'warn',
            'The generic adapter is enabled. Targets may be routed through the unmodelled OpenAI-compatible path rather than a compile-time provider adapter.',
          )
        : null,
      definitionList([
        ['Maximum request body', formatBytes(deployment.max_body_bytes)],
        ['Maximum request head', formatBytes(deployment.max_head_bytes)],
        ['Default deadline', formatMillis(deployment.default_deadline_ms)],
        ['Maximum attempts', formatNumber(deployment.max_attempts)],
        ['Retry budget', formatMillis(deployment.retry_budget_ms)],
        ['Slow-client timeout', formatMillis(deployment.slow_client_timeout_ms)],
        ['Stream keepalive interval', formatMillis(deployment.keepalive_interval_ms)],
        [
          'Breaker failure ceiling',
          deployment.max_failure_percent === undefined
            ? null
            : `${formatCount(deployment.max_failure_percent)}%`,
        ],
        [
          'Weighted tie-break',
          flag(deployment.weighted_tie_break, { on: 'Enabled', off: 'Disabled' }),
        ],
        [
          'Generic adapter',
          flag(deployment.allow_generic_adapter, {
            on: 'Allowed',
            off: 'Refused (default)',
            onTone: 'warn',
            offTone: 'ok',
          }),
        ],
        [
          'Outbound TLS helper',
          flag(deployment.outbound_tls_configured, {
            on: 'Wired',
            off: 'Not wired',
            onTone: 'ok',
            offTone: 'warn',
          }),
        ],
      ]),
    ],
  });
}

/**
 * The session is authenticated, but not recently enough for `manage_settings`.
 *
 * `Permission::requires_reauthentication` is true for `ManageSettings`, and
 * `settings_view` calls `require` before it builds anything, so a session past
 * the freshness window fails this screen at load. The refusal arrives as a 403
 * — the same status as a plain permission denial — so it is told apart by its
 * code and given the one control that resolves it. Rendering it as a refusal
 * would send an operator looking for a role change that did not happen, and
 * leave them no way forward but signing out.
 *
 * @param {object} ctx
 * @returns {HTMLElement}
 */
function reauthenticationRequired(ctx) {
  const again = actionButton(
    'Sign in again',
    () =>
      ctx.api.beginSignIn(meta.path).then((url) => {
        if (typeof url !== 'string' || url === '') {
          throw new Error('the router did not return an authorization endpoint');
        }
        // The fixed authorization URL the router was configured with; no part
        // of it comes from this screen or from the address bar.
        location.assign(url);
      }),
    { busyLabel: 'Redirecting…' },
  );

  return card('A recent sign-in is required', [
    el('p', {
      class: 'page-lede',
      text: 'Reading how this router is configured is a sensitive action, so the router requires an authentication newer than this session has. Nothing has failed and no setting has changed; sign in again to see them.',
    }),
    buttonRow([again]),
  ]);
}

// -------------------------------------------------------------------- paint -

/**
 * Paint one reading, or the reason there is none.
 *
 * A failed read clears the previous values rather than leaving them on screen.
 * They were true a minute ago and would be presented as current, and on this
 * screen in particular the difference between "the limit is 1 MiB" and "the
 * limit was 1 MiB when we last managed to ask" is the difference between a safe
 * deployment and a wrong one.
 *
 * @param {HTMLElement} body Element to fill.
 * @param {object|null} settings The `GET /admin/v1/settings` body.
 * @param {unknown} error Whatever the request threw, if it threw.
 * @param {object} ctx The screen context, for the session and the permission
 *   check that decides which follow-on route is worth naming.
 */
function paint(body, settings, error, ctx) {
  if (error || !settings) {
    // `reauthentication_required` is a 403 like a plain refusal, and telling
    // the two apart is the whole difference between an operator who signs in
    // again and one who goes looking for the role change that never happened.
    // Checked before the status, because the status alone cannot distinguish
    // them.
    if (error && error.code === 'reauthentication_required') {
      render(body, [reauthenticationRequired(ctx)]);
      return;
    }
    const forbidden = error && error.status === 403;
    render(body, [
      banner('error', `The settings could not be read — ${reason(error)}.`),
      emptyState(
        'Nothing is shown here',
        forbidden
          ? 'The router refused the read. This screen needs manage_settings, and a role change since sign-in would explain a refusal on a screen that was reachable a moment ago. No setting is shown, because none was returned.'
          : 'No setting is shown because the router returned none. This is a failed read, not an empty configuration.',
      ),
    ]);
    return;
  }

  const oidc = object(settings.oidc);
  const retention = object(settings.retention);
  const breakGlass = object(settings.break_glass);
  const deployment = object(settings.deployment);
  const origins = array(settings.cors_origins).map((origin) => String(origin));

  render(body, [
    // Two facts that must not be a row in a table, for opposite reasons: one is
    // a default that has been turned off, the other a capability that reads as
    // present and is not.
    retention.prompt_capture_enabled === true
      ? banner(
          'warn',
          'Prompt and completion capture is enabled. Specification 10 keeps request and response bodies out of the logs by default; with this on, every prompt this tenant sends is within reach of whoever can read the router\'s logs, for the whole retention window.',
        )
      : null,
    // Inverted from what this said before: the sign-in is implemented, so what
    // is worth a banner is a deployment that cannot use it. Read together with
    // the sign-in panel above, `configured: false` and `oidc.configured: false`
    // mean nothing can establish a session at all once the current ones expire.
    breakGlass.configured === false
      ? banner(
          'warn',
          'No break-glass token is preprovisioned on this router, so specification 22.4\'s recovery path cannot be used. The token is printed once by --generate-secrets and stored nowhere; a router without one needs a new key bundle, and a new key bundle cannot read the state directory the current one authenticates.',
        )
      : null,

    // The read-only statement stands where an editor would otherwise be, so it
    // is read before the values rather than after a search for a save button.
    settings.read_only === true
      ? el('p', {
          class: 'page-lede',
          text: settings.note
            ? `This screen is read-only: ${String(settings.note)}.`
            : 'This screen is read-only. Settings change through a policy draft and publish.',
        })
      : null,
    settings.read_only === true && ctx.can('edit_policy')
      ? el('p', {
          class: 'field__hint',
          text: 'This session holds edit_policy, so the change starts on the Routing policies screen: draft, validate, simulate, then publish for approval.',
        })
      : null,

    identityPanel(settings, ctx.session),
    signInPanel(oidc, object(settings.sessions)),
    retentionPanel(retention, settings.tenant),
    corsPanel(origins),
    breakGlassPanel(breakGlass, ctx.session),
    deploymentPanel(deployment),
  ]);
}

/**
 * Render the screen.
 *
 * @param {HTMLElement} container Empty element to render into.
 * @param {object} ctx
 * @param {import('../api.js').Api} ctx.api
 * @param {object} ctx.session The `/admin/v1/session` body.
 * @param {(path: string) => void} ctx.navigate
 * @param {(tone: string, message: string) => void} ctx.notify
 * @param {(permission: string) => boolean} ctx.can
 * @returns {Promise<() => void>} Cleanup, called on navigation away.
 */
export async function mount(container, ctx) {
  /** Set by cleanup. A reload already in flight must not paint after it. */
  let stopped = false;
  /** Guards a second click landing while the first read is still out. */
  let loading = false;

  // Awaited before anything is painted, so the shell's own "Loading…" line and
  // `aria-busy` cover the first read and this screen needs no loading state of
  // its own. The failure is captured rather than thrown: the screen can then
  // say, in the place the values would have been, that the read failed —
  // which a banner above an empty page cannot.
  let settings = null;
  let failure = null;
  try {
    const response = await ctx.api.get('/settings');
    settings = response.data || {};
  } catch (error) {
    if (error && error.name === 'AbortError') {
      // The operator navigated away; the shell has already moved on.
      return () => {};
    }
    failure = error;
  }

  const status = el('p', {
    class: 'panel__note',
    role: 'status',
    'aria-live': 'polite',
    text: !failure
      ? `Read at ${formatTime(Date.now())}.`
      : failure.code === 'reauthentication_required'
        ? 'The router asked for a fresher sign-in before answering. Nothing below is a configured value.'
        : 'The read failed. Nothing below is a configured value.',
  });

  const body = el('div');

  const reload = actionButton(
    'Reload',
    async () => {
      if (loading || stopped) {
        return;
      }
      loading = true;
      status.textContent = 'Reading…';
      try {
        const response = await ctx.api.get('/settings');
        if (stopped) {
          return;
        }
        settings = response.data || {};
        paint(body, settings, null, ctx);
        status.textContent = `Read at ${formatTime(Date.now())}.`;
      } catch (error) {
        if (error && error.name === 'AbortError') {
          // Navigation cancelled it; the next screen owns the DOM now.
          return;
        }
        // Painted here rather than left to the shell's boundary, so the page
        // itself says why it is empty. Not rethrown: the panel below carries
        // the same message the banner would, and two copies of one failure
        // teach an operator to read neither.
        settings = null;
        paint(body, null, error, ctx);
        status.textContent =
          error && error.code === 'reauthentication_required'
            ? 'The router asked for a fresher sign-in before answering. Nothing below is from this attempt.'
            : 'The reload failed. Nothing below is from this attempt.';
      } finally {
        loading = false;
      }
    },
    { tone: 'quiet', busyLabel: 'Reading…', title: 'Re-read the active settings' },
  );

  // The header and the control are built once and the response is painted into
  // `body`, so a reload cannot move focus out of the button the operator is
  // using.
  render(container, [
    pageHeader(meta.title, meta.lede),
    toolbar([el('div', { class: 'panel__actions' }, reload)], { label: 'Settings controls' }),
    status,
    body,
  ]);
  paint(body, settings, failure, ctx);

  return () => {
    stopped = true;
  };
}
