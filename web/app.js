/**
 * The application shell.
 *
 * Specification 15.1: "Router, session state, API client, abort/cancellation,
 * error boundary."
 *
 * Four decisions in this file are worth the explanation:
 *
 * - **The view list is a static import table.** Every screen is imported by
 *   name, in one place, and the same ten names appear in the router's static
 *   asset allowlist (`crates/hypellm-router/src/admin.rs`). Dynamic `import()` of
 *   a path assembled at runtime would let the two drift, and the failure mode —
 *   a screen that 404s only for the operator who navigates to it — is the kind
 *   that is discovered during an incident.
 * - **Routing is on `location.hash`, not the History API.** The server serves a
 *   fixed set of allowlisted paths and joins nothing; a History URL such as
 *   `/targets` would 404 on reload or on a pasted link. A hash never reaches
 *   the server, so every deep link resolves to `index.html` and then to a
 *   screen.
 * - **Navigation cancels.** `api.abort()` runs before the next screen mounts,
 *   and a screen may return a cleanup function. A response that arrives for an
 *   abandoned screen must not paint over the one the operator is looking at.
 * - **Nothing that throws escapes.** Every `mount` call, every stray promise
 *   rejection, and every uncaught listener error is funnelled into one banner.
 *   A management console that fails silently is worse than one that fails
 *   loudly: the operator acts on what the screen shows.
 */

import { ApiError, api } from './api.js';
import { el, pill, replace, text } from './components/dom.js';
import { actionButton } from './components/layout.js';
import { banner, buttonRow, card, field, pageHeader, render } from './components/table.js';

// The enumeration. Order is the navigation order, and it follows the reading
// order of specification 15.3 rather than alphabetical: what is running, what
// it is running on, how it is routed, who may use it, what it cost, and what
// happened.
import * as overview from './views/overview.js';
import * as targets from './views/targets.js';
import * as fleet from './views/fleet.js';
import * as activations from './views/activations.js';
import * as policies from './views/policies.js';
import * as access from './views/access.js';
import * as keys from './views/keys.js';
import * as credentials from './views/credentials.js';
import * as usage from './views/usage.js';
import * as decisions from './views/decisions.js';
import * as audit from './views/audit.js';
import * as settings from './views/settings.js';

/** Every screen, in navigation order. */
const VIEWS = [
  overview,
  targets,
  // The fleet sits next to targets: a target is what routing chooses, and a
  // deployment is that target's lifecycle on a machine. Reading one without the
  // other is how an operator concludes a model is "down" when it is merely
  // cold.
  fleet,
  activations,
  policies,
  access,
  keys,
  credentials,
  usage,
  decisions,
  audit,
  settings,
];

/** How long a success message stays before it clears itself, in milliseconds. */
const NOTICE_MILLIS = 6000;

/**
 * Look up a shell element.
 *
 * A startup invariant, not a data-plane condition: `index.html` ships with this
 * file, so a missing element means the deployment is internally inconsistent
 * and there is nothing sensible to degrade to.
 *
 * @param {string} id
 * @returns {HTMLElement}
 */
function byId(id) {
  const node = document.getElementById(id);
  if (!node) {
    throw new Error(`the application shell is missing #${id}`);
  }
  return node;
}

const shell = {
  nav: byId('nav-list'),
  view: byId('view'),
  main: byId('main'),
  banner: byId('error-banner'),
  bannerText: byId('error-text'),
  bannerDismiss: byId('error-dismiss'),
  signOut: byId('sign-out'),
  factConfig: byId('fact-config'),
  factPrincipal: byId('fact-principal'),
};

const state = {
  /** @type {object|null} The `/admin/v1/session` body, or null when signed out. */
  session: null,
  /** @type {(() => void)|null} Cleanup returned by the mounted screen. */
  cleanup: null,
  /** @type {string|null} The `meta.path` of the mounted screen. */
  current: null,
  /**
   * Incremented on every navigation. A mount that finishes with a stale token
   * lost the race and must not touch the DOM: this is the guard that makes a
   * slow screen harmless rather than a source of flicker and wrong data.
   */
  token: 0,
  /** Whether any screen has been mounted yet, to avoid stealing initial focus. */
  mounted: false,
  /** @type {number|null} Timer for the self-clearing success notice. */
  noticeTimer: null,
  /** @type {Map<string, HTMLElement>} Route path to its navigation anchor. */
  navLinks: new Map(),
};

// -------------------------------------------------------------- permissions -

/**
 * Whether the session may use a screen.
 *
 * `meta.permission` is a permission name, `null` for any signed-in principal,
 * or an array when more than one permission grants the screen — the usage and
 * policy endpoints each accept either of two (specification 9.3). A screen the
 * operator cannot use is not rendered as a disabled item: it does not appear at
 * all, so the navigation is an honest statement of what this session can do.
 *
 * @param {object} meta
 * @returns {boolean}
 */
function permitted(meta) {
  if (!state.session) {
    return false;
  }
  const required = meta.permission;
  if (required === null || required === undefined) {
    return true;
  }
  const held = state.session.permissions || [];
  const wanted = Array.isArray(required) ? required : [required];
  return wanted.some((name) => held.includes(name));
}

/** Screens this session may use, in navigation order. @returns {object[]} */
function visibleViews() {
  return VIEWS.filter((view) => permitted(view.meta));
}

// ------------------------------------------------------------------- banner -

/**
 * Show a message in the shell banner.
 *
 * There is one banner rather than a per-screen one so that a message raised
 * while a screen is being replaced still has somewhere to appear.
 *
 * @param {'ok'|'warn'|'error'} tone
 * @param {string} message
 */
function notify(tone, message) {
  clearNoticeTimer();
  shell.bannerText.textContent = message;
  shell.banner.className = `banner banner--${tone}`;
  shell.banner.setAttribute('role', tone === 'error' ? 'alert' : 'status');
  shell.banner.hidden = false;

  // A confirmation has served its purpose after it has been read; a warning or
  // an error stays until it is dismissed or the operator navigates.
  if (tone === 'ok') {
    state.noticeTimer = window.setTimeout(() => {
      state.noticeTimer = null;
      dismissBanner();
    }, NOTICE_MILLIS);
  }
}

function clearNoticeTimer() {
  if (state.noticeTimer !== null) {
    window.clearTimeout(state.noticeTimer);
    state.noticeTimer = null;
  }
}

function dismissBanner() {
  clearNoticeTimer();
  shell.banner.hidden = true;
  shell.bannerText.textContent = '';
}

/**
 * Turn any thrown value into one line an operator can act on.
 *
 * The request id is included whenever the router supplied one: it is the only
 * handle that ties what the operator saw to the structured log and the audit
 * record (specification 17), and asking them to reproduce a failure without it
 * wastes an incident.
 *
 * @param {unknown} error
 * @returns {string}
 */
function describe(error) {
  if (error instanceof ApiError) {
    const parts = [error.message];
    if (Array.isArray(error.details) && error.details.length > 0) {
      parts.push(error.details.map((detail) => String(detail)).join('; '));
    }
    if (error.requestId) {
      parts.push(`request ${error.requestId}`);
    }
    if (error.code && error.code !== 'unknown') {
      parts.push(`code ${error.code}`);
    }
    return parts.join(' — ');
  }
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return 'an unexpected fault occurred in the admin application';
}

/**
 * The error boundary.
 *
 * @param {unknown} error
 * @returns {boolean} Whether the error was handled here.
 */
function handleError(error) {
  // Aborting is how navigation works, not a failure. Reporting it would train
  // operators to ignore the banner.
  if (error && error.name === 'AbortError') {
    return true;
  }
  if (error instanceof ApiError && error.needsSignIn) {
    state.session = null;
    api.csrfToken = null;
    renderSignIn('The session has ended. Sign in again to continue.');
    return true;
  }
  notify('error', describe(error));
  return true;
}

// -------------------------------------------------------------------- route -

/**
 * The route encoded in the address bar.
 *
 * A screen may carry parameters — `#/decisions?request_id=…` is the link an
 * operator pastes from a log line — so the query is parsed here and handed to
 * the screen rather than left for each one to re-derive.
 *
 * @returns {{path: string, query: URLSearchParams}}
 */
function currentRoute() {
  const raw = location.hash.startsWith('#') ? location.hash.slice(1) : location.hash;
  const split = raw.indexOf('?');
  const path = split === -1 ? raw : raw.slice(0, split);
  const query = split === -1 ? '' : raw.slice(split + 1);
  return { path, query: new URLSearchParams(query) };
}

/**
 * Go to a screen.
 *
 * @param {string} path A `meta.path`, optionally with a `?query`.
 */
function navigate(path) {
  const normalized = path.startsWith('/') ? path : `/${path}`;
  const target = `#${normalized}`;
  if (location.hash === target) {
    // Re-navigating to the current route is a deliberate refresh; `hashchange`
    // would not fire, so route directly.
    void route();
    return;
  }
  location.hash = target;
}

/** Rebuild the navigation from the permitted screens. */
function renderNav() {
  state.navLinks = new Map();
  const items = visibleViews().map((view) => {
    const anchor = el('a', { class: 'nav__link', href: `#${view.meta.path}` }, view.meta.title);
    state.navLinks.set(view.meta.path, anchor);
    return el('li', {}, anchor);
  });
  replace(shell.nav, items);
  markCurrent(state.current);
}

/** @param {string|null} path */
function markCurrent(path) {
  for (const [routePath, anchor] of state.navLinks) {
    if (routePath === path) {
      anchor.setAttribute('aria-current', 'page');
    } else {
      anchor.removeAttribute('aria-current');
    }
  }
}

/** Run the previous screen's cleanup exactly once, and never let it break navigation. */
function runCleanup() {
  const cleanup = state.cleanup;
  state.cleanup = null;
  if (typeof cleanup !== 'function') {
    return;
  }
  try {
    cleanup();
  } catch (error) {
    // A screen that fails to tear down must not strand the operator on it.
    notify('warn', `the previous screen did not shut down cleanly: ${describe(error)}`);
  }
}

/**
 * Resolve the address bar to a screen and mount it.
 *
 * @returns {Promise<void>}
 */
async function route() {
  if (!state.session) {
    renderSignIn();
    return;
  }

  const permittedViews = visibleViews();
  if (permittedViews.length === 0) {
    renderNoAccess();
    return;
  }

  const { path, query } = currentRoute();
  const view = permittedViews.find((candidate) => candidate.meta.path === path);
  if (!view) {
    // An unknown or forbidden route is not an error worth a banner — a stale
    // bookmark and a link to a screen this role cannot use look identical from
    // here. `replace` keeps it out of the history so Back still works.
    //
    // The target is always a route that was *not* matched a moment ago, so the
    // hash necessarily changes and `hashchange` necessarily fires. Calling
    // `route` directly as well would be a recursion with no base case.
    const first = permittedViews[0];
    if (first) {
      location.replace(`#${first.meta.path}`);
    }
    return;
  }

  const token = ++state.token;
  runCleanup();
  api.abort();
  dismissBanner();

  state.current = view.meta.path;
  markCurrent(view.meta.path);
  document.title = `${view.meta.title} · HypeLLM Router`;

  // The screen renders into a container of its own so the loading line can be
  // removed independently, and so `mount` receives an element that is empty as
  // the contract promises.
  const container = el('div', { class: 'view__body' });
  const loading = el('p', { class: 'loading', text: 'Loading…' });
  shell.view.setAttribute('aria-busy', 'true');
  replace(shell.view, [loading, container]);

  // Focus follows navigation, but not the first paint: on load the operator has
  // not asked to go anywhere, and moving focus past the skip link would take
  // away the one shortcut it exists to provide.
  if (state.mounted) {
    shell.main.focus();
  }
  state.mounted = true;

  const ctx = {
    api,
    session: state.session,
    navigate,
    notify,
    /** The parsed `?…` of the current route. */
    query,
    /** The current `meta.path`. */
    path: view.meta.path,
    /** @param {string} permission @returns {boolean} */
    can: (permission) => (state.session?.permissions || []).includes(permission),
  };

  // The container stays empty: the screen owns everything below the masthead,
  // including its own `pageHeader(meta.title, meta.lede)`.
  try {
    const cleanup = await view.mount(container, ctx);
    if (token !== state.token) {
      // The operator navigated away while this was loading. Tear down whatever
      // was set up and leave the DOM to the screen that won.
      if (typeof cleanup === 'function') {
        try {
          cleanup();
        } catch {
          // Nothing to report: this screen is already gone.
        }
      }
      return;
    }
    state.cleanup = typeof cleanup === 'function' ? cleanup : null;
  } catch (error) {
    if (token !== state.token) {
      return;
    }
    handleError(error);
  } finally {
    if (token === state.token) {
      shell.view.setAttribute('aria-busy', 'false');
      loading.remove();
    }
  }
}

// ------------------------------------------------------------------ session -

/** Put the principal and configuration digest in the masthead. */
function renderFacts() {
  const session = state.session;
  if (!session) {
    shell.factConfig.textContent = '—';
    replace(shell.factPrincipal, text('—'));
    shell.signOut.hidden = true;
    return;
  }

  const digest = session.config_digest || '—';
  shell.factConfig.textContent =
    session.config_version === undefined ? digest : `v${session.config_version} · ${digest}`;
  shell.factConfig.title = 'Active configuration version and digest';

  const who = session.email || session.principal || 'unknown principal';
  const parts = [text(who)];
  if (session.break_glass) {
    // Specification 9.3: a break-glass session is time-limited and alerted on.
    // It should never be possible to forget you are in one.
    parts.push(text(' '), pill('Break glass', 'danger'));
  }
  replace(shell.factPrincipal, parts);
  shell.factPrincipal.title = session.tenant
    ? `${session.principal} in tenant ${session.tenant}`
    : String(session.principal || '');

  shell.signOut.hidden = false;
}

/**
 * Username length, mirroring `MAX_USERNAME_LEN` in `hypellm-config`.
 *
 * A bound on the input rather than a validation: the router rejects an overlong
 * name without comparing it, and this only stops the browser from sending one.
 */
const USERNAME_MAX = 64;

/**
 * Password length, mirroring `MAX_PASSWORD_LEN` in `hypellm_crypto::pbkdf2`.
 */
const PASSWORD_MAX = 1024;

/**
 * The local username-and-password sign-in panel.
 *
 * **This is not the supported way in.** Specification 9.2 lists four ways a
 * principal is established and a local password is none of them; it exists so a
 * deployment can be operated before an identity provider and a verifier process
 * have been set up, and it is recorded as a deviation in
 * `docs/deferred-issues.md`.
 *
 * Two decisions worth stating, both the same as the break-glass panel's:
 *
 * - **It is rendered whatever the router is configured with.** The form is
 *   static UI shipped with the application, so it discloses nothing: a router
 *   with no `local_user` record answers it with the same 404 it answers `curl`
 *   with, which is the property `password_sign_in` in `handlers.rs`
 *   deliberately has. The 404 is reported here as "not configured" rather than
 *   as a failure, because on a router with an identity provider that is the
 *   correct and expected answer.
 * - **The inputs carry no `name`.** A `<form>` whose submit is not prevented
 *   serializes named controls into a query string; nameless ones cannot be, so
 *   the password has no path into the address bar, the browser's history, or
 *   the router's access log even if the listener below never runs.
 *
 * @returns {{element: HTMLElement, focus: () => void}}
 */
function passwordPanel() {
  const status = el('p', { class: 'field__hint', role: 'status', 'aria-live': 'polite' });

  const username = el('input', {
    type: 'text',
    autocomplete: 'username',
    autocapitalize: 'none',
    spellcheck: 'false',
    maxlength: String(USERNAME_MAX),
  });
  const password = el('input', {
    type: 'password',
    autocomplete: 'current-password',
    autocapitalize: 'none',
    spellcheck: 'false',
    maxlength: String(PASSWORD_MAX),
  });

  const submit = actionButton('Sign in', signIn, { busyLabel: 'Signing in…' });

  const form = el('form', { novalidate: true }, [
    field({
      id: 'local-username',
      label: 'Username',
      control: username,
    }),
    field({
      id: 'local-password',
      label: 'Password',
      control: password,
    }),
    buttonRow([submit]),
    status,
  ]);

  // Same shape as the break-glass form: the button is `type="button"`, so Enter
  // routes through the one guarded handler rather than a second code path that
  // is not disabled while a sign-in is in flight.
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    submit.click();
  });

  const element = card('Sign in with a local account', [form]);

  return { element, focus: () => username.focus() };

  /** Validate locally, sign in, and enter the application. */
  async function signIn() {
    status.textContent = '';

    if (username.value === '' || password.value === '') {
      status.textContent = 'A username and a password are required.';
      (username.value === '' ? username : password).focus();
      return;
    }

    try {
      await api.passwordSignIn(username.value, password.value);
    } catch (error) {
      // Reported here rather than raised to the shell's error boundary: on this
      // screen the boundary's answer to a 401 is to render the sign-in screen,
      // which is where the operator already is.
      if (error instanceof ApiError && error.status === 404) {
        status.textContent =
          'This router has no local accounts configured. Sign in with the identity provider, or use break-glass.';
      } else {
        status.textContent = describe(error);
      }
      password.value = '';
      password.focus();
      return;
    }

    // Cleared as soon as it has been spent, for the reason the break-glass
    // panel clears its token: the value is still in the browser's memory until
    // this node is collected, but leaving it in a live input is a copy that
    // stays on screen for the whole session.
    password.value = '';

    await start();
  }
}

/**
 * Reason length, mirroring `MIN_BREAK_GLASS_REASON`/`MAX_BREAK_GLASS_REASON`
 * in `crates/hypellm-admin-api/src/handlers.rs`.
 *
 * Checked here so the operator is told what is wrong before a refusal is
 * recorded — the router checks the reason *before* the token, so a short one
 * costs a `break_glass_reason_missing` audit record and a `critical` log event
 * during an incident. Not a substitute for the router's check: this is a
 * courtesy, and the refusal that matters happens there.
 */
const BREAK_GLASS_REASON_MIN = 8;
const BREAK_GLASS_REASON_MAX = 256;

/**
 * The break-glass sign-in panel.
 *
 * Specification 22.4 requires a preprovisioned, time-limited, reason-bound
 * recovery path that does not depend on the identity provider. The router has
 * had one at `POST /admin/v1/auth/break-glass` for as long as it has had
 * `break_glass_principal`; what it did not have was a way to reach it from a
 * browser, so on a deployment with no OIDC — the air-gapped profile, and every
 * local one — the management plane could only be entered with `curl`.
 *
 * Three decisions worth stating:
 *
 * - **It is hidden until asked for, and revealed on `not_found`.** An escape
 *   hatch offered with equal weight to the ordinary sign-in becomes the
 *   ordinary sign-in, and every use of it wakes somebody. But a deployment
 *   with no OIDC configured answers `POST /auth/google/start` with 404, and an
 *   operator who has just been told "sign-in is not configured" needs the
 *   alternative in front of them rather than in the runbook.
 * - **It is rendered whatever the router is configured with.** The panel is
 *   static UI shipped with the SPA, identical everywhere, so it discloses
 *   nothing: a router that has not preprovisioned a token answers this form
 *   with the same 404 it answers `curl` with, which is the property
 *   `break_glass` in `handlers.rs` deliberately has ("a deployment that has
 *   not preprovisioned one should not advertise that the endpoint is live").
 * - **The inputs carry no `name`.** A `<form>` whose submit is not prevented
 *   serializes named controls into a query string; nameless ones cannot be
 *   serialized at all, so the token has no path into the address bar, the
 *   browser's history, or the router's access log even if this file's listener
 *   never runs. The same reasoning as `secretInput` in `views/credentials.js`.
 *
 * @returns {{element: HTMLElement, reveal: (note?: string) => void}}
 */
function breakGlassPanel() {
  const status = el('p', { class: 'field__hint', role: 'status', 'aria-live': 'polite' });

  const token = el('input', {
    type: 'password',
    autocomplete: 'off',
    autocapitalize: 'none',
    spellcheck: 'false',
    // Guards a paste of a whole file rather than enforcing the router's limit,
    // which is the router's to enforce and which it reports precisely.
    maxlength: '4096',
  });
  const reason = el('input', {
    type: 'text',
    autocomplete: 'off',
    spellcheck: 'false',
    maxlength: String(BREAK_GLASS_REASON_MAX),
  });

  const submit = actionButton('Open a break-glass session', signIn, {
    tone: 'danger',
    busyLabel: 'Signing in…',
  });

  const form = el('form', { novalidate: true }, [
    field({
      id: 'break-glass-token',
      label: 'Break-glass token',
      hint: 'The token printed once by --generate-secrets. The router holds only a verifier, so a lost token cannot be recovered or reissued.',
      control: token,
    }),
    field({
      id: 'break-glass-reason',
      label: 'Reason',
      hint: `Required, ${BREAK_GLASS_REASON_MIN} to ${BREAK_GLASS_REASON_MAX} characters, and recorded in the audit chain. This is what a later review reads.`,
      control: reason,
    }),
    buttonRow([submit]),
    status,
  ]);

  // Same shape as the key-creation form: the button is `type="button"`, so the
  // Enter key routes through the one guarded handler rather than a second code
  // path that is not disabled while a sign-in is in flight.
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    submit.click();
  });

  const element = card('Break-glass access', [
    el('p', {
      class: 'page-lede',
      text:
        'The preprovisioned recovery path of specification 22.4. It does not involve the identity provider, which is the point of it: this is the sign-in that still works when the provider does not, and the only one that carries permission to mint an API key.',
    }),
    banner(
      'warn',
      'A break-glass session is time-limited, emits a critical alert on sign-in and on sign-out, and is recorded with your reason for a mandatory review. Use it to recover access or to enrol an ordinary administrator — not as a daily sign-in.',
    ),
    form,
  ]);
  element.hidden = true;

  return { element, reveal };

  /** Show the panel, optionally saying what brought the operator here. */
  function reveal(note) {
    element.hidden = false;
    if (note) {
      status.textContent = note;
    }
    token.focus();
  }

  /** Validate locally, sign in, and enter the application. */
  async function signIn() {
    status.textContent = '';

    const tokenValue = token.value;
    if (tokenValue === '') {
      status.textContent = 'The break-glass token is required.';
      token.focus();
      return;
    }

    const reasonValue = reason.value.trim();
    if (
      reasonValue.length < BREAK_GLASS_REASON_MIN ||
      reasonValue.length > BREAK_GLASS_REASON_MAX
    ) {
      status.textContent = `A reason of ${BREAK_GLASS_REASON_MIN} to ${BREAK_GLASS_REASON_MAX} characters is required, and it is recorded.`;
      reason.focus();
      return;
    }

    try {
      await api.breakGlassSignIn(tokenValue, reasonValue);
    } catch (error) {
      // Reported here rather than raised to the shell's error boundary: on this
      // screen the boundary's own answer to a 401 is to render the sign-in
      // screen, which is where the operator already is.
      status.textContent = describe(error);
      return;
    }

    // Cleared as soon as it has been spent. The value is still in the browser's
    // memory until this node is collected, but leaving it in a live input is a
    // copy that survives on screen for the whole session.
    token.value = '';
    reason.value = '';

    await start();

    // Raised after `start`, not before: `route` dismisses the banner as it
    // mounts the first screen, so a notice raised here would flash and vanish.
    // Specification 9.3 wants it to be impossible to forget you are in a
    // break-glass session — the header pill says so for the whole session, and
    // this says it once on the way in.
    notify(
      'warn',
      'Break-glass session open. It is time-limited and separately audited; sign out when the work is done.',
    );
  }
}

/**
 * The signed-out screen.
 *
 * @param {string} [message]
 */
function renderSignIn(message) {
  runCleanup();
  api.abort();
  state.current = null;
  state.session = null;
  state.mounted = false;
  replace(shell.nav, []);
  state.navLinks = new Map();
  renderFacts();
  document.title = 'Sign in · HypeLLM Router';
  shell.view.setAttribute('aria-busy', 'false');

  const status = el('p', { class: 'page-lede' }, [
    'The management interface requires a signed-in principal. ',
    'Sign-in is delegated to the configured identity provider, or to a local account on a ',
    'deployment that has not configured one yet.',
  ]);

  const password = passwordPanel();
  const breakGlass = breakGlassPanel();

  const button = el('button', { type: 'button', class: 'button' }, 'Sign in with Google');
  button.addEventListener('click', () => {
    button.disabled = true;
    const { path } = currentRoute();
    // The return path is an in-application route, and the router sanitizes it
    // again on arrival (`sanitize_return_path`); sending anything absolute
    // would be an open-redirect attempt against ourselves.
    const returnPath = path && path.startsWith('/') ? path : '/';
    api
      .beginSignIn(returnPath)
      .then((url) => {
        if (typeof url !== 'string' || url === '') {
          throw new Error('the router did not return an authorization endpoint');
        }
        // The destination is the fixed authorization URL the router was
        // configured with (specification 16); it is not assembled here and no
        // part of it comes from the address bar.
        location.assign(url);
      })
      .catch((error) => {
        button.disabled = false;
        // 404 here is not a fault: it is `oidc_start` reporting that this
        // deployment configured no identity provider, which is the supported
        // air-gapped profile rather than a misconfiguration. Saying only
        // "sign-in is not configured" leaves the operator with no next step,
        // and the next step is the panel directly below.
        if (error instanceof ApiError && error.status === 404) {
          breakGlass.reveal(
            'This router has no identity provider configured, so Google sign-in cannot start. Sign in with a local account above, or use break-glass.',
          );
          notify('warn', 'No identity provider is configured on this router.');
          return;
        }
        notify('error', describe(error));
      });
  });

  const reveal = el('button', { type: 'button', class: 'button button--quiet' }, 'Use break-glass access');
  reveal.addEventListener('click', () => {
    reveal.disabled = true;
    breakGlass.reveal();
  });

  render(shell.view, [
    pageHeader('HypeLLM Router', 'Management interface'),
    card('Sign in', [status, buttonRow([button, reveal])]),
    password.element,
    breakGlass.element,
  ]);

  if (message) {
    notify('warn', message);
  } else {
    dismissBanner();
  }
}

/** A signed-in principal whose role grants no screen at all. */
function renderNoAccess() {
  state.current = null;
  markCurrent(null);
  shell.view.setAttribute('aria-busy', 'false');
  render(shell.view, [
    pageHeader('No accessible screens', 'The session is valid but holds no permissions.'),
    card(
      'Nothing to show',
      el('p', {
        class: 'empty',
        text:
          'This principal is signed in but holds no permission that grants access to a management screen. An administrator must grant a role before anything appears here.',
      }),
    ),
  ]);
}

/** A start-up failure that is not a missing session. */
function renderStartupFailure(error) {
  shell.view.setAttribute('aria-busy', 'false');
  const retry = el('button', { type: 'button', class: 'button' }, 'Try again');
  retry.addEventListener('click', () => {
    retry.disabled = true;
    void start();
  });
  render(shell.view, [
    pageHeader('Cannot reach the router', 'The management API did not answer.'),
    card('Session', [
      el('p', { class: 'page-lede', text: describe(error) }),
      buttonRow([retry]),
    ]),
  ]);
}

/** Load the session and show the first screen. */
async function start() {
  shell.view.setAttribute('aria-busy', 'true');
  try {
    state.session = await api.session();
  } catch (error) {
    if (error instanceof ApiError && error.needsSignIn) {
      renderSignIn();
      return;
    }
    if (error && error.name === 'AbortError') {
      return;
    }
    state.session = null;
    renderFacts();
    renderStartupFailure(error);
    return;
  }

  renderFacts();
  renderNav();
  await route();
}

// ------------------------------------------------------------------- wiring -

window.addEventListener('hashchange', () => {
  void route();
});

shell.bannerDismiss.addEventListener('click', () => {
  dismissBanner();
});

shell.signOut.addEventListener('click', () => {
  shell.signOut.disabled = true;
  api
    .logout()
    .catch(() => {
      // A failed sign-out is still a sign-out from this browser's point of
      // view: the local session state is dropped either way, and leaving the
      // operator apparently signed in would be the more dangerous mistake.
    })
    .then(() => {
      shell.signOut.disabled = false;
      renderSignIn('Signed out.');
    });
});

// The boundary of last resort. A rejected promise from a button handler — the
// common shape for a mutation that failed — has no `try` around it; without
// this it would reach the console and nowhere else.
window.addEventListener('unhandledrejection', (event) => {
  if (handleError(event.reason)) {
    event.preventDefault();
  }
});

window.addEventListener('error', (event) => {
  if (event.error) {
    handleError(event.error);
  }
});

void start();
