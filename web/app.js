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
import { buttonRow, card, pageHeader, render } from './components/table.js';

// The enumeration. Order is the navigation order, and it follows the reading
// order of specification 15.3 rather than alphabetical: what is running, what
// it is running on, how it is routed, who may use it, what it cost, and what
// happened.
import * as overview from './views/overview.js';
import * as targets from './views/targets.js';
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
    'Sign-in is delegated to the configured identity provider; this application never handles a password.',
  ]);

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
        notify('error', describe(error));
      });
  });

  render(shell.view, [
    pageHeader('HypeLLM Router', 'Management interface'),
    card('Sign in', [status, buttonRow([button])]),
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
