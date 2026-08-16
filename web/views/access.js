/**
 * Users & access.
 *
 * Specification 15.3: "Google-linked identities, service principals, roles,
 * status, sessions."
 *
 * All five now exist. `GET /admin/v1/access` (`list_access`) answers with the
 * caller's `tenant` plus four arrays — `identities`, `service_principals`,
 * `groups`, `sessions` — every one of them filtered to that tenant by the
 * handler, and every one of them free of anything replayable: a service
 * principal is identified by its key's public prefix and never its secret, and
 * a session by a short digest of the cookie rather than the cookie.
 *
 * Four decisions here are worth explaining:
 *
 * - **Every value on this screen reaches the DOM as a text node.** That is the
 *   rule for the whole application (`dom.js`), but it is load-bearing here in a
 *   way it is not on, say, the usage screen: principal identifiers, group
 *   members, descriptions, and above all email addresses arrive from an
 *   identity provider and from configuration written by people. This is the
 *   screen where a string concatenated into markup would be the admin-console
 *   cross-site scripting, so nothing on it is built from a string.
 * - **The screen is read-only, because the endpoint is.** Identities, groups,
 *   and role bindings are *configuration*: they change through a policy draft
 *   and a publication (specification 15.4), not through this view. No edit
 *   control is offered for them, because there is no request behind it.
 * - **Two capabilities are still absent and are named as absent.** There is no
 *   endpoint that revokes another principal's session, and none that creates or
 *   edits an identity. Both are reported through `notAvailable` rather than
 *   drawn as a control that would fail — a disabled "Revoke" button beside a
 *   session row would be read, during the incident where it matters, as a
 *   permission problem rather than as a missing feature.
 * - **The caller's own session is marked, not assumed.** `is_current` comes
 *   from the router comparing session digests. An operator reading a session
 *   list has to be able to tell which row is the chair they are sitting in
 *   before they act on any of the others.
 *
 * The operator summary at the foot of the screen is `ctx.session` — the shell's
 * copy, established at page load. It carries what `/access` deliberately does
 * not: the permission set this session holds, the configuration it is being
 * served, and whether it is a break-glass session. Its live timing (last seen,
 * expiry) is in the sessions table above it, from the router, on the row marked
 * as current.
 */

import { ApiError } from '../api.js';
import { el, formatDuration, formatTime, pill, replace, text } from '../components/dom.js';
import { buttonRow, card, grid, pageHeader, render, stat, table } from '../components/table.js';
import {
  actionButton,
  confirmPrompt,
  definitionList,
  notAvailable,
  panel,
} from '../components/layout.js';

/** Screen metadata, read by the router to build navigation. */
export const meta = {
  path: '/access',
  title: 'Users & access',
  lede: 'Who can reach this tenant, what authenticates them, and which sessions are live right now.',
  // `list_access` calls `require(session, Permission::ManagePrincipals)`, so
  // this is the permission the screen claims. There is no read-only variant of
  // it: a principal who cannot manage principals cannot list them either.
  permission: 'manage_principals',
};

/**
 * Render the screen.
 *
 * @param {HTMLElement} container  Empty element to render into.
 * @param {object} ctx
 * @param {import('../api.js').Api} ctx.api
 * @param {object} ctx.session      The /admin/v1/session body.
 * @param {(path: string) => void} ctx.navigate
 * @param {(tone: string, message: string) => void} ctx.notify   tone: 'ok' | 'warn' | 'error'
 * @param {(permission: string) => boolean} ctx.can
 * @returns {Promise<void|(() => void)>}  Optional cleanup called on navigation away.
 */
export async function mount(container, ctx) {
  /** Set by cleanup: nothing may touch the DOM after the screen is gone. */
  let disposed = false;

  const header = pageHeader(meta.title, meta.lede);

  // The load happens before anything is rendered, so the shell's "Loading…"
  // line and `aria-busy` cover it without this screen implementing either.
  let access;
  try {
    access = await fetchAccess(ctx.api);
  } catch (error) {
    if (error && error.name === 'AbortError') {
      return;
    }
    if (error instanceof ApiError && error.needsReauthentication) {
      // `ManagePrincipals::requires_reauthentication` is true, so a session that
      // is otherwise valid can be refused here. That is a specific, recoverable
      // condition and is rendered as one rather than as a generic fault.
      render(container, [header, reauthenticationRequired(ctx)]);
      return;
    }
    // A screen-specific failure state rather than the shell's bare banner: the
    // operator needs somewhere to retry from, and an empty page under an error
    // message reads as a broken application rather than as a failed request.
    render(container, [header, loadFailure(ctx, error)]);
    ctx.notify('error', `The access list could not be loaded: ${describeBriefly(error)}`);
    return;
  }

  // Regions the screen repaints in place on a refresh. Keeping them separate is
  // what lets one re-read update four tables without disturbing the confirmation
  // prompt or the operator's scroll position.
  const summaryHost = el('div');
  const identityHost = el('div');
  const principalHost = el('div');
  const groupHost = el('div');
  const sessionHost = el('div');
  const refreshStatus = el('p', {
    class: 'status-line',
    role: 'status',
    'aria-live': 'polite',
  });

  /**
   * Paint every region from one `/access` body.
   *
   * @param {object} body The `GET /admin/v1/access` response.
   */
  function renderAll(body) {
    const identities = arrayOf(body.identities);
    const principals = arrayOf(body.service_principals);
    const groups = arrayOf(body.groups);
    const sessions = orderSessions(arrayOf(body.sessions));

    replace(summaryHost, summaryTiles(identities, principals, groups, sessions));
    replace(identityHost, identityTable(identities));
    replace(principalHost, principalTable(principals));
    replace(groupHost, groupTable(groups));
    replace(sessionHost, sessionTable(sessions));
  }

  renderAll(access);

  const refresh = actionButton(
    'Refresh',
    async () => {
      refreshStatus.textContent = '';
      let next;
      try {
        next = await fetchAccess(ctx.api);
      } catch (error) {
        if (error && error.name === 'AbortError') {
          return;
        }
        if (!disposed) {
          // The tables on screen are now of unknown age; say so where the
          // operator is looking, and still let the shell name the fault with
          // the router's request id.
          refreshStatus.textContent =
            'The refresh failed. What is shown below is the last answer the router gave.';
        }
        throw error;
      }
      if (disposed) {
        return;
      }
      renderAll(next);
      refreshStatus.textContent = `Re-read at ${formatTime(Date.now())}.`;
    },
    { tone: 'quiet', busyLabel: 'Refreshing…', title: 'Re-read the access list from the router' },
  );

  // The tenant is the scope of everything below it, and `list_access` filters
  // on exactly this value, so it is stated once at the top rather than repeated
  // as a caveat on each table.
  const summaryPanel = panel({
    title: `Tenant ${String(access.tenant || ctx.session.tenant || 'unknown')}`,
    note: 'Everything on this screen is scoped to this tenant. Identities, service principals, groups, and sessions belonging to any other tenant are not readable here and are not counted below.',
    actions: [refresh],
    content: [summaryHost, refreshStatus],
  });

  // ------------------------------------------------------------ identities -

  const identityContent = [
    identityHost,
    notAvailable(
      'Creating and editing identities',
      'An identity binds a Google account to a principal, and a role binding grants it authority. Both are configuration: they change through a policy draft and a publication, never from this screen.',
    ),
  ];

  // Only offered when the session could actually use the destination: pointing
  // an operator at a screen their role does not grant would bounce them back to
  // wherever the shell decides, which reads as a bug.
  if (ctx.can('edit_policy') || ctx.can('simulate_policy') || ctx.can('publish_policy')) {
    identityContent.push(
      el('p', { class: 'panel__note' }, [
        'Draft the change, simulate it, and publish it on the ',
        el('a', { href: '#/policies' }, 'Routing policies'),
        ' screen. A draft changes nothing until it is published.',
      ]),
    );
  }

  const identityPanel = panel({
    title: 'Google-linked identities',
    note: 'A person signs in through the identity provider; the issuer and subject pair is what the router matches, and the principal is what every policy decision and audit record then names.',
    content: identityContent,
  });

  // --------------------------------------------------- service principals --

  const principalContent = [principalHost];

  if (ctx.can('manage_keys')) {
    principalContent.push(
      el('p', { class: 'panel__note' }, [
        'Keys are issued, scoped, and revoked on the ',
        el('a', { href: '#/keys' }, 'API keys'),
        ' screen. A secret is shown once, at creation, and the router cannot produce it again.',
      ]),
    );
  }

  const principalPanel = panel({
    title: 'Service principals',
    note: 'Workloads authenticate to the inference path with a router API key. The identifier below is the key’s public prefix; the secret is not part of this response and cannot be read back.',
    content: principalContent,
  });

  // ---------------------------------------------------------------- groups -

  const groupPanel = panel({
    title: 'Groups',
    note: 'A group is who a group-scoped binding will match. Membership is configuration, and is shown here so that the effect of a binding can be read before it is published.',
    content: groupHost,
  });

  // -------------------------------------------------------------- sessions -

  const sessionActions = el('div', { class: 'button-row' });

  /**
   * Put the action row back in its idle state.
   *
   * @returns {HTMLElement} The idle button, so a caller cancelling a prompt can
   *   move focus onto it.
   */
  function resetSessionActions() {
    const end = actionButton(
      'End this session',
      () => {
        askToEnd();
      },
      { tone: 'danger', title: 'Invalidate this browser session on the router' },
    );
    replace(sessionActions, end);
    return end;
  }

  /**
   * Confirm before signing out.
   *
   * Ending a session is not destructive in the sense that a key revocation is —
   * signing in again restores it — so there is no phrase to type. It is still a
   * mutation, so nothing is drawn as done until the router has answered
   * (specification 15.4): the reload happens after `logout` resolves, never
   * before.
   */
  function askToEnd() {
    const prompt = confirmPrompt({
      message: 'End this management session?',
      detail:
        'The router invalidates the session immediately and this page returns to sign-in. The other sessions listed above are unaffected — and cannot be ended from here.',
      confirmLabel: 'End session',
      onConfirm: async () => {
        await ctx.api.logout();
        // The shell establishes the session at start-up, so the honest way to
        // show a session that no longer exists is to start up again: `start()`
        // re-reads `/session`, is told 401, and renders sign-in.
        location.reload();
      },
      onCancel: () => {
        const restored = resetSessionActions();
        // Focus was inside the prompt that is about to be removed; leaving it
        // on `<body>` would strand a keyboard operator at the top of the page.
        restored.focus();
      },
    });
    replace(sessionActions, prompt);
  }

  resetSessionActions();

  const sessionPanel = panel({
    title: 'Live sessions',
    note: 'Every management session open in this tenant. The identifier is a short digest the router derives from the session; it identifies a session without being usable as one.',
    content: [
      sessionHost,
      notAvailable(
        'Revoking another principal’s session',
        'No endpoint ends a session other than the caller’s own, so a session listed above stays live until it expires or its holder signs out. Only the session in this browser can be ended, below.',
      ),
      sessionActions,
    ],
  });

  // ------------------------------------------------------- this session ----

  const operatorPanel = panel({
    title: 'This session',
    note: 'What the shell was told when this page loaded. Its live timing — last seen, expiry — is on the row marked as this session above; reload the page to re-read the rest.',
    content: operatorFacts(ctx.session),
  });

  render(container, [
    header,
    summaryPanel,
    identityPanel,
    principalPanel,
    groupPanel,
    sessionPanel,
    operatorPanel,
  ]);

  return () => {
    disposed = true;
    // A confirmation left open belongs to a screen that no longer exists.
    replace(sessionActions, []);
  };
}

// ---------------------------------------------------------------- requests -

/**
 * Read the access view.
 *
 * @param {import('../api.js').Api} api
 * @returns {Promise<object>} The `/admin/v1/access` body.
 */
async function fetchAccess(api) {
  const { data } = await api.get('/access');
  return data;
}

/**
 * A field the router may have omitted, as an array.
 *
 * A screen that iterates whatever arrived would throw on a body that is missing
 * a section, and a thrown screen tells the operator nothing about which section
 * was missing. An empty array renders as the section's empty state instead.
 *
 * @param {unknown} value
 * @returns {object[]}
 */
function arrayOf(value) {
  return Array.isArray(value) ? value : [];
}

/**
 * A value the router may have omitted, as a node.
 *
 * The difference between "the router reported nothing" and "the screen forgot
 * to render it" should never be invisible, so an absent value is an em dash.
 *
 * @param {unknown} value
 * @returns {Node}
 */
function orDash(value) {
  return value === null || value === undefined || value === '' ? text('—') : text(String(value));
}

/**
 * Identifier text, monospaced.
 *
 * @param {unknown} value
 * @returns {HTMLElement}
 */
function mono(value) {
  return el('code', { class: 'mono', text: String(value === undefined ? '' : value) });
}

/**
 * A wrapping row of role or scope pills.
 *
 * @param {unknown} values
 * @param {string} absent What it means for the list to be empty.
 * @returns {Node}
 */
function pillRow(values, absent) {
  const list = arrayOf(values);
  if (list.length === 0) {
    return el('span', { class: 'field__hint', text: absent });
  }
  return el(
    'div',
    { class: 'pill-row' },
    list.map((value) => pill(String(value))),
  );
}

// ---------------------------------------------------------------- sections -

/**
 * Order the session list.
 *
 * The caller's own session first, then the most recently seen. Both are
 * reversible view state, which specification 15.4 permits the client to decide;
 * the rows themselves are exactly what the router returned.
 *
 * @param {object[]} sessions
 * @returns {object[]}
 */
function orderSessions(sessions) {
  return [...sessions].sort((a, b) => {
    const current = Number(Boolean(b.is_current)) - Number(Boolean(a.is_current));
    if (current !== 0) {
      return current;
    }
    return millis(b.last_seen) - millis(a.last_seen);
  });
}

/** @param {unknown} value @returns {number} */
function millis(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

/**
 * The four counts, so the shape of the tenant is readable before the tables are.
 *
 * @param {object[]} identities
 * @param {object[]} principals
 * @param {object[]} groups
 * @param {object[]} sessions
 * @returns {HTMLElement}
 */
function summaryTiles(identities, principals, groups, sessions) {
  const revoked = principals.filter((row) => row.status === 'revoked').length;
  const active = principals.length - revoked;
  const current = sessions.filter((row) => row.is_current).length;

  return grid([
    stat('Identities', identities.length, 'Google accounts bound to a principal'),
    stat(
      'Service principals',
      principals.length,
      `${active} active, ${revoked} revoked`,
    ),
    stat('Groups', groups.length, 'Subjects a group-scoped binding can match'),
    stat(
      'Live sessions',
      sessions.length,
      current === 1 ? 'Including this one' : 'This session is not among them',
    ),
  ]);
}

/**
 * Google-linked identities.
 *
 * @param {object[]} rows
 * @returns {HTMLElement}
 */
function identityTable(rows) {
  return table({
    caption: `Identities — ${countOf(rows.length, 'identity', 'identities')}`,
    columns: [
      { label: 'Principal', cell: (row) => mono(row.principal) },
      { label: 'Issuer', cell: (row) => mono(row.issuer) },
      { label: 'Subject', cell: (row) => mono(row.subject) },
      {
        label: 'Roles',
        cell: (row) => pillRow(row.roles, 'No role is bound to this principal.'),
      },
      { label: 'Description', cell: (row) => orDash(row.description) },
    ],
    rows,
    empty:
      'No Google-linked identity is bound to a principal in this tenant. Nobody can sign in to the management interface here until an identity record is published.',
  });
}

/**
 * Service principals — one row per API key issued in this tenant.
 *
 * @param {object[]} rows
 * @returns {HTMLElement}
 */
function principalTable(rows) {
  const now = Date.now();
  return table({
    caption: `Service principals — ${countOf(rows.length, 'key', 'keys')}`,
    columns: [
      { label: 'Key', cell: (row) => mono(row.key_id) },
      { label: 'Principal', cell: (row) => mono(row.principal) },
      { label: 'Status', cell: (row) => statusCell(row, now) },
      { label: 'Scopes', cell: (row) => pillRow(row.scopes, 'No scope: this key authorizes nothing.') },
      { label: 'Created', cell: (row) => text(formatTime(row.created_at)) },
      { label: 'Expires', cell: (row) => text(row.expires_at ? formatTime(row.expires_at) : 'No expiry') },
      { label: 'Description', cell: (row) => orDash(row.description) },
    ],
    rows,
    empty:
      'No service principal holds a key in this tenant. Nothing but a signed-in operator can reach the inference path here.',
  });
}

/**
 * The status of one key.
 *
 * `status` is the router's own field and is rendered as it stands. The expiry
 * pill beside it is derived — from the router's timestamp, but against *this
 * browser's* clock, which is why it is worded as an observation and carries the
 * caveat in its tooltip rather than being drawn as a second authoritative
 * status.
 *
 * @param {object} row
 * @param {number} now
 * @returns {Node}
 */
function statusCell(row, now) {
  if (row.status === 'revoked') {
    return pill('Revoked', 'danger');
  }

  const pills = [pill('Active', 'ok')];
  if (typeof row.expires_at === 'number' && row.expires_at <= now) {
    const expired = pill('Past expiry', 'warn');
    expired.title = 'The expiry the router reported is in the past according to this browser’s clock.';
    pills.push(expired);
  }
  if (pills.length === 1) {
    return pills[0];
  }
  return el('div', { class: 'pill-row' }, pills);
}

/**
 * Groups and their members.
 *
 * @param {object[]} rows
 * @returns {HTMLElement}
 */
function groupTable(rows) {
  return table({
    caption: `Groups — ${countOf(rows.length, 'group', 'groups')}`,
    columns: [
      { label: 'Group', cell: (row) => mono(row.id) },
      { label: 'Members', cell: (row) => memberCell(row.members) },
      { label: 'Description', cell: (row) => orDash(row.description) },
    ],
    rows,
    empty:
      'No group is defined in this tenant. A group-scoped binding would match nobody here; bindings are made to principals directly.',
  });
}

/**
 * The members of one group.
 *
 * Rendered as separate monospaced nodes joined by punctuation text, not as one
 * joined string: a member identifier is configuration written by a person, and
 * every one of them belongs in a text node of its own.
 *
 * @param {unknown} members
 * @returns {Node}
 */
function memberCell(members) {
  const list = arrayOf(members);
  if (list.length === 0) {
    return el('span', { class: 'field__hint', text: 'No members: this group matches nobody.' });
  }
  return el(
    'div',
    {},
    list.flatMap((member, index) => (index === 0 ? [mono(member)] : [text(', '), mono(member)])),
  );
}

/**
 * Live management sessions.
 *
 * @param {object[]} rows
 * @returns {HTMLElement}
 */
function sessionTable(rows) {
  return table({
    caption: `Live sessions — ${countOf(rows.length, 'session', 'sessions')}`,
    columns: [
      { label: 'Session', cell: (row) => sessionCell(row) },
      { label: 'Principal', cell: (row) => principalCell(row) },
      { label: 'Method', cell: (row) => mono(row.auth_method) },
      { label: 'Roles', cell: (row) => pillRow(row.roles, 'No role: this session can do nothing.') },
      { label: 'Started', cell: (row) => text(formatTime(row.created_at)) },
      { label: 'Last seen', cell: (row) => text(formatTime(row.last_seen)) },
      { label: 'Expires', cell: (row) => text(formatTime(row.expires_at)) },
    ],
    rows,
    // Unreachable in practice — the caller's own session is in this list, which
    // is how the row marked `is_current` gets there — so reaching it means the
    // response and the request disagree about who is asking.
    empty:
      'The router reported no live session in this tenant, not even the one reading this screen. That should not be possible; reload the page, and treat it as a fault if it persists.',
  });
}

/**
 * The session identifier, with the caller's own session marked.
 *
 * @param {object} row
 * @returns {Node}
 */
function sessionCell(row) {
  const id = mono(row.id);
  if (!row.is_current) {
    return id;
  }
  // Marked rather than merely sorted first: an operator about to act on a
  // session list has to be able to see which row is their own.
  return el('div', { class: 'pill-row' }, [id, pill('This session', 'ok')]);
}

/**
 * Who holds a session: the principal, with the provider's address beneath it.
 *
 * @param {object} row
 * @returns {Node}
 */
function principalCell(row) {
  const principal = mono(row.principal);
  if (!row.email) {
    return principal;
  }
  // The address is an attribute shown for recognition, not the identity key —
  // the router matches on issuer and subject — so it is secondary here too.
  return el('div', {}, [principal, el('div', { class: 'field__hint', text: String(row.email) })]);
}

/**
 * The caller's own session, from the shell's copy of `/admin/v1/session`.
 *
 * This is the part of "who am I and what may I do" that `/access` deliberately
 * does not carry: the permission set, the configuration being served, and
 * whether this is a break-glass session.
 *
 * @param {object} session
 * @returns {HTMLElement}
 */
function operatorFacts(session) {
  const permissions = [...arrayOf(session.permissions)].map(String).sort();

  const authenticatedAt = session.authenticated_at;
  const elapsed = typeof authenticatedAt === 'number' ? Date.now() - authenticatedAt : Number.NaN;
  const authenticated =
    Number.isFinite(elapsed) && elapsed >= 0
      ? `${formatTime(authenticatedAt)} (${formatDuration(elapsed)} ago)`
      : formatTime(authenticatedAt);

  const version = session.config_version;
  const digest = session.config_digest || '—';

  return definitionList([
    ['Principal', mono(session.principal || '')],
    ['Tenant', mono(session.tenant || '')],
    // The field is omitted entirely when the identity provider sent no address,
    // which is a different fact from "the address is blank".
    ['Email', session.email || 'Not reported by the identity provider.'],
    ['Authentication method', mono(session.auth_method || '')],
    ['Roles', pillRow(session.roles, 'No role is bound to this principal.')],
    ['Authenticated', authenticated],
    ['Break glass', session.break_glass ? pill('Active', 'danger') : text('Not active.')],
    ['Active configuration', version === undefined ? digest : `v${version} · ${digest}`],
    [
      'Permissions',
      pillRow(
        permissions,
        'This session carries no permission, so no management action is authorized for it.',
      ),
    ],
  ]);
}

/**
 * "3 groups", "1 identity".
 *
 * @param {number} count
 * @param {string} one
 * @param {string} many
 * @returns {string}
 */
function countOf(count, one, many) {
  return `${count} ${count === 1 ? one : many}`;
}

// --------------------------------------------------------------- failures --

/**
 * One line naming a failure, for the shell's notification channel.
 *
 * `app.js` formats errors it catches; this one was caught here, so it needs the
 * same treatment — above all the request id, which is the only handle tying
 * what the operator saw to the router's logs (specification 17).
 *
 * @param {unknown} error
 * @returns {string}
 */
function describeBriefly(error) {
  if (error instanceof ApiError) {
    const parts = [error.message];
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
  return 'the router did not answer';
}

/**
 * The session is valid but not fresh enough for this screen.
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
      text: 'Reading who may reach this tenant is a sensitive action, so the router requires an authentication newer than this session has. Nothing has failed and nothing has changed; sign in again to see the access list.',
    }),
    buttonRow([again]),
  ]);
}

/**
 * The access list could not be read.
 *
 * @param {object} ctx
 * @param {unknown} error
 * @returns {HTMLElement}
 */
function loadFailure(ctx, error) {
  const retry = actionButton(
    'Try again',
    () => {
      // Re-navigating to the current route re-runs `mount` from a clean state,
      // which is exactly what a retry means here.
      ctx.navigate(meta.path);
    },
    { tone: 'quiet' },
  );

  return card('The access list could not be loaded', [
    el('p', { class: 'page-lede', text: describeBriefly(error) }),
    el('p', {
      class: 'field__hint',
      text: 'Nothing has changed as a result of this failure. Nothing is shown below rather than a stale or partial list of who can reach this tenant — a half-rendered access list is worse than none.',
    }),
    buttonRow([retry]),
  ]);
}
