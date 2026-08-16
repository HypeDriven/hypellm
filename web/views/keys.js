/**
 * The API keys screen.
 *
 * Specification 15.3: "Create once, scope, expiry, last-used metadata, revoke;
 * secret never displayed again." Specification 16: `POST /admin/v1/keys` returns
 * a one-time secret and `DELETE /admin/v1/keys/{id}` revokes immediately.
 *
 * Four decisions here are worth explaining, because each of them is a place
 * where the obvious implementation would be wrong:
 *
 * - **The secret is handled as a value that exists once.** It arrives in the
 *   creation response, is put into exactly one text node by `secretOnce`, and is
 *   never written to a URL, the history, storage, or a log. It is not kept in a
 *   variable that outlives the screen: the cleanup function empties the region,
 *   so navigating away destroys it. The router genuinely cannot produce it
 *   again — `create_key` returns `new_key.into_secret()` and stores only a
 *   keyed verifier — so a screen that implied otherwise would be lying about
 *   the one thing an operator must act on immediately.
 * - **Nothing is painted before the router confirms it.** Specification 15.4
 *   permits optimistic UI "only for reversible view state". The status filter
 *   and the search box are exactly that and update instantly; creation and
 *   revocation re-read the list from the router and render what it returned. A
 *   row that shows "Revoked" here has been revoked *there*.
 * - **Revocation is confirmed by typing the key id.** It cannot be undone, and
 *   the workload holding the key stops authenticating on its next request. The
 *   phrase is the key id rather than a generic word so that confirming the
 *   wrong row requires typing the wrong row's identifier.
 * - **`manage_keys` requires a recent authentication** (`Permission::
 *   requires_reauthentication` in `hypellm-core::rbac`), and that applies to the
 *   *listing* as well as the mutations. A stale session therefore fails this
 *   screen at load with `reauthentication_required`, which is a specific,
 *   recoverable condition and is rendered as one instead of as a generic fault.
 *
 * Two capabilities specification 15.3 names are absent from the management API
 * as it stands, and are reported as absent rather than approximated: last-used
 * metadata is not recorded on `KeyRecord`, and neither source restriction nor
 * management roles are settable through `POST /admin/v1/keys`.
 */

import { ApiError } from '../api.js';
import { el, formatTime, pill, replace } from '../components/dom.js';
import { buttonRow, card, field, pageHeader, render, table } from '../components/table.js';
import {
  actionButton,
  confirmPrompt,
  definitionList,
  inlineField,
  morePager,
  notAvailable,
  panel,
  secretOnce,
  toolbar,
} from '../components/layout.js';

/** Screen metadata, read by the router to build navigation. */
export const meta = {
  path: '/keys',
  title: 'API keys',
  lede: 'Issue scoped router keys, see what is outstanding, and revoke immediately.',
  // `list_keys`, `create_key`, and `revoke_key` all call
  // `require(session, Permission::ManageKeys)`. There is no read-only view of
  // this screen: a principal who cannot manage keys cannot list them either.
  permission: 'manage_keys',
};

/**
 * The scopes the router accepts.
 *
 * Hard-coded because no endpoint enumerates them; the authority is
 * `hypellm_auth::Scope`, and `create_key` rejects anything it cannot parse. That
 * makes drift loud — a scope this list gains and the router does not is a
 * rejected creation with the offending name in the error — which is the right
 * failure for a security control. A free-text field would instead let a typo
 * become a key with the wrong authority.
 */
const SCOPES = [
  { name: 'inference', hint: 'Chat and responses.' },
  { name: 'embeddings', hint: 'Embedding requests.' },
  { name: 'models', hint: 'Model and alias discovery.' },
  { name: 'tokenize', hint: 'Tokenisation.' },
  { name: 'management:read', hint: 'Read-only management access.' },
  { name: 'management:write', hint: 'Write management access.' },
];

/**
 * What `PrincipalId::new` accepts: ASCII alphanumerics plus `. _ - :`, at most
 * `MAX_ID_LEN` bytes. Checked here so an obvious mistake is named next to the
 * field instead of returning as a generic invalid-request banner.
 */
const PRINCIPAL_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

/**
 * Render the screen.
 *
 * @param {HTMLElement} container  Empty element to render into.
 * @param {object} ctx
 * @param {import('../api.js').Api} ctx.api
 * @param {object} ctx.session
 * @param {(path: string) => void} ctx.navigate
 * @param {(tone: string, message: string) => void} ctx.notify
 * @param {string} ctx.path
 * @returns {Promise<void|(() => void)>}
 */
export async function mount(container, ctx) {
  const state = {
    /** @type {object[]} Every key row loaded so far. */
    rows: [],
    /** @type {object|null} The most recent list envelope, for its cursor. */
    envelope: null,
    /** 'all' | 'active' | 'revoked' */
    status: 'all',
    /** Free-text filter over id, principal, and description. */
    search: '',
    /** Set by cleanup: nothing may touch the DOM after the screen is gone. */
    disposed: false,
  };

  const header = pageHeader(meta.title, meta.lede);

  // The load happens before anything is rendered, so the shell's "Loading…"
  // line and `aria-busy` cover it without this screen implementing either.
  let envelope;
  try {
    envelope = await fetchKeys(ctx.api);
  } catch (error) {
    if (error && error.name === 'AbortError') {
      return;
    }
    if (error instanceof ApiError && error.needsReauthentication) {
      render(container, [header, reauthenticationRequired(ctx)]);
      return;
    }
    // A screen-specific failure state rather than the shell's bare banner: the
    // operator needs somewhere to retry from, and an empty page under an error
    // message reads as a broken application rather than a failed request.
    render(container, [header, loadFailure(ctx, error)]);
    ctx.notify('error', 'The key list could not be loaded.');
    return;
  }

  adopt(state, envelope, true);

  // Regions the screen updates in place. Keeping them separate is what lets a
  // list refresh leave a freshly issued secret on screen, and lets the secret
  // be destroyed on navigation without disturbing anything else.
  const secretRegion = el('div');
  const confirmRegion = el('div');
  const tableRegion = el('div');

  const form = createForm(ctx, state, { secretRegion, onCreated: refresh });
  const filters = filterBar(state, renderTable);

  const refreshButton = actionButton('Refresh', refresh, {
    tone: 'quiet',
    busyLabel: 'Refreshing…',
    title: 'Re-read the key list from the router',
  });

  render(container, [
    header,
    secretRegion,
    form.element,
    panel({
      title: 'Issued keys',
      note: `Keys belonging to tenant ${String(ctx.session.tenant || 'unknown')}. Revoked keys stay listed so that a revocation remains visible.`,
      actions: [refreshButton],
      content: [filters, confirmRegion, tableRegion],
    }),
    card(
      'Not shown here',
      notAvailable(
        'Last-used metadata',
        'The router does not record a last-use time on a key record, so this screen cannot show one. Creation and revocation are in the audit log; traffic attribution is on the usage screen.',
      ),
    ),
  ]);

  renderTable();

  return () => {
    state.disposed = true;
    // The one-time secret dies with the screen. Nothing else holds it: it was
    // never assigned to module state, and the closure that captured it goes
    // with these nodes.
    replace(secretRegion, []);
    replace(confirmRegion, []);
  };

  // ------------------------------------------------------------- behaviour -

  /** Re-read the list and repaint the table. Never optimistic. */
  async function refresh() {
    let next;
    try {
      next = await fetchKeys(ctx.api);
    } catch (error) {
      if (error && error.name === 'AbortError') {
        return;
      }
      throw error;
    }
    if (state.disposed) {
      return;
    }
    adopt(state, next, true);
    renderTable();
  }

  /**
   * Append the next page.
   *
   * The router does not paginate keys today — `list_keys` answers with no
   * cursor — so this control never appears. It is wired anyway because the
   * failure mode if it ever does paginate is a silently truncated list of
   * credentials, which is precisely the list that must not be truncated
   * silently.
   *
   * @param {string} cursor
   */
  async function loadMore(cursor) {
    const next = await fetchKeys(ctx.api, cursor);
    if (state.disposed) {
      return;
    }
    adopt(state, next, false);
    renderTable();
  }

  /** Paint the table from `state`. */
  function renderTable() {
    const rows = visibleRows(state);
    const total = state.rows.length;
    const caption =
      rows.length === total
        ? `${total} key${total === 1 ? '' : 's'}`
        : `${rows.length} of ${total} keys shown`;

    replace(tableRegion, [
      table({
        caption: `API keys — ${caption}`,
        columns: columns(askRevoke),
        rows,
        empty: emptyMessage(state),
      }),
      morePager(state.envelope, loadMore),
    ]);
  }

  /**
   * Ask before revoking.
   *
   * @param {object} row
   * @param {HTMLElement} trigger The button that opened the prompt.
   */
  function askRevoke(row, trigger) {
    replace(
      confirmRegion,
      confirmPrompt({
        message: `Revoke key ${row.id}, used by principal ${row.principal}?`,
        detail:
          'Revocation is immediate and cannot be undone; it does not wait for a configuration publication. Any client presenting this key stops authenticating on its next request, so issue a replacement first if the workload must keep running.',
        confirmLabel: 'Revoke this key',
        // Typing the id, not a generic word: confirming the wrong row should
        // require typing the wrong row's identifier.
        phrase: row.id,
        onConfirm: () => revoke(row),
        onCancel: () => {
          replace(confirmRegion, []);
          // Focus goes back where it came from rather than to the top of the
          // document, so a keyboard operator resumes at the row they left.
          if (trigger.isConnected) {
            trigger.focus();
          }
        },
      }),
    );
  }

  /** @param {object} row */
  async function revoke(row) {
    try {
      // No `If-Match`: `revoke_key` guards on nothing but tenant ownership and
      // the router publishes no ETag for a key record. Sending a precondition
      // the router does not check would be theatre, and specification 15.4 asks
      // for `If-Match` where the resource is versioned, which this is not.
      await ctx.api.delete(`/keys/${encodeURIComponent(row.id)}`);
    } catch (error) {
      if (error instanceof ApiError && error.needsReauthentication) {
        ctx.notify(
          'error',
          'Revoking a key needs a recent sign-in. Sign out and back in, then try again — the key has not been revoked.',
        );
        return;
      }
      throw error;
    }
    if (state.disposed) {
      return;
    }
    replace(confirmRegion, []);
    ctx.notify('ok', `Key ${row.id} is revoked.`);
    // The confirmation the operator was focused on has just been removed, so
    // focus is placed deliberately instead of falling back to the document.
    if (refreshButton.isConnected) {
      refreshButton.focus();
    }
    await refresh();
  }
}

// ---------------------------------------------------------------- requests -

/**
 * Read the key list.
 *
 * @param {import('../api.js').Api} api
 * @param {string} [cursor]
 * @returns {Promise<object>} The list envelope.
 */
async function fetchKeys(api, cursor) {
  const query = cursor ? `?after=${encodeURIComponent(cursor)}&limit=100` : '';
  const { data } = await api.get(`/keys${query}`);
  return data;
}

/**
 * Take a list envelope into `state`.
 *
 * @param {object} state
 * @param {object} envelope
 * @param {boolean} fresh Whether this replaces the rows or extends them.
 */
function adopt(state, envelope, fresh) {
  const data = Array.isArray(envelope && envelope.data) ? envelope.data : [];
  state.rows = fresh ? data : state.rows.concat(data);
  state.envelope = envelope;
}

// ------------------------------------------------------------------- table -

/**
 * The columns of the key table.
 *
 * @param {(row: object, trigger: HTMLElement) => void} onRevoke
 * @returns {object[]}
 */
function columns(onRevoke) {
  return [
    {
      label: 'Key id',
      cell: (row) => el('span', { class: 'mono', text: String(row.id) }),
    },
    { label: 'Principal', cell: (row) => String(row.principal || '—') },
    { label: 'Description', cell: (row) => (row.description ? String(row.description) : '—') },
    {
      label: 'Scopes',
      cell: (row) => {
        const scopes = Array.isArray(row.scopes) ? row.scopes : [];
        if (scopes.length === 0) {
          // The router refuses to create one, so an empty set means a record
          // that predates that rule or was written by another path. Saying so
          // is more useful than an empty cell.
          return el('span', { class: 'empty', text: 'none — this key can do nothing' });
        }
        return el(
          'span',
          { class: 'button-row' },
          scopes.map((scope) => pill(String(scope))),
        );
      },
    },
    { label: 'Status', cell: (row) => statusPill(row) },
    { label: 'Created', cell: (row) => formatTime(row.created_at) },
    {
      label: 'Expires',
      cell: (row) =>
        row.expires_at === null || row.expires_at === undefined
          ? 'No expiry'
          : formatTime(row.expires_at),
    },
    {
      label: 'Action',
      cell: (row) => {
        if (row.revoked) {
          return el('span', { class: 'empty', text: 'Revoked' });
        }
        const button = actionButton(
          'Revoke',
          () => {
            onRevoke(row, button);
          },
          { tone: 'danger', title: `Revoke key ${row.id}` },
        );
        return button;
      },
    },
  ];
}

/**
 * How a key stands.
 *
 * Expiry is compared against *this browser's* clock, which is why an expired
 * key is labelled as such rather than treated as revoked: the router's clock is
 * the authority for whether the key still authenticates, and the two can
 * disagree. Revocation, which the router has recorded, takes precedence in the
 * display.
 *
 * @param {object} row
 * @returns {HTMLElement}
 */
function statusPill(row) {
  if (row.revoked) {
    return pill('Revoked', 'danger');
  }
  const expiry = row.expires_at;
  if (typeof expiry === 'number' && Number.isFinite(expiry) && expiry <= Date.now()) {
    return pill('Expired', 'warn');
  }
  return pill('Active', 'ok');
}

/**
 * Rows after the view filters.
 *
 * @param {object} state
 * @returns {object[]}
 */
function visibleRows(state) {
  const needle = state.search.trim().toLowerCase();
  return state.rows.filter((row) => {
    if (state.status === 'active' && row.revoked) {
      return false;
    }
    if (state.status === 'revoked' && !row.revoked) {
      return false;
    }
    if (needle === '') {
      return true;
    }
    const haystack = [row.id, row.principal, row.description]
      .filter((value) => typeof value === 'string')
      .join(' ')
      .toLowerCase();
    return haystack.includes(needle);
  });
}

/**
 * Why the table is empty. An empty table that does not say why is
 * indistinguishable from a broken one.
 *
 * @param {object} state
 * @returns {string}
 */
function emptyMessage(state) {
  if (state.rows.length === 0) {
    return 'The router holds no API keys for this tenant. Every request to the inference listener must present one, so nothing can call the router until a key is issued above.';
  }
  return 'No key matches the current filters. Clear the search or set the status filter back to "All" to see the other keys.';
}

/**
 * The filter row. Pure view state, so it applies immediately (specification
 * 15.4 allows optimistic UI exactly here and nowhere else on this screen).
 *
 * @param {object} state
 * @param {() => void} onChange
 * @returns {HTMLElement}
 */
function filterBar(state, onChange) {
  const status = el('select', {}, [
    el('option', { value: 'all' }, 'All'),
    el('option', { value: 'active' }, 'Active only'),
    el('option', { value: 'revoked' }, 'Revoked only'),
  ]);
  status.value = state.status;
  status.addEventListener('change', () => {
    state.status = status.value;
    onChange();
  });

  const search = el('input', {
    type: 'text',
    autocomplete: 'off',
    spellcheck: 'false',
    placeholder: 'id, principal, or description',
  });
  search.addEventListener('input', () => {
    state.search = search.value;
    onChange();
  });

  return toolbar(
    [
      inlineField({ id: 'keys-filter-status', label: 'Status', control: status }),
      inlineField({ id: 'keys-filter-search', label: 'Search', control: search }),
    ],
    { label: 'Key filters' },
  );
}

// -------------------------------------------------------------- create form -

/**
 * The issue-a-key panel.
 *
 * @param {object} ctx
 * @param {object} state
 * @param {object} options
 * @param {HTMLElement} options.secretRegion Where the one-time secret is shown.
 * @param {() => Promise<void>} options.onCreated Refresh the list.
 * @returns {{element: HTMLElement}}
 */
function createForm(ctx, state, { secretRegion, onCreated }) {
  const principal = el('input', {
    type: 'text',
    autocomplete: 'off',
    spellcheck: 'false',
    required: true,
  });
  const description = el('input', { type: 'text', autocomplete: 'off' });
  const expiry = el('input', { type: 'date' });

  const boxes = new Map();
  const scopeItems = SCOPES.map((scope) => {
    const id = `key-scope-${scope.name.replace(/[^a-z]+/g, '-')}`;
    const input = el('input', {
      type: 'checkbox',
      id,
      value: scope.name,
      // The hint is associated rather than merely adjacent: a screen reader
      // should hear what `management:write` means at the moment of ticking it.
      'aria-describedby': `${id}-hint`,
    });
    boxes.set(scope.name, input);
    return el('div', { class: 'checkset__item' }, [
      input,
      el('label', { for: id }, scope.name),
      el('span', { class: 'checkset__hint', id: `${id}-hint`, text: scope.hint }),
    ]);
  });

  // A real `fieldset`/`legend`, so the group of checkboxes is announced as one
  // named control rather than as six unrelated ones.
  const scopeSet = el('fieldset', { class: 'checkset' }, [
    el('legend', { class: 'checkset__legend' }, 'Scopes'),
    el('p', {
      class: 'field__hint',
      text: 'At least one is required. The router issues keys with no management role, so a management scope alone grants no management permission.',
    }),
    ...scopeItems,
  ]);

  // Async status for the form: announced politely rather than shouted, because
  // most of what lands here is a validation message the operator just caused.
  const status = el('p', { class: 'field__hint', role: 'status', 'aria-live': 'polite' });

  const submit = actionButton('Create key', create, { busyLabel: 'Creating…' });

  const form = el('form', { novalidate: true }, [
    field({
      id: 'key-principal',
      label: 'Principal',
      hint: 'The identity the key authenticates as. ASCII letters, digits, and . _ - : up to 128 characters.',
      control: principal,
    }),
    field({
      id: 'key-description',
      label: 'Description (optional)',
      hint: 'What holds this key. This is the only thing that will identify it later.',
      control: description,
    }),
    scopeSet,
    field({
      id: 'key-expiry',
      label: 'Expiry (optional)',
      hint: 'The key stops working at 00:00:00 UTC on this day. Leave it empty for a key that never expires.',
      control: expiry,
    }),
    buttonRow([submit]),
    status,
  ]);

  // The button is `type="button"`, so a form submit is the Enter key rather
  // than a second code path: it routes to the same guarded handler, which is
  // not re-entrant while a creation is in flight.
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    submit.click();
  });

  const element = panel({
    title: 'Issue a key',
    note: 'The secret is returned once. Nothing — not this screen, not the router — can produce it again.',
    content: [
      form,
      el('p', {
        class: 'field__hint',
        text: 'Source restriction and management roles are not settable through this API: keys are created usable from any source and with no management role.',
      }),
    ],
  });

  return { element };

  /** Validate locally, create, and show the secret. */
  async function create() {
    status.textContent = '';

    const principalValue = principal.value.trim();
    if (!PRINCIPAL_PATTERN.test(principalValue)) {
      status.textContent =
        'A principal is required, using ASCII letters, digits, and . _ - : only (at most 128 characters).';
      principal.focus();
      return;
    }

    const scopes = SCOPES.map((scope) => scope.name).filter((name) => {
      const box = boxes.get(name);
      return Boolean(box && box.checked);
    });
    if (scopes.length === 0) {
      status.textContent = 'Select at least one scope; the router refuses a key with none.';
      const first = boxes.get(SCOPES[0].name);
      if (first) {
        first.focus();
      }
      return;
    }

    /** @type {number|undefined} */
    let expiresAt;
    if (expiry.value) {
      // The router stores an absolute wall-clock millisecond value, so the date
      // is interpreted in UTC and not in the browser's zone: a key that expires
      // at a different moment than the operator was shown is a key that fails
      // at an unexplained time.
      const parsed = Date.parse(`${expiry.value}T00:00:00Z`);
      if (!Number.isFinite(parsed)) {
        status.textContent = 'The expiry date could not be read. Use the date picker or YYYY-MM-DD.';
        expiry.focus();
        return;
      }
      if (parsed <= Date.now()) {
        status.textContent =
          'That expiry is now or in the past; the key would be dead on arrival. Choose a later day.';
        expiry.focus();
        return;
      }
      expiresAt = parsed;
    }

    const body = { principal: principalValue, scopes };
    const descriptionValue = description.value.trim();
    if (descriptionValue !== '') {
      body.description = descriptionValue;
    }
    if (expiresAt !== undefined) {
      body.expires_at = expiresAt;
    }

    let created;
    try {
      const response = await ctx.api.post('/keys', body);
      created = response.data;
    } catch (error) {
      if (error instanceof ApiError && error.needsReauthentication) {
        status.textContent =
          'Creating a key needs a recent sign-in. Sign out and back in, then try again — no key was created.';
        return;
      }
      throw error;
    }
    if (state.disposed) {
      return;
    }

    if (!created || typeof created.secret !== 'string' || created.secret === '') {
      // The key may well exist; what is certain is that this screen cannot show
      // the secret, and pretending otherwise would send the operator away with
      // nothing. Refresh so the row is visible and say plainly what happened.
      status.textContent =
        'The router accepted the key but returned no secret. Check the list below and the audit log before creating another.';
      await onCreated();
      return;
    }

    showSecret(created);
    ctx.notify('ok', `Key ${String(created.id || '')} created. Store the secret now.`);

    // The form is cleared so the next creation starts from nothing; leaving a
    // principal in place invites a second key nobody meant to issue.
    principal.value = '';
    description.value = '';
    expiry.value = '';
    for (const box of boxes.values()) {
      box.checked = false;
    }
    status.textContent = '';

    await onCreated();
  }

  /**
   * Show the one-time secret, once.
   *
   * @param {object} created The `POST /keys` body: `{id, principal, secret, notice}`.
   */
  function showSecret(created) {
    const block = secretOnce({
      value: created.secret,
      label: `Secret for key ${String(created.id || '')}`,
      notice:
        typeof created.notice === 'string' && created.notice !== ''
          ? created.notice
          : 'This secret is shown once and cannot be retrieved again.',
      onDismiss: () => {
        replace(secretRegion, []);
        submit.focus();
      },
    });

    const wrapper = el('div', { tabindex: '-1' }, [
      block,
      definitionList([
        ['Key id', String(created.id || '—')],
        ['Principal', String(created.principal || '—')],
        ['Scopes', (Array.isArray(created.scopes) ? created.scopes : []).join(', ')],
      ]),
    ]);

    replace(secretRegion, wrapper);
    // Focus moves to the secret because it is the only thing on the screen with
    // a deadline: leaving without copying it means issuing another key.
    wrapper.focus();
  }
}

// -------------------------------------------------------------- load states -

/**
 * The session is authenticated but not recently enough for `manage_keys`.
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
      text: 'Managing API keys is a sensitive action, so the router requires an authentication newer than this session has. Nothing has failed and no key has changed; sign in again to see and manage keys.',
    }),
    buttonRow([again]),
  ]);
}

/**
 * The list could not be read.
 *
 * @param {object} ctx
 * @param {unknown} error
 * @returns {HTMLElement}
 */
function loadFailure(ctx, error) {
  const detail =
    error instanceof ApiError
      ? [
          error.message,
          error.requestId ? `request ${error.requestId}` : null,
          error.code && error.code !== 'unknown' ? `code ${error.code}` : null,
        ]
          .filter(Boolean)
          .join(' — ')
      : 'The management API did not answer.';

  const retry = actionButton(
    'Try again',
    () => {
      // Re-navigating to the current route re-runs `mount` from a clean state,
      // which is exactly what a retry means here.
      ctx.navigate(meta.path);
    },
    { tone: 'quiet' },
  );

  return card('The key list could not be loaded', [
    el('p', { class: 'page-lede', text: detail }),
    el('p', {
      class: 'field__hint',
      text: 'No key has been created or revoked by this failure. Nothing is shown below rather than a stale or partial list.',
    }),
    buttonRow([retry]),
  ]);
}
