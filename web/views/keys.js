/**
 * The API keys screen.
 *
 * Specification 15.3: "Create once, scope, expiry, last-used metadata, revoke;
 * secret never displayed again." Specification 16: `POST /admin/v1/keys` returns
 * a one-time secret and `DELETE /admin/v1/keys/{id}` revokes immediately.
 * `PUT /admin/v1/keys/{id}/expiry` moves or removes an outstanding key's expiry,
 * and `GET`/`PUT /admin/v1/keys/{id}/restrictions` narrow what one key may use
 * within what its principal may use.
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
  {
    name: 'management:read',
    hint: 'Read /admin/v1 with this key. Permissions still come from the role bindings for the key\u2019s principal.',
  },
  {
    name: 'management:write',
    hint: 'Also change things through /admin/v1. No key may mint keys or open break-glass.',
  },
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
        columns: columns(
          askRevoke,
          askExpiry,
          askAccess,
          ctx.can('manage_key_budgets') ? askBudget : null,
        ),
        rows,
        empty: emptyMessage(state),
      }),
      morePager(state.envelope, loadMore),
    ]);
  }

  /**
   * Open the budget editor for a key.
   *
   * @param {object} row
   * @param {HTMLElement} trigger The button that opened the editor.
   */
  function askBudget(row, trigger) {
    const close = () => {
      replace(confirmRegion, []);
      if (trigger.isConnected) {
        trigger.focus();
      }
    };
    replace(
      confirmRegion,
      budgetEditor(ctx, row, {
        onClose: close,
        onChanged: async () => {
          if (state.disposed) {
            return;
          }
          replace(confirmRegion, []);
          await refresh();
        },
      }),
    );
  }

  /**
   * Open the expiry editor for a key.
   *
   * @param {object} row
   * @param {HTMLElement} trigger The button that opened the editor.
   */
  function askExpiry(row, trigger) {
    const close = () => {
      replace(confirmRegion, []);
      if (trigger.isConnected) {
        trigger.focus();
      }
    };
    replace(
      confirmRegion,
      expiryEditor(ctx, row, {
        onClose: close,
        onChanged: async () => {
          if (state.disposed) {
            return;
          }
          replace(confirmRegion, []);
          if (refreshButton.isConnected) {
            refreshButton.focus();
          }
          await refresh();
        },
      }),
    );
  }

  /**
   * Open the access editor for a key.
   *
   * @param {object} row
   * @param {HTMLElement} trigger The button that opened the editor.
   */
  function askAccess(row, trigger) {
    const close = () => {
      replace(confirmRegion, []);
      if (trigger.isConnected) {
        trigger.focus();
      }
    };
    replace(
      confirmRegion,
      accessEditor(ctx, row, {
        onClose: close,
        onChanged: async () => {
          if (state.disposed) {
            return;
          }
          replace(confirmRegion, []);
          if (refreshButton.isConnected) {
            refreshButton.focus();
          }
          await refresh();
        },
      }),
    );
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
      // No `If-Match`, deliberately: `revoke_key` checks none. Revocation is
      // monotonic and idempotent, so there is no lost update to prevent, and a
      // 412 from a concurrent revoke would refuse the one operation that should
      // never be refused. The key's ETag exists for the expiry editor.
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
 * A token count for display. Counts are integers; grouping makes a million
 * distinguishable from ten million at a glance.
 *
 * @param {unknown} value
 * @returns {string}
 */
function tokens(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value.toLocaleString('en-US') : '—';
}

/**
 * A key's token budget, as the router reports it.
 *
 * @param {object|undefined} budget
 * @returns {HTMLElement|string}
 */
function budgetCell(budget) {
  if (!budget || typeof budget !== 'object') {
    return '—';
  }
  const used = `${tokens(budget.consumed_tokens)} used`;
  if (budget.token_limit === null || budget.token_limit === undefined) {
    return el('span', {}, [pill('Unlimited'), ` ${used}`]);
  }
  const remaining = budget.remaining_tokens;
  return el('span', {}, [
    pill(`${tokens(remaining)} left`, remaining === 0 ? 'danger' : 'neutral'),
    ` of ${tokens(budget.token_limit)}, ${used}`,
  ]);
}

/**
 * The budget editor: the absolute limit and payment instructions, and — for a
 * finite budget — a one-off credit.
 *
 * Both actions carry the budget's ETag, so an edit made against a limit that
 * somebody else has since changed is refused rather than applied on top of it.
 * Consumption does not move that tag, so a key in use can still be edited.
 *
 * @param {object} ctx
 * @param {object} row
 * @param {{onClose: () => void, onChanged: () => Promise<void>}} handlers
 * @returns {HTMLElement}
 */
function budgetEditor(ctx, row, { onClose, onChanged }) {
  const budget = row.budget && typeof row.budget === 'object' ? row.budget : {};
  const finite = typeof budget.token_limit === 'number';
  const path = `/keys/${encodeURIComponent(row.id)}/budget`;
  const override = budget.payment_override ? budget.payment_required || {} : {};

  const limit = el('input', {
    type: 'text',
    inputmode: 'numeric',
    autocomplete: 'off',
    value: finite ? String(budget.token_limit) : '',
  });
  const message = el('input', {
    type: 'text',
    autocomplete: 'off',
    maxlength: '512',
    value: typeof override.message === 'string' ? override.message : '',
  });
  const url = el('input', {
    type: 'url',
    autocomplete: 'off',
    maxlength: '512',
    value: typeof override.payment_url === 'string' ? override.payment_url : '',
  });
  const amount = el('input', { type: 'text', inputmode: 'numeric', autocomplete: 'off' });
  const reference = el('input', {
    type: 'text',
    autocomplete: 'off',
    spellcheck: 'false',
    maxlength: '128',
    // A fresh reference per editor, so pressing Credit twice — or retrying
    // after a timeout — is one credit. An operator recording a real payment
    // replaces it with that payment's own identifier.
    value: `console-${crypto.randomUUID()}`,
  });
  const reason = el('input', { type: 'text', autocomplete: 'off', maxlength: '256' });
  const status = el('p', { class: 'field__hint', role: 'status', 'aria-live': 'polite' });

  /** @param {string} raw @returns {number|null} A whole token count, or null. */
  const whole = (raw) => (/^\d{1,15}$/.test(raw) ? Number(raw) : null);

  /** @param {unknown} error @param {string} what */
  const explain = (error, what) => {
    if (error instanceof ApiError && error.status === 412) {
      status.textContent = `The budget changed while this editor was open, so ${what} was not applied. Close it and reopen from the refreshed list.`;
      return;
    }
    if (error instanceof ApiError && (error.status === 400 || error.status === 409)) {
      status.textContent = `${error.message} Nothing was changed.`;
      return;
    }
    throw error;
  };

  const save = actionButton(
    'Save budget',
    async () => {
      const raw = limit.value.trim();
      const parsed = raw === '' ? null : whole(raw);
      if (raw !== '' && parsed === null) {
        status.textContent = 'The limit is a whole number of tokens, or empty for no limit.';
        limit.focus();
        return;
      }
      const body = { token_limit: parsed, payment_required: null };
      const messageValue = message.value.trim();
      const urlValue = url.value.trim();
      if (messageValue !== '' || urlValue !== '') {
        body.payment_required = {};
        if (messageValue !== '') {
          body.payment_required.message = messageValue;
        }
        if (urlValue !== '') {
          body.payment_required.payment_url = urlValue;
        }
      }
      try {
        await ctx.api.put(path, body, budget.etag);
      } catch (error) {
        explain(error, 'the new limit');
        return;
      }
      ctx.notify('ok', `Budget for key ${row.id} saved.`);
      await onChanged();
    },
    { busyLabel: 'Saving…' },
  );

  const credit = actionButton(
    'Credit tokens',
    async () => {
      const parsed = whole(amount.value.trim());
      if (parsed === null || parsed === 0) {
        status.textContent = 'A credit is a positive whole number of tokens.';
        amount.focus();
        return;
      }
      const referenceValue = reference.value.trim();
      if (!/^[\x21-\x7e]{1,128}$/.test(referenceValue)) {
        status.textContent =
          'The reference is 1 to 128 printable characters with no spaces: the payment or ticket this credit records.';
        reference.focus();
        return;
      }
      const body = { tokens: parsed };
      if (reason.value.trim() !== '') {
        body.reason = reason.value.trim();
      }
      let outcome;
      try {
        outcome = await ctx.api.postOnce(`${path}:credit`, body, budget.etag, referenceValue);
      } catch (error) {
        explain(error, 'the credit');
        return;
      }
      ctx.notify(
        'ok',
        outcome.data && outcome.data.replayed
          ? `That reference was already credited to key ${row.id}; nothing was added.`
          : `${tokens(parsed)} tokens credited to key ${row.id}.`,
      );
      await onChanged();
    },
    { busyLabel: 'Crediting…' },
  );

  const inherited =
    !budget.payment_override && budget.payment_required
      ? ' The tenant default currently applies.'
      : '';

  return panel({
    title: `Token budget — key ${row.id}`,
    note: 'A budget is a cumulative allowance that does not refill. When a request cannot be funded the key gets HTTP 402 and the provider is not called.',
    actions: [actionButton('Close', onClose, { tone: 'quiet' })],
    content: [
      definitionList([
        ['Limit', finite ? tokens(budget.token_limit) : 'Unlimited'],
        ['Consumed', tokens(budget.consumed_tokens)],
        ['Held by requests in flight', tokens(budget.reserved_tokens)],
        ['Remaining', finite ? tokens(budget.remaining_tokens) : 'Unlimited'],
      ]),
      field({
        id: 'budget-limit',
        label: 'Token limit',
        hint: 'The total the key may ever consume, input plus output. Empty means no limit; zero permits nothing. Changing it never resets what has been consumed.',
        control: limit,
      }),
      field({
        id: 'budget-message',
        label: 'Payment message (optional)',
        hint: `Plain text returned with the 402. Leave both payment fields empty to inherit the tenant default.${inherited}`,
        control: message,
      }),
      field({
        id: 'budget-url',
        label: 'Payment URL (optional)',
        hint: 'An absolute HTTPS address. The router returns it as data and never calls or redirects to it.',
        control: url,
      }),
      buttonRow([save]),
      ...(finite
        ? [
            field({
              id: 'budget-credit',
              label: 'Credit tokens',
              hint: 'Added to the limit once. Use the limit above to set an absolute allowance instead.',
              control: amount,
            }),
            field({
              id: 'budget-reference',
              label: 'Reference',
              hint: 'Identifies this credit. Submitting the same reference again adds nothing, so a retry is safe.',
              control: reference,
            }),
            field({
              id: 'budget-reason',
              label: 'Reason (optional)',
              hint: 'Recorded in the audit log with the credit.',
              control: reason,
            }),
            buttonRow([credit]),
          ]
        : [
            el('p', {
              class: 'field__hint',
              text: 'An unlimited budget cannot be credited. Set a limit first.',
            }),
          ]),
      status,
    ],
  });
}

/**
 * The UTC calendar day of a millisecond time, as a date input holds it.
 *
 * @param {unknown} millis
 * @returns {string} `YYYY-MM-DD`, or empty when there is no usable time.
 */
function utcDay(millis) {
  if (typeof millis !== 'number' || !Number.isFinite(millis)) {
    return '';
  }
  return new Date(millis).toISOString().slice(0, 10);
}

/**
 * The expiry editor: a later day, an earlier one, or no expiry at all.
 *
 * Carries the key's ETag, so a change made against an expiry somebody else
 * has since moved — or against a key revoked since the list was read — is
 * refused rather than applied on top of it.
 *
 * When the session's key authority is break-glass alone, the router caps a
 * key's expiry at the session's own end and refuses "no expiry", exactly as it
 * does at creation: break-glass authority is meant to end with the session,
 * and a key that outlived it would carry it on. A `key_manager` is not capped,
 * even when it also holds break-glass. The router reports which applies as
 * `keys_capped_to_session`; the editor says so up front instead of letting the
 * operator discover it from a refusal.
 *
 * @param {object} ctx
 * @param {object} row
 * @param {{onClose: () => void, onChanged: () => Promise<void>}} handlers
 * @returns {HTMLElement}
 */
function expiryEditor(ctx, row, { onClose, onChanged }) {
  const capped = Boolean(ctx.session && ctx.session.keys_capped_to_session);
  const current = typeof row.expires_at === 'number' ? row.expires_at : null;

  const day = el('input', { type: 'date', value: utcDay(current) });
  const never = el('input', {
    type: 'checkbox',
    id: 'key-expiry-never',
    'aria-describedby': 'key-expiry-never-hint',
  });
  never.checked = current === null && !capped;
  never.disabled = capped;
  day.disabled = never.checked;
  never.addEventListener('change', () => {
    day.disabled = never.checked;
  });

  const status = el('p', { class: 'field__hint', role: 'status', 'aria-live': 'polite' });

  const save = actionButton(
    'Save expiry',
    async () => {
      status.textContent = '';
      /** @type {number|null} */
      let expiresAt = null;
      if (!never.checked) {
        if (!day.value) {
          status.textContent = capped
            ? 'Choose a day. On break-glass authority a key\u2019s expiry cannot be removed.'
            : 'Choose a day, or tick \u201cNo expiry\u201d.';
          day.focus();
          return;
        }
        // UTC midnight, as at creation: the moment shown is the moment stored.
        const parsed = Date.parse(`${day.value}T00:00:00Z`);
        if (!Number.isFinite(parsed)) {
          status.textContent = 'The date could not be read. Use the date picker or YYYY-MM-DD.';
          day.focus();
          return;
        }
        if (parsed <= Date.now()) {
          status.textContent =
            'That day is now or in the past. To stop the key working, revoke it instead.';
          day.focus();
          return;
        }
        expiresAt = parsed;
      }
      try {
        await ctx.api.put(`/keys/${encodeURIComponent(row.id)}/expiry`, { expires_at: expiresAt }, row.etag);
      } catch (error) {
        if (error instanceof ApiError && error.needsReauthentication) {
          status.textContent =
            'Changing an expiry needs a recent sign-in. Sign out and back in, then try again \u2014 nothing was changed.';
          return;
        }
        if (error instanceof ApiError && error.status === 412) {
          status.textContent =
            'The key changed while this editor was open, so nothing was applied. Close it and reopen from the refreshed list.';
          return;
        }
        if (error instanceof ApiError && [400, 403, 409, 428].includes(error.status)) {
          status.textContent = `${error.message}. Nothing was changed.`;
          return;
        }
        throw error;
      }
      ctx.notify(
        'ok',
        expiresAt === null
          ? `Key ${row.id} no longer expires.`
          : `Key ${row.id} now expires ${formatTime(expiresAt)}.`,
      );
      await onChanged();
    },
    { busyLabel: 'Saving\u2026' },
  );

  const expired = current !== null && current <= Date.now();
  return panel({
    title: `Expiry \u2014 key ${row.id}`,
    note: expired
      ? 'This key has expired. A later expiry makes it authenticate again, with the same secret and scopes.'
      : 'The key keeps its secret and scopes; only the moment it stops working moves.',
    actions: [actionButton('Close', onClose, { tone: 'quiet' })],
    content: [
      definitionList([['Currently', current === null ? 'No expiry' : formatTime(current)]]),
      field({
        id: 'key-expiry-day',
        label: 'Expires on',
        hint: 'The key stops working at 00:00:00 UTC on this day.',
        control: day,
      }),
      el('div', { class: 'checkset__item' }, [
        never,
        el('label', { for: 'key-expiry-never' }, 'No expiry'),
        el('span', {
          class: 'checkset__hint',
          id: 'key-expiry-never-hint',
          text: capped
            ? 'Not available on break-glass authority: the router caps a key\u2019s expiry at this session\u2019s end. The key_manager role lifts that.'
            : 'The key works until it is revoked.',
        }),
      ]),
      buttonRow([save]),
      status,
    ],
  });
}

/** Admission classes, served first to last. */
const PRIORITIES = ['interactive', 'standard', 'batch'];

/**
 * A key's restrictions as one line for the table.
 *
 * @param {object|undefined} restrictions The listing's `restrictions` object.
 * @returns {HTMLElement|string}
 */
function accessCell(restrictions) {
  const r = restrictions || {};
  const parts = [];
  const count = (list, one, many) =>
    Array.isArray(list) ? `${list.length} ${list.length === 1 ? one : many}` : null;
  const models = count(r.models, 'model', 'models');
  const targets = count(r.targets, 'target', 'targets');
  const hosts = count(r.hosts, 'slave', 'slaves');
  if (models) parts.push(models);
  if (targets) parts.push(targets);
  if (hosts) parts.push(hosts);
  if (typeof r.priority === 'string') parts.push(r.priority);
  if (parts.length === 0) {
    return el('span', { class: 'empty', text: 'As its principal' });
  }
  const node = pill(`Narrowed: ${parts.join(' · ')}`, 'warn');
  node.title = [
    Array.isArray(r.models) ? `Models: ${r.models.join(', ')}` : 'Models: all of the principal\u2019s',
    Array.isArray(r.targets) ? `Targets: ${r.targets.join(', ')}` : 'Targets: all of the principal\u2019s',
    Array.isArray(r.hosts) ? `Slaves: ${r.hosts.join(', ')}` : 'Slaves: all of the principal\u2019s',
    `Priority: ${typeof r.priority === 'string' ? r.priority : 'the principal\u2019s'}`,
  ].join('\n');
  return node;
}

/**
 * A checkbox list that can be switched off as a whole.
 *
 * "No restriction" is a separate control rather than "every box ticked",
 * because they mean different things to the router: ticking everything pins
 * the key to today's list, and a model the principal is given tomorrow would
 * stay out of reach of this key. `null` follows the principal.
 *
 * @param {object} options
 * @param {string} options.id
 * @param {string} options.legend
 * @param {string} options.allLabel
 * @param {{value: string, label: string, hint?: string, group?: string}[]} options.choices
 * @param {string[]|null} options.current
 * @returns {{element: HTMLElement, value: () => string[]|null, problem: () => string|null}}
 */
function allowlist({ id, legend, allLabel, choices, current }) {
  const all = el('input', { type: 'checkbox', id: `${id}-all`, 'aria-label': allLabel });
  all.checked = !Array.isArray(current);
  const chosen = new Set(Array.isArray(current) ? current : []);
  const offered = new Set(choices.map((c) => c.value));

  const boxes = choices.map((choice, index) => {
    const boxId = `${id}-${index}`;
    const box = el('input', {
      type: 'checkbox',
      id: boxId,
      value: choice.value,
      'aria-label': `${legend}: ${choice.label}`,
    });
    box.checked = chosen.has(choice.value);
    const label = choice.group ? `${choice.label} \u2014 ${choice.group}` : choice.label;
    return {
      box,
      item: el('div', { class: 'checkset__item' }, [
        box,
        el('label', { for: boxId }, label),
        choice.hint ? el('span', { class: 'checkset__hint', text: choice.hint }) : null,
      ]),
    };
  });

  // What the key was narrowed to that its principal can no longer use. The
  // router refuses to save those, and ignores them meanwhile; say so instead
  // of silently dropping them.
  const gone = [...chosen].filter((value) => !offered.has(value));
  const goneNote =
    gone.length > 0
      ? el('p', {
          class: 'field__hint',
          text: `No longer available to the principal, so already out of this key\u2019s reach and dropped on save: ${gone.join(', ')}.`,
        })
      : null;

  const sync = () => {
    for (const { box } of boxes) {
      box.disabled = all.checked;
    }
  };
  all.addEventListener('change', sync);
  sync();

  const element = el('fieldset', { class: 'checkset' }, [
    el('legend', { class: 'checkset__legend' }, legend),
    el('div', { class: 'checkset__item' }, [all, el('label', { for: `${id}-all` }, allLabel)]),
    ...boxes.map((b) => b.item),
    goneNote,
    choices.length === 0
      ? el('p', { class: 'field__hint', text: 'The principal may use none at the moment.' })
      : null,
  ]);

  return {
    element,
    value: () => (all.checked ? null : boxes.filter((b) => b.box.checked).map((b) => b.box.value)),
    problem: () =>
      !all.checked && boxes.every((b) => !b.box.checked)
        ? `${legend}: tick at least one, or allow all. A key that may use nothing should be revoked.`
        : null,
  };
}

/**
 * The access editor: which models, targets and slaves one key may use, and
 * the priority it queues at, within what its principal may.
 *
 * The choices come from `GET /keys/{id}/restrictions`, which computes the
 * principal's ceiling from the active configuration. Only those are offered,
 * because the router refuses anything else: a key can narrow its principal's
 * access and never widen it. Changing the ceiling itself is a policy change,
 * drafted and published elsewhere.
 *
 * @param {object} ctx
 * @param {object} row
 * @param {{onClose: () => void, onChanged: () => Promise<void>}} handlers
 * @returns {HTMLElement}
 */
function accessEditor(ctx, row, { onClose, onChanged }) {
  const body = el('div', {}, [el('p', { class: 'field__hint', text: 'Loading what this key\u2019s principal may use\u2026' })]);
  const element = panel({
    title: `Access \u2014 key ${row.id}`,
    note: 'Narrows this key within its principal\u2019s access. Takes effect on the key\u2019s next request; no publication is needed, because nothing here can widen what the policy allows.',
    actions: [actionButton('Close', onClose, { tone: 'quiet' })],
    content: [body],
  });

  ctx.api
    .get(`/keys/${encodeURIComponent(row.id)}/restrictions`)
    .then(({ data, etag }) => {
      if (!body.isConnected) {
        return;
      }
      replace(body, accessForm(ctx, row, data, etag || row.etag, onChanged));
    })
    .catch((error) => {
      const message =
        error instanceof ApiError && error.needsReauthentication
          ? 'Reading this key\u2019s access needs a recent sign-in. Sign out and back in, then try again.'
          : `The key\u2019s access could not be read: ${error && error.message ? error.message : String(error)}`;
      replace(body, [el('p', { class: 'field__hint', role: 'alert', text: message })]);
    });

  return element;
}

/**
 * The Models, Slaves and Priority controls, built from a principal's ceiling.
 *
 * Shared by the access editor and the create form, so a key minted narrowed
 * is offered exactly the choices narrowing it later would be.
 *
 * @param {object} ceiling The `ceiling` object of `GET /keys/{id}/restrictions`
 *   or `GET /keys:ceiling`.
 * @param {object} current The restrictions to start from; `{}` allows all.
 * @param {string} prefix Element id prefix, unique on the page.
 * @returns {{elements: HTMLElement[], principalClass: string, problem: () => string|null, payload: () => object}}
 */
function accessControls(ceiling, current, prefix) {
  const models = Array.isArray(ceiling.models) ? ceiling.models : [];
  const targets = Array.isArray(ceiling.targets) ? ceiling.targets : [];
  const hosts = Array.isArray(ceiling.hosts) ? ceiling.hosts : [];
  const principalClass = PRIORITIES.includes(ceiling.priority) ? ceiling.priority : 'standard';

  const modelList = allowlist({
    id: `${prefix}-models`,
    legend: 'Models',
    allLabel: 'Every model the principal may use',
    choices: models.map((m) => ({
      value: String(m.id),
      label: String(m.id),
      hint: m.description ? String(m.description) : undefined,
    })),
    current: current.models,
  });
  const targetList = allowlist({
    id: `${prefix}-targets`,
    legend: 'Slaves and targets',
    allLabel: 'Every target the principal may be served by',
    choices: targets.map((t) => ({
      value: String(t.id),
      label: String(t.id),
      group: t.host ? `slave ${t.host}` : t.provider ? `provider ${t.provider}` : undefined,
    })),
    current: current.targets,
  });
  // Fleet slaves only exist when the configuration declares a fleet; with
  // none, a slave is a provider and the target list above already says it.
  const hostList =
    hosts.length > 0 || Array.isArray(current.hosts)
      ? allowlist({
          id: `${prefix}-hosts`,
          legend: 'Fleet slaves',
          allLabel: 'Every slave the principal may use',
          choices: hosts.map((h) => ({ value: String(h), label: String(h) })),
          current: current.hosts,
        })
      : null;

  const priority = el('select', { id: `${prefix}-priority` }, [
    el('option', { value: '' }, `As the principal (${principalClass})`),
    ...PRIORITIES.map((name) => {
      const option = el('option', { value: name }, name);
      // A key may lower its principal's class and never raise it.
      if (PRIORITIES.indexOf(name) < PRIORITIES.indexOf(principalClass)) {
        option.disabled = true;
        option.textContent = `${name} \u2014 above the principal`;
      }
      return option;
    }),
  ]);
  priority.value = typeof current.priority === 'string' ? current.priority : '';

  const offeredModels = new Set(models.map((m) => String(m.id)));
  const offeredTargets = new Set(targets.map((t) => String(t.id)));
  const offeredHosts = new Set(hosts.map(String));
  const keep = (list, offered) => (list === null ? null : list.filter((v) => offered.has(v)));

  return {
    principalClass,
    elements: [
      modelList.element,
      targetList.element,
      hostList ? hostList.element : null,
      field({
        id: `${prefix}-priority`,
        label: 'Priority',
        hint: 'Where this key\u2019s requests queue when a model is busy. A key can queue below its principal, never above.',
        control: priority,
      }),
    ],
    problem: () =>
      [modelList, targetList, hostList]
        .filter(Boolean)
        .map((l) => l.problem())
        .find(Boolean) || null,
    payload: () => ({
      models: keep(modelList.value(), offeredModels),
      targets: keep(targetList.value(), offeredTargets),
      hosts: hostList ? keep(hostList.value(), offeredHosts) : null,
      priority: priority.value === '' ? null : priority.value,
    }),
  };
}

/**
 * The form inside the access editor, once the ceiling has been read.
 *
 * @param {object} ctx
 * @param {object} row
 * @param {object} data The `GET /keys/{id}/restrictions` body.
 * @param {string} etag
 * @param {() => Promise<void>} onChanged
 * @returns {HTMLElement[]}
 */
function accessForm(ctx, row, data, etag, onChanged) {
  const controls = accessControls(data.ceiling || {}, data.restrictions || {}, 'key-access');
  const status = el('p', { class: 'field__hint', role: 'status', 'aria-live': 'polite' });

  const save = actionButton(
    'Save access',
    async () => {
      status.textContent = '';
      const problem = controls.problem();
      if (problem) {
        status.textContent = problem;
        return;
      }
      try {
        await ctx.api.put(`/keys/${encodeURIComponent(row.id)}/restrictions`, controls.payload(), etag);
      } catch (error) {
        if (error instanceof ApiError && error.needsReauthentication) {
          status.textContent =
            'Changing a key\u2019s access needs a recent sign-in. Sign out and back in, then try again \u2014 nothing was changed.';
          return;
        }
        if (error instanceof ApiError && error.status === 412) {
          status.textContent =
            'The key changed while this editor was open, so nothing was applied. Close it and reopen from the refreshed list.';
          return;
        }
        if (error instanceof ApiError && [400, 403, 409, 422, 428].includes(error.status)) {
          status.textContent = `${error.message}. Nothing was changed.`;
          return;
        }
        throw error;
      }
      ctx.notify('ok', `Key ${row.id}\u2019s access is updated.`);
      await onChanged();
    },
    { busyLabel: 'Saving\u2026' },
  );

  return [
    definitionList([
      ['Principal', String(data.principal || row.principal || '\u2014')],
      ['Principal\u2019s priority', controls.principalClass],
    ]),
    sharedPrincipalNote(data.keys_sharing_principal, 'what you set here narrows this key only'),
    ...controls.elements,
    buttonRow([save]),
    status,
  ];
}

/**
 * A note that other keys sign in as the same principal, or null when none do.
 *
 * @param {unknown} count `keys_sharing_principal` from the router.
 * @param {string} tail What the narrowing on this screen affects.
 * @returns {HTMLElement|null}
 */
function sharedPrincipalNote(count, tail) {
  const shared = Number(count) || 0;
  if (shared <= 0) {
    return null;
  }
  return el('p', {
    class: 'field__hint',
    role: 'note',
    text: `${shared} other active ${shared === 1 ? 'key signs' : 'keys sign'} in as this principal. They share its policy, so a change to that reaches them too; ${tail}.`,
  });
}

/**
 * The columns of the key table.
 *
 * @param {(row: object, trigger: HTMLElement) => void} onRevoke
 * @param {(row: object, trigger: HTMLElement) => void} onExpiry
 * @param {(row: object, trigger: HTMLElement) => void} onAccess
 * @param {((row: object, trigger: HTMLElement) => void)|null} onBudget Null
 *   when the session may not manage budgets, in which case the column still
 *   shows them and offers no editor.
 * @returns {object[]}
 */
function columns(onRevoke, onExpiry, onAccess, onBudget) {
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
    { label: 'Token budget', cell: (row) => budgetCell(row.budget) },
    { label: 'Created', cell: (row) => formatTime(row.created_at) },
    {
      label: 'Expires',
      cell: (row) =>
        row.expires_at === null || row.expires_at === undefined
          ? 'No expiry'
          : formatTime(row.expires_at),
    },
    { label: 'Access', cell: (row) => accessCell(row.restrictions) },
    {
      label: 'Usage',
      cell: (row) =>
        el('a', { href: `#/usage?principal=${encodeURIComponent(String(row.principal || ''))}&key=${encodeURIComponent(String(row.id))}` }, 'Usage'),
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
        const expiry = actionButton(
          'Expiry',
          () => {
            onExpiry(row, expiry);
          },
          { tone: 'quiet', title: `Extend, shorten, or remove the expiry of key ${row.id}` },
        );
        const access = actionButton(
          'Access',
          () => {
            onAccess(row, access);
          },
          { tone: 'quiet', title: `Narrow which models, targets and slaves key ${row.id} may use` },
        );
        if (!onBudget) {
          return buttonRow([expiry, access, button]);
        }
        const budget = actionButton(
          'Budget',
          () => {
            onBudget(row, budget);
          },
          { tone: 'quiet', title: `Edit the token budget of key ${row.id}` },
        );
        return buttonRow([expiry, access, budget, button]);
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
  const sources = el('input', {
    type: 'text',
    autocomplete: 'off',
    spellcheck: 'false',
    placeholder: '192.168.8.0/24, 100.64.0.0/10',
  });

  // Narrowing at creation. The choices are the principal's ceiling, read from
  // the router for whatever principal is typed, so a key minted narrowed is
  // offered exactly what narrowing it later would be. Off by default: an
  // unticked box mints a key with its principal's access, as before.
  const narrow = el('input', {
    type: 'checkbox',
    id: 'key-create-narrow',
    'aria-label': 'Narrow this key within its principal\u2019s access',
  });
  const accessRegion = el('div', { class: 'policy-stack' });
  /** @type {{principal: string, controls: ReturnType<typeof accessControls>}|null} */
  let access = null;
  let accessLoad = 0;

  async function loadAccess() {
    access = null;
    accessLoad += 1;
    const token = accessLoad;
    if (!narrow.checked) {
      replace(accessRegion, []);
      return;
    }
    const value = principal.value.trim();
    if (!PRINCIPAL_PATTERN.test(value)) {
      replace(accessRegion, [
        el('p', { class: 'field__hint', text: 'Enter the principal first: the choices are what it may use.' }),
      ]);
      return;
    }
    replace(accessRegion, [
      el('p', { class: 'field__hint', text: `Loading what ${value} may use\u2026` }),
    ]);
    try {
      // Shared, so reading the ceiling does not cancel the key list's load.
      const { data } = await ctx.api.get(`/keys:ceiling?principal=${encodeURIComponent(value)}`, {
        shared: true,
      });
      if (token !== accessLoad || state.disposed) {
        return;
      }
      const controls = accessControls(data.ceiling || {}, {}, 'key-create-access');
      access = { principal: value, controls };
      replace(accessRegion, [
        sharedPrincipalNote(data.keys_sharing_principal, 'what you set here narrows the new key only'),
        ...controls.elements,
      ]);
    } catch (error) {
      if (token !== accessLoad) {
        return;
      }
      const message =
        error instanceof ApiError && error.needsReauthentication
          ? 'Reading what the principal may use needs a recent sign-in. Sign out and back in, then try again.'
          : `What the principal may use could not be read: ${error && error.message ? error.message : String(error)}`;
      replace(accessRegion, [el('p', { class: 'field__hint', role: 'alert', text: message })]);
    }
  }
  narrow.addEventListener('change', () => void loadAccess());
  principal.addEventListener('change', () => {
    if (narrow.checked) {
      void loadAccess();
    }
  });
  const accessSet = el('fieldset', { class: 'checkset' }, [
    el('legend', { class: 'checkset__legend' }, 'Access (optional)'),
    el('div', { class: 'checkset__item' }, [
      narrow,
      el('label', { for: 'key-create-narrow' }, 'Narrow this key within its principal\u2019s access'),
      el('span', {
        class: 'checkset__hint',
        text: 'Some of the principal\u2019s models, slaves and targets, and a lower priority. The key is narrowed from its first request.',
      }),
    ]),
    accessRegion,
  ]);

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
    field({
      id: 'key-sources',
      label: 'Source networks (optional)',
      hint: 'CIDR blocks the key may be used from, separated by commas or spaces. Leave it empty for a key usable from anywhere.',
      control: sources,
    }),
    accessSet,
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
        text: 'A key carries no management role of its own: its management permissions, if it has a management scope, are its principal\u2019s role bindings.',
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

    const networks = sources.value
      .split(/[\s,]+/)
      .map((entry) => entry.trim())
      .filter((entry) => entry !== '');
    if (networks.some((entry) => !entry.includes('/'))) {
      status.textContent =
        'Write each source network as a CIDR block with a prefix length, such as 10.0.0.0/8 or 203.0.113.7/32.';
      sources.focus();
      return;
    }

    /** @type {object|undefined} */
    let restrictions;
    if (narrow.checked) {
      if (!access || access.principal !== principalValue) {
        status.textContent =
          'The access choices are not loaded for this principal yet. Wait for them, or untick \u201cNarrow this key\u201d.';
        return;
      }
      const problem = access.controls.problem();
      if (problem) {
        status.textContent = problem;
        return;
      }
      const payload = access.controls.payload();
      // All four "as the principal" narrows nothing; send nothing.
      if (Object.values(payload).some((value) => value !== null)) {
        restrictions = payload;
      }
    }

    const body = { principal: principalValue, scopes };
    if (networks.length > 0) {
      body.source_networks = networks;
    }
    if (restrictions !== undefined) {
      body.restrictions = restrictions;
    }
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
      if (error instanceof ApiError && [400, 403, 422].includes(error.status)) {
        status.textContent = `${error.message}. No key was created.`;
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
    sources.value = '';
    narrow.checked = false;
    void loadAccess();
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
        ['Access', accessCell(created.restrictions)],
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
