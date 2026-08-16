/**
 * The audit screen.
 *
 * Specification 15.3: "Actor/action/object/result, filters, export, integrity
 * checkpoint status."
 *
 * The log is only worth reading if the operator can tell how much of it they
 * are looking at, so three things are stated on the page rather than implied:
 *
 * - **The chain head and length come first.** Specification 11.2 makes audit
 *   records "a hash/MAC chain with periodic signed checkpoints". The head
 *   digest and the record count are what make the log evidence rather than a
 *   list, so they are the first block on the screen — not a footnote under the
 *   table. This screen *reports* them; it does not verify them, and it says so.
 *   A browser claiming to have checked a chain it cannot recompute would be
 *   worse than a browser that says nothing.
 * - **Filtering is in the browser, over one fetched page.** `GET /admin/v1/audit`
 *   takes `?limit=` and nothing else — no search, no cursor, no time range. A
 *   filter box that quietly searched only the last fifty records would be a
 *   trap during an incident, so the row count, the fetched count, and the chain
 *   length are shown together and the toolbar says where the filtering happens.
 * - **There is no export endpoint.** Specification 15.3 asks for one and the
 *   store defines an `audit_exported` action for it, but the management API
 *   exposes no route. The screen names that gap instead of offering a browser
 *   download, which would produce a file that looks like an export while
 *   leaving no record in the chain that an export occurred.
 *
 * The screen is read-only: `GET /admin/v1/audit` is the whole of its API
 * surface, so specification 15.4's rule about never applying optimistic UI to a
 * security-sensitive mutation has nothing to bite on here. Refresh and page
 * size still go through `actionButton`/disabled controls so that a double click
 * cannot stack two requests.
 *
 * Response shape, from `list_audit` in `crates/hypellm-admin-api/src/handlers.rs`:
 * `{object, data: [{sequence, timestamp, actor, action, outcome, object?,
 * tenant?, reason?, link}], chain_head, chain_length}`. There is no
 * `next_cursor`, hence a page-size control rather than a pager.
 */

import { el, formatCount, formatTime, pill, replace, text } from '../components/dom.js';
import { pageHeader, render, table } from '../components/table.js';
import {
  actionButton,
  definitionList,
  emptyState,
  inlineField,
  notAvailable,
  panel,
  toolbar,
} from '../components/layout.js';

/** Screen metadata, read by the router to build navigation. */
export const meta = {
  path: '/audit',
  title: 'Audit',
  lede: 'Who did what, to what, and with what result — with the hash chain the records hang from.',
  // `list_audit` requires `Permission::ReadAudit`; `export_audit` is a separate
  // permission and gates nothing on this screen, because no export route exists.
  permission: 'read_audit',
};

/** Page sizes offered. The router clamps `?limit=` to 1..500 (`Pagination`). */
const PAGE_SIZES = [50, 100, 200, 500];

/** The default, matching `Pagination::DEFAULT_LIMIT`. */
const DEFAULT_PAGE_SIZE = 50;

/** The sentinel used by the filter selects for "do not filter on this". */
const ANY = '';

/**
 * The tone for an outcome.
 *
 * `denied` is a warning rather than a failure: authorization refused the action
 * and the router behaved correctly, but it is the row an operator scanning for
 * trouble wants to find. `failed` means the action did not complete.
 *
 * @param {string} outcome
 * @returns {'ok'|'warn'|'danger'|'neutral'}
 */
function outcomeTone(outcome) {
  switch (outcome) {
    case 'success':
      return 'ok';
    case 'denied':
      return 'warn';
    case 'failed':
      return 'danger';
    default:
      return 'neutral';
  }
}

/**
 * The text a free-text filter searches within one record.
 *
 * Every displayed field is included, so what the operator can see is what they
 * can search — a filter that silently ignored the reason column would hide the
 * rows that explain a denial.
 *
 * @param {object} record
 * @returns {string}
 */
function haystack(record) {
  return [
    record.sequence,
    record.actor,
    record.action,
    record.outcome,
    record.object,
    record.tenant,
    record.reason,
    record.link,
  ]
    .filter((value) => value !== null && value !== undefined)
    .join(' ')
    .toLowerCase();
}

/**
 * The records of a list envelope, defensively.
 *
 * A shape the screen did not expect should render an honest empty table rather
 * than throw: the chain status above it is still worth showing.
 *
 * @param {object|null} envelope
 * @returns {object[]}
 */
function recordsOf(envelope) {
  return envelope && Array.isArray(envelope.data) ? envelope.data : [];
}

/**
 * Whether a digest string names an actual chain head.
 *
 * An all-zero digest is what a store with nothing committed reports, and it is
 * worth distinguishing from a head the router failed to supply.
 *
 * @param {unknown} digest
 * @returns {boolean}
 */
function isRealDigest(digest) {
  return typeof digest === 'string' && /^[0-9a-f]+$/i.test(digest) && !/^0+$/.test(digest);
}

/**
 * Fetch one page.
 *
 * @param {import('../api.js').Api} api
 * @param {number} limit
 * @returns {Promise<object>}
 */
async function fetchPage(api, limit) {
  const { data } = await api.get(`/audit?limit=${encodeURIComponent(String(limit))}`);
  return data;
}

/**
 * A `<select>` whose options are the distinct values present in the page.
 *
 * Deliberately data-derived rather than the full `AuditAction` enumeration:
 * offering twenty actions of which two ever match trains the operator to expect
 * an empty result, and the enumeration would drift from the router's the first
 * time an action is added.
 *
 * @param {HTMLSelectElement} select
 * @param {string[]} values
 * @param {string} anyLabel
 * @returns {string} The selection after the rebuild, which may differ from the
 *   selection before it if that value is no longer present.
 */
function fillOptions(select, values, anyLabel) {
  const wanted = select.value;
  const options = [el('option', { value: ANY, text: anyLabel })];
  for (const value of values) {
    options.push(el('option', { value, text: value }));
  }
  replace(select, options);
  select.value = values.includes(wanted) ? wanted : ANY;
  return select.value;
}

/** @param {object[]} records @param {string} key @returns {string[]} */
function distinct(records, key) {
  const seen = new Set();
  for (const record of records) {
    const value = record[key];
    if (typeof value === 'string' && value !== '') {
      seen.add(value);
    }
  }
  return [...seen].sort();
}

/**
 * Render the screen.
 *
 * @param {HTMLElement} container  Empty element to render into.
 * @param {object} ctx
 * @param {import('../api.js').Api} ctx.api
 * @param {object} ctx.session
 * @param {(path: string) => void} ctx.navigate
 * @param {(tone: string, message: string) => void} ctx.notify
 * @param {URLSearchParams} ctx.query
 * @param {(permission: string) => boolean} ctx.can
 * @returns {Promise<() => void>}
 */
export async function mount(container, ctx) {
  const state = {
    /** @type {object|null} The last envelope the router returned. */
    envelope: null,
    limit: DEFAULT_PAGE_SIZE,
    /**
     * Set false by the cleanup function. A refresh that resolves after the
     * operator has navigated away must not paint: `app.js` discards a stale
     * screen's writes, but a screen that knows it is gone should not make them.
     */
    live: true,
  };

  // The await happens before anything is rendered, so the shell's "Loading…"
  // line and `aria-busy` cover the first fetch without this screen owning a
  // loading state of its own.
  state.envelope = await fetchPage(ctx.api, state.limit);

  const tenant = String(ctx.session.tenant || 'this tenant');

  // ------------------------------------------------------------ integrity --

  const chainHost = el('div');

  /** @returns {Node[]} The chain-status block, rebuilt on every fetch. */
  function chainContent() {
    const envelope = state.envelope || {};
    const head = envelope.chain_head;
    const length = typeof envelope.chain_length === 'number' ? envelope.chain_length : null;

    let status;
    if (length === 0) {
      status = pill('Empty chain', 'neutral');
    } else if (isRealDigest(head)) {
      status = pill('Head reported', 'ok');
    } else {
      // Records exist but the head is absent or all-zero: something is wrong
      // between the store and this response, and an operator should not have to
      // notice a missing field to find out.
      status = pill('Head not reported', 'warn');
    }

    return [
      definitionList(
        [
          ['Chain status', status],
          ['Records in the chain', length === null ? null : formatCount(length)],
          ['Chain head', isRealDigest(head) ? el('span', { class: 'digest', text: head }) : null],
        ],
        { wide: true },
      ),
      el('p', {
        class: 'panel__note',
        text:
          'These values are what the router reported for its append-only chain. This screen does not recompute them — verification happens in the store, against the durable log, not in a browser. Each row below carries the truncated chain link at that record.',
      }),
      notAvailable(
        'Checkpoint verification',
        'Specification 11.2 defines periodic signed checkpoints exported to immutable storage; the management API exposes no route reporting when the chain was last checkpointed or verified, so this screen cannot say.',
      ),
    ];
  }

  // -------------------------------------------------------------- controls --

  const search = el('input', {
    type: 'search',
    autocomplete: 'off',
    spellcheck: 'false',
    placeholder: 'actor, object, reason…',
  });
  // A deep link may arrive pre-filtered — the link an operator pastes to a
  // colleague — but nothing is ever written back to the address bar.
  const seeded = (ctx.query && ctx.query.get('q')) || '';
  search.value = seeded.slice(0, 200);

  const actionSelect = el('select');
  const outcomeSelect = el('select');

  const sizeSelect = el(
    'select',
    {},
    PAGE_SIZES.map((size) =>
      el('option', { value: String(size), text: String(size), selected: size === state.limit }),
    ),
  );

  const clear = el('button', { type: 'button', class: 'button button--quiet' }, 'Clear filters');

  const refresh = actionButton('Refresh', () => reload(), {
    tone: 'quiet',
    busyLabel: 'Refreshing…',
  });

  const controls = toolbar(
    [
      inlineField({ id: 'audit-search', label: 'Contains', control: search }),
      inlineField({ id: 'audit-action', label: 'Action', control: actionSelect }),
      inlineField({ id: 'audit-outcome', label: 'Outcome', control: outcomeSelect }),
      inlineField({ id: 'audit-size', label: 'Fetch', control: sizeSelect }),
      clear,
      refresh,
    ],
    { label: 'Audit filters' },
  );

  // One live region for both the row count and the result of a refresh, so a
  // screen reader hears a single sentence rather than two competing ones.
  const status = el('p', { class: 'panel__note', role: 'status', 'aria-live': 'polite' });

  const tableHost = el('div');

  // ----------------------------------------------------------------- paint --

  /** @param {object} record @returns {boolean} */
  function matches(record) {
    const needle = search.value.trim().toLowerCase();
    if (needle !== '' && !haystack(record).includes(needle)) {
      return false;
    }
    if (actionSelect.value !== ANY && record.action !== actionSelect.value) {
      return false;
    }
    if (outcomeSelect.value !== ANY && record.outcome !== outcomeSelect.value) {
      return false;
    }
    return true;
  }

  /** @returns {boolean} Whether any filter is narrowing the page. */
  function filtering() {
    return search.value.trim() !== '' || actionSelect.value !== ANY || outcomeSelect.value !== ANY;
  }

  const columns = [
    {
      label: 'Time',
      cell: (row) => text(formatTime(row.timestamp)),
    },
    {
      label: 'Sequence',
      numeric: true,
      cell: (row) => text(formatCount(row.sequence)),
    },
    {
      label: 'Actor',
      cell: (row) => text(row.actor || '—'),
    },
    {
      label: 'Action',
      cell: (row) => text(row.action || '—'),
    },
    {
      label: 'Object',
      cell: (row) => text(row.object || '—'),
    },
    {
      label: 'Result',
      cell: (row) => (row.outcome ? pill(row.outcome, outcomeTone(row.outcome)) : text('—')),
    },
    {
      label: 'Reason',
      cell: (row) => text(row.reason || '—'),
    },
    {
      // The link is the record's position in the hash chain, truncated by the
      // router for display; it is what ties a row to the head above it.
      label: 'Chain link',
      cell: (row) => el('span', { class: 'mono', text: row.link || '—' }),
    },
  ];

  /** Rebuild the table, the chain block, and the status line from `state`. */
  function paint() {
    const records = recordsOf(state.envelope);
    const rows = records.filter(matches);

    replace(chainHost, chainContent());

    if (rows.length > 0) {
      replace(
        tableHost,
        table({
          caption: `Audit records for tenant ${tenant}, newest first`,
          columns,
          rows,
        }),
      );
    } else if (records.length > 0) {
      // The page is not empty; the filters emptied it. Saying which is the
      // difference between "nothing happened" and "you are looking past it".
      replace(
        tableHost,
        emptyState(
          'No record on this page matches the filters',
          `Filtering runs in the browser over the ${formatCount(records.length)} records fetched. Clear the filters, or fetch more, to look further back.`,
        ),
      );
    } else {
      replace(
        tableHost,
        emptyState(
          `No audit records for tenant ${tenant}`,
          'The router returned an empty page. Management visibility never exceeds the caller’s tenant, and router-wide records that carry no tenant are not exposed through this endpoint, so a tenant that has taken no administrative action shows nothing here.',
        ),
      );
    }

    const chainLength = state.envelope && typeof state.envelope.chain_length === 'number'
      ? formatCount(state.envelope.chain_length)
      : 'an unreported number of';
    status.textContent = filtering()
      ? `Showing ${formatCount(rows.length)} of ${formatCount(records.length)} fetched records; the chain holds ${chainLength}.`
      : `Showing ${formatCount(records.length)} most recent records; the chain holds ${chainLength}.`;
  }

  /** Rebuild the filter selects from the current page, keeping valid choices. */
  function syncOptions() {
    const records = recordsOf(state.envelope);
    fillOptions(actionSelect, distinct(records, 'action'), 'Any action');
    fillOptions(outcomeSelect, distinct(records, 'outcome'), 'Any result');
  }

  /**
   * Fetch again at the current page size.
   *
   * Controls are disabled for the duration: two overlapping fetches would race
   * to paint, and the `api` singleton would abort the first one anyway.
   *
   * @returns {Promise<void>}
   */
  async function reload() {
    sizeSelect.disabled = true;
    tableHost.setAttribute('aria-busy', 'true');
    try {
      const envelope = await fetchPage(ctx.api, state.limit);
      if (!state.live) {
        return;
      }
      state.envelope = envelope;
      syncOptions();
      paint();
    } finally {
      if (state.live) {
        sizeSelect.disabled = false;
        tableHost.removeAttribute('aria-busy');
      }
    }
  }

  search.addEventListener('input', paint);
  actionSelect.addEventListener('change', paint);
  outcomeSelect.addEventListener('change', paint);

  clear.addEventListener('click', () => {
    search.value = '';
    actionSelect.value = ANY;
    outcomeSelect.value = ANY;
    paint();
    search.focus();
  });

  sizeSelect.addEventListener('change', () => {
    const parsed = Number.parseInt(sizeSelect.value, 10);
    state.limit = Number.isFinite(parsed) ? parsed : DEFAULT_PAGE_SIZE;
    // A rejection here reaches the shell's `unhandledrejection` boundary, which
    // is the one place that knows how to name an `ApiError` and its request id.
    void reload();
  });

  // ---------------------------------------------------------------- render --

  const exportDetail = ctx.can('export_audit')
    ? 'This session holds export_audit, but no route implements it. A download built in the browser is not an export: it would leave no audit_exported record in the chain and would carry no signature.'
    : 'A download built in the browser is not an export: it would leave no audit_exported record in the chain and would carry no signature.';

  render(container, [
    pageHeader(meta.title, meta.lede),
    panel({
      title: 'Chain integrity',
      content: chainHost,
      note: 'What makes the log evidence rather than a list.',
    }),
    panel({
      title: 'Records',
      content: [controls, status, tableHost],
      note: `The router returns the most recent records for tenant ${tenant}; filtering below runs in the browser over that page, not across the whole chain.`,
    }),
    notAvailable('Audit export', exportDetail),
  ]);

  syncOptions();
  paint();

  return () => {
    state.live = false;
  };
}
