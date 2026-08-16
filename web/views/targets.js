/**
 * The Targets screen.
 *
 * Specification 15.3: "Add/edit fixed endpoints, capability declaration,
 * maintenance/drain/quarantine, safe test."
 *
 * What the router actually exposes today shapes this screen, and the gaps are
 * named rather than papered over:
 *
 * - **Nothing here creates or edits a target.** `GET /admin/v1/targets` lists
 *   what the active configuration snapshot holds; there is no create or replace
 *   endpoint (`handlers.rs` dispatches only `GET /targets` and
 *   `PATCH /targets/{id}`). A target's provider, model, endpoint, and declared
 *   capabilities come from configuration, which is changed by publishing a
 *   policy draft. A create form would be a form whose submit button cannot
 *   exist, and an operator who trusts one is an operator who is surprised
 *   during an incident.
 * - **The administrative state is the one mutable thing**, and every change
 *   goes through `PATCH /admin/v1/targets/{id}` — drain, maintenance,
 *   quarantine, disable, and the restoration of any of them.
 * - **The safe test of 15.3 has no endpoint.** It is declared missing through
 *   the shared `notAvailable` block; no synthetic result is shown.
 *
 * Two decisions about the mutation path are worth stating plainly, because both
 * are weaker than they look at first glance and an operator should know which
 * guarantee they are relying on:
 *
 * - **`If-Match` is `*`, and that is forced.** The router computes a target's
 *   entity tag over the *rendered* row (`etag_for(&render_target(target))`),
 *   which includes `in_flight`, `total_requests`, and `total_failures`. The
 *   list response carries no `ETag` header at all (`ApiResponse::ok`), and there
 *   is no per-target `GET`, so the exact tag is not obtainable by a browser —
 *   and even if it were, it would be stale again the moment the target served a
 *   request. `*` is the only precondition this client can honestly present.
 * - **So the drift check is done here, explicitly.** Before a change is sent,
 *   the list is re-read and the target's `state` and `quarantined` are compared
 *   with what the operator was actually shown. A target that moved underneath
 *   them is reported and the change is abandoned, not overwritten. This closes
 *   the window an operator can perceive; it does not close the race inside the
 *   router, which is the server's to close when it publishes a stable tag.
 *
 * Specification 15.4 — "optimistic UI only for reversible view state, never for
 * security-sensitive mutations" — is why filtering repaints immediately and a
 * state change repaints nothing until the router has answered and the list has
 * been read back.
 */

import { ApiError } from '../api.js';
import { el, formatCount, pill } from '../components/dom.js';
import {
  actionButton,
  confirmPrompt,
  definitionList,
  emptyState,
  inlineField,
  morePager,
  notAvailable,
  panel,
  toolbar,
} from '../components/layout.js';
import { buttonRow, card, field, grid, pageHeader, render, stat, table } from '../components/table.js';

/** Screen metadata, read by the router to build navigation. */
export const meta = {
  path: '/targets',
  title: 'Targets',
  // `GET /admin/v1/targets` requires `Permission::ReadSummary`, so a viewer
  // reaches the screen and reads it; the controls below are gated separately on
  // `operate_targets` and `quarantine_targets`, which is where the router
  // enforces them too.
  permission: 'read_summary',
  lede:
    'Every target the active configuration defines, its declared capabilities, its live health, and the administrative state an operator may change.',
};

/**
 * The administrative states `PATCH /admin/v1/targets/{id}` accepts.
 *
 * The values are `hypellm_core::target::AdminState::as_str`; the descriptions are
 * that enum's own documentation, so the screen and the router cannot drift into
 * describing a state differently.
 */
const STATES = [
  {
    value: 'enabled',
    label: 'Enabled',
    tone: 'ok',
    effect: 'The target is selectable for new requests.',
  },
  {
    value: 'draining',
    label: 'Draining',
    tone: 'warn',
    effect: 'The target accepts no new requests; requests already in flight finish.',
  },
  {
    value: 'maintenance',
    label: 'Maintenance',
    tone: 'warn',
    effect: 'The target is withdrawn from selection for planned work.',
  },
  {
    value: 'quarantined',
    label: 'Quarantined',
    tone: 'danger',
    effect:
      'The target is withdrawn and automated recovery is overridden until the quarantine expires. A reason is required and is written to the audit log.',
  },
  {
    value: 'disabled',
    label: 'Disabled',
    tone: 'neutral',
    effect: 'The target stays configured but is switched off.',
  },
];

/** Circuit-breaker states, from `hypellm_core::health::BreakerState::as_str`. */
const BREAKERS = {
  closed: { label: 'Closed', tone: 'ok' },
  open: { label: 'Open', tone: 'danger' },
  half_open: { label: 'Half open', tone: 'warn' },
};

/** The default quarantine window the router applies when none is supplied. */
const DEFAULT_QUARANTINE_SECONDS = 3600;

/**
 * The identifier grammar of `hypellm_core::ids` (`MAX_ID_LEN` is 128).
 *
 * The router matches `/admin/v1/targets/{id}` on the raw path and does *not*
 * percent-decode the segment, so percent-encoding an identifier here would
 * produce a 404 rather than a safe request. Checking the value against the
 * grammar the router itself accepts is the correct defence: nothing that is not
 * already a valid identifier is ever spliced into a request path.
 */
const ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

/**
 * The mutation path for a target.
 *
 * @param {string} id
 * @returns {string}
 * @throws {Error} When the identifier is not one the router could have issued.
 */
function targetPath(id) {
  if (!ID_PATTERN.test(String(id))) {
    throw new Error('the router returned a target identifier this screen will not place in a URL');
  }
  return `/targets/${id}`;
}

/** @param {string} value @returns {object} */
function stateInfo(value) {
  return (
    STATES.find((entry) => entry.value === value) || {
      value,
      // An unknown state means this screen is older than the router. Showing the
      // raw token is more useful than inventing a label for it.
      label: String(value || 'unknown'),
      tone: 'neutral',
      effect: 'This screen does not recognise the state the router reported.',
    }
  );
}

/** @param {object} target @returns {HTMLElement} */
function statePill(target) {
  const info = stateInfo(target.state);
  return pill(info.label, info.tone);
}

/**
 * Health as the router reports it: breaker state, plus quarantine when set.
 *
 * `state` and `quarantined` are separate fields and can disagree — a quarantine
 * is held in live health, not in the configuration snapshot — so both are shown
 * rather than one being derived from the other.
 *
 * @param {object} target
 * @returns {HTMLElement}
 */
function healthCell(target) {
  const breaker = BREAKERS[target.breaker_state] || {
    label: String(target.breaker_state || 'unknown'),
    tone: 'neutral',
  };
  return el('span', { class: 'pill-row' }, [
    pill(breaker.label, breaker.tone),
    target.quarantined ? pill('Quarantined', 'danger') : null,
  ]);
}

/** @param {unknown} value @returns {number|null} */
function numberOf(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/** @param {boolean} value @returns {string} */
function yesNo(value) {
  return value === true ? 'Yes' : value === false ? 'No' : '—';
}

/**
 * Share of requests that failed, computed from the two counters the router
 * returned. Nothing is estimated: with no requests there is no rate.
 *
 * @param {object} target
 * @returns {string|null}
 */
function failureRate(target) {
  const total = numberOf(target.total_requests);
  const failures = numberOf(target.total_failures);
  if (total === null || failures === null || total === 0) {
    return null;
  }
  return `${((failures / total) * 100).toFixed(1)}%`;
}

/**
 * One line an operator can act on.
 *
 * `app.js` owns the same formatting for the shell banner, but a screen that
 * writes into its own status region needs it too, and the request id is the
 * handle that ties what was seen to the structured log (specification 17).
 *
 * @param {unknown} error
 * @returns {string}
 */
function explain(error) {
  if (error instanceof ApiError) {
    const parts = [error.message];
    if (Array.isArray(error.details) && error.details.length > 0) {
      parts.push(error.details.map((detail) => String(detail)).join('; '));
    }
    if (error.requestId) {
      parts.push(`request ${error.requestId}`);
    }
    return parts.join(' — ');
  }
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return 'an unexpected fault occurred';
}

/**
 * Render the screen.
 *
 * @param {HTMLElement} container Empty element to render into.
 * @param {object} ctx
 * @param {import('../api.js').Api} ctx.api
 * @param {object} ctx.session
 * @param {(path: string) => void} ctx.navigate
 * @param {(tone: string, message: string) => void} ctx.notify
 * @param {(permission: string) => boolean} ctx.can
 * @returns {Promise<void>}
 */
export async function mount(container, ctx) {
  const canOperate = ctx.can('operate_targets');
  const canQuarantine = ctx.can('quarantine_targets');

  const view = {
    /** @type {object[]} Every target loaded, in the order the router listed them. */
    rows: [],
    /** @type {object|null} The most recent list envelope, for the pager. */
    envelope: null,
    /** @type {Map<string, object>|null} Providers by id, for endpoint display. */
    providers: null,
    /** @type {string|null} Why the provider list is absent, when it is. */
    providersError: null,
    filters: { state: 'all', health: 'all', text: '' },
    /** @type {string|null} The target whose detail panel is open. */
    selected: null,
    /** Survives a repaint so a refresh does not discard what was typed. */
    draft: { state: '', reason: '', duration: String(DEFAULT_QUARANTINE_SECONDS) },
    /**
     * The last thing the form said. Held here rather than only in the node,
     * because the outcome of a change is written at the moment the panel is
     * rebuilt from fresh data — and an operator should not lose the sentence
     * explaining what just happened to their target.
     */
    status: '',
  };

  /** @type {Map<string, HTMLButtonElement>} Row buttons, for returning focus. */
  const rowButtons = new Map();

  // ---------------------------------------------------------------- loading -

  /** Read the first page of targets, replacing whatever was loaded. */
  async function loadTargets() {
    const { data } = await ctx.api.get('/targets');
    view.rows = Array.isArray(data.data) ? data.data.slice() : [];
    view.envelope = data;
  }

  /**
   * Read the providers, for the fixed endpoints of specification 15.3.
   *
   * A failure here is not a failure of the screen: the target list is the
   * point, and the endpoints are context. It is recorded and shown as absent
   * rather than being allowed to blank the page.
   */
  async function loadProviders() {
    try {
      const { data } = await ctx.api.get('/providers');
      const entries = Array.isArray(data.data) ? data.data : [];
      view.providers = new Map(entries.map((provider) => [provider.id, provider]));
      view.providersError = null;
    } catch (error) {
      if (error && error.name === 'AbortError') {
        throw error;
      }
      view.providers = null;
      view.providersError = explain(error);
    }
  }

  async function loadAll() {
    await loadTargets();
    await loadProviders();
  }

  /** Append the next page. */
  async function loadMore(cursor) {
    // The cursor is opaque and came from the router; it travels as a query
    // value, which the router does percent-decode.
    const { data } = await ctx.api.get(`/targets?after=${encodeURIComponent(cursor)}`);
    const next = Array.isArray(data.data) ? data.data : [];
    view.rows = view.rows.concat(next);
    view.envelope = data;
    paintAll();
  }

  // --------------------------------------------------------------- filtering -

  /** @returns {object[]} */
  function filtered() {
    const needle = view.filters.text.trim().toLowerCase();
    return view.rows.filter((row) => {
      if (view.filters.state !== 'all' && row.state !== view.filters.state) {
        return false;
      }
      if (view.filters.health === 'healthy' && (row.breaker_state !== 'closed' || row.quarantined)) {
        return false;
      }
      if (view.filters.health === 'impaired' && row.breaker_state === 'closed' && !row.quarantined) {
        return false;
      }
      if (needle !== '') {
        const haystack = `${row.id} ${row.provider} ${row.model}`.toLowerCase();
        if (!haystack.includes(needle)) {
          return false;
        }
      }
      return true;
    });
  }

  const stateFilter = el(
    'select',
    {},
    [el('option', { value: 'all' }, 'Any state')].concat(
      STATES.map((entry) => el('option', { value: entry.value }, entry.label)),
    ),
  );
  stateFilter.addEventListener('change', () => {
    view.filters.state = stateFilter.value;
    paintList();
  });

  const healthFilter = el('select', {}, [
    el('option', { value: 'all' }, 'Any health'),
    el('option', { value: 'healthy' }, 'Breaker closed, not quarantined'),
    el('option', { value: 'impaired' }, 'Breaker open or quarantined'),
  ]);
  healthFilter.addEventListener('change', () => {
    view.filters.health = healthFilter.value;
    paintList();
  });

  const textFilter = el('input', { type: 'text', autocomplete: 'off', spellcheck: 'false' });
  textFilter.addEventListener('input', () => {
    view.filters.text = textFilter.value;
    paintList();
  });

  const clearFilters = () => {
    view.filters = { state: 'all', health: 'all', text: '' };
    stateFilter.value = 'all';
    healthFilter.value = 'all';
    textFilter.value = '';
    paintList();
  };

  const filterRow = toolbar(
    [
      inlineField({ id: 'targets-filter-state', label: 'Administrative state', control: stateFilter }),
      inlineField({ id: 'targets-filter-health', label: 'Health', control: healthFilter }),
      inlineField({ id: 'targets-filter-text', label: 'Identifier, provider, or model', control: textFilter }),
    ],
    { label: 'Filter the target list' },
  );

  // ----------------------------------------------------------------- layout -

  const summaryBox = el('div');
  const tableBox = el('div');
  const scopeNote = el('p', { class: 'panel__note' });
  const detailBox = el('div');
  const pagerBox = el('div');

  const refreshButton = actionButton(
    'Re-read from the router',
    async () => {
      await loadAll();
      paintAll();
    },
    { tone: 'quiet', busyLabel: 'Reading…' },
  );

  const listPanel = panel({
    title: 'Configured targets',
    note: 'Read from the active configuration snapshot together with live health at the moment of the request. Nothing on this screen polls; use the button to re-read.',
    actions: [refreshButton],
    content: [filterRow, scopeNote, tableBox],
  });

  /** How the definition of a target is actually changed. */
  const definitionCard = card('Adding and editing a target', [
    el('p', {
      class: 'page-lede',
      text: 'A target — its provider, native model, endpoint, capabilities, cost class, and residency — is defined in the router configuration. The management API exposes no endpoint that creates or replaces one, so this screen offers no form that would pretend to.',
    }),
    el('p', {
      class: 'page-lede',
      text: 'Changing a definition means publishing a new configuration: draft it, validate it, simulate it, and publish it from the policy screen. Activation is atomic and requests in flight keep the snapshot they started with.',
    }),
    buttonRow([
      actionButton('Go to routing policies', () => ctx.navigate('/policies'), { tone: 'quiet' }),
    ]),
  ]);

  const testCard = card(
    'Safe test',
    notAvailable(
      'Sending a safe test request to a target',
      'The nearest thing the router does expose is the decision trace for a request that already happened, on the decision explorer.',
    ),
  );

  // ---------------------------------------------------------------- painting -

  function paintSummary() {
    const rows = view.rows;
    const admitting = rows.filter((row) => row.state === 'enabled' && !row.quarantined).length;
    const withdrawn = rows.filter((row) => row.state !== 'enabled').length;
    const impaired = rows.filter((row) => row.breaker_state !== 'closed').length;
    const inFlight = rows.reduce((total, row) => total + (numberOf(row.in_flight) || 0), 0);
    const more = Boolean(view.envelope && view.envelope.has_more);

    render(
      summaryBox,
      grid([
        stat('Targets loaded', formatCount(rows.length), more ? 'More pages remain' : 'The whole list'),
        stat('Admitting requests', formatCount(admitting), 'Enabled and not quarantined'),
        stat('Withdrawn', formatCount(withdrawn), 'Draining, maintenance, quarantined, or disabled'),
        stat('Breaker not closed', formatCount(impaired), 'Open or half open'),
        stat('Requests in flight', formatCount(inFlight), 'Summed across loaded targets'),
      ]),
    );
  }

  function paintList() {
    rowButtons.clear();
    const rows = filtered();
    const more = Boolean(view.envelope && view.envelope.has_more);

    scopeNote.hidden = !more;
    if (more) {
      scopeNote.textContent =
        'The router returned more targets than this page holds. Filters apply only to the targets loaded so far — load the remaining pages to search the rest.';
    }

    if (view.rows.length === 0) {
      render(
        tableBox,
        emptyState(
          'The router reported no targets',
          'The active configuration snapshot defines none, so nothing can be routed yet. A target is added by publishing a configuration draft.',
        ),
      );
      return;
    }

    if (rows.length === 0) {
      render(tableBox, [
        emptyState(
          'No loaded target matches these filters',
          `${formatCount(view.rows.length)} targets are loaded; none of them matches the current state, health, and text filters.`,
        ),
        buttonRow([actionButton('Clear the filters', clearFilters, { tone: 'quiet' })]),
      ]);
      return;
    }

    render(
      tableBox,
      table({
        caption: `Configured targets — showing ${formatCount(rows.length)} of ${formatCount(view.rows.length)} loaded.`,
        columns: [
          { label: 'Target', cell: (row) => el('span', { class: 'mono', text: row.id }) },
          { label: 'Provider', cell: (row) => el('span', { class: 'mono', text: row.provider }) },
          { label: 'Model', cell: (row) => el('span', { class: 'mono', text: row.model }) },
          { label: 'Locality', cell: (row) => (row.local === true ? 'Local' : row.local === false ? 'Remote' : '—') },
          { label: 'State', cell: statePill },
          { label: 'Health', cell: healthCell },
          { label: 'In flight', numeric: true, cell: (row) => formatCount(numberOf(row.in_flight)) },
          { label: 'Requests', numeric: true, cell: (row) => formatCount(numberOf(row.total_requests)) },
          { label: 'Failures', numeric: true, cell: (row) => formatCount(numberOf(row.total_failures)) },
          {
            label: 'Detail',
            cell: (row) => {
              const button = actionButton(
                canOperate ? 'Manage' : 'Inspect',
                () => {
                  openTarget(row.id);
                },
                { tone: 'quiet' },
              );
              // The visible label repeats down the column, so the accessible
              // name carries the identifier the button actually acts on.
              button.setAttribute(
                'aria-label',
                `${canOperate ? 'Manage' : 'Inspect'} target ${row.id}`,
              );
              rowButtons.set(row.id, button);
              return button;
            },
          },
        ],
        rows,
      }),
    );
  }

  function paintPager() {
    const pager = morePager(view.envelope, (cursor) => loadMore(cursor));
    pagerBox.hidden = pager === null;
    render(pagerBox, pager || []);
  }

  /**
   * Open a target's detail panel.
   *
   * @param {string} id
   */
  function openTarget(id) {
    const target = view.rows.find((row) => row.id === id);
    if (!target) {
      return;
    }
    view.selected = id;
    view.status = '';
    view.draft = {
      state: target.state,
      reason: '',
      duration: String(DEFAULT_QUARANTINE_SECONDS),
    };
    paintDetail(true);
  }

  /** Close the panel and hand focus back to the row it was opened from. */
  function closeTarget() {
    const previous = view.selected;
    view.selected = null;
    paintDetail(false);
    const button = previous === null ? null : rowButtons.get(previous);
    if (button && button.isConnected) {
      button.focus();
    }
  }

  /** @param {boolean} [focusDetail] Whether the detail panel should take focus. */
  function paintAll(focusDetail = false) {
    paintSummary();
    paintList();
    paintPager();
    paintDetail(focusDetail);
  }

  /**
   * The detail panel: everything the router said about one target, and the only
   * mutation this screen performs.
   *
   * @param {boolean} focus Whether to move focus to the panel.
   */
  function paintDetail(focus) {
    if (view.selected === null) {
      detailBox.hidden = true;
      render(detailBox, []);
      return;
    }

    const target = view.rows.find((row) => row.id === view.selected);
    if (!target) {
      // The target left the configuration between paints. Saying so beats an
      // empty panel or a silently closed one.
      detailBox.hidden = false;
      render(
        detailBox,
        panel({
          title: 'That target is gone',
          actions: [actionButton('Close', closeTarget, { tone: 'quiet' })],
          content: emptyState(
            'The target is no longer in the list the router returned',
            'It was removed from the configuration, or it moved to a page that is not loaded.',
          ),
        }),
      );
      return;
    }

    const rate = failureRate(target);
    const facts = definitionList([
      ['Identifier', el('span', { class: 'mono', text: target.id })],
      ['Provider', el('span', { class: 'mono', text: target.provider })],
      ['Native model', el('span', { class: 'mono', text: target.model })],
      ['Administrative state', statePill(target)],
      ['Circuit breaker', healthCell(target)],
      ['Locality', target.local === true ? 'Local inference' : target.local === false ? 'Remote provider' : '—'],
      ['Cost class', formatCount(numberOf(target.cost_class))],
      ['Residency', target.residency || null],
      ['Requests in flight', formatCount(numberOf(target.in_flight))],
      ['Requests total', formatCount(numberOf(target.total_requests))],
      ['Failures total', rate === null ? formatCount(numberOf(target.total_failures)) : `${formatCount(numberOf(target.total_failures))} (${rate})`],
    ]);

    const capabilities = target.capabilities || {};
    const operations = Array.isArray(capabilities.operations) ? capabilities.operations : [];
    const capabilityFacts = definitionList([
      ['Operations', operations.length > 0 ? operations.join(', ') : null],
      ['Streaming', yesNo(capabilities.streaming)],
      ['Tool calls', yesNo(capabilities.tools)],
      ['JSON mode', yesNo(capabilities.json_mode)],
      ['Structured output', yesNo(capabilities.structured_output)],
      ['Maximum context tokens', formatCount(numberOf(capabilities.max_context_tokens))],
      ['Maximum output tokens', formatCount(numberOf(capabilities.max_output_tokens))],
    ]);

    const detailSection = panel({
      title: `Target ${target.id}`,
      note: 'Definition and declared capabilities come from the active configuration and are read-only here. Only the administrative state can be changed.',
      actions: [actionButton('Close', closeTarget, { tone: 'quiet' })],
      content: [
        facts,
        el('h3', { class: 'card__title', text: 'Declared capabilities' }),
        el('p', {
          class: 'panel__note',
          text: 'Capabilities are declared in configuration, not discovered from the provider. Routing treats them as eligibility filters, so a wrong declaration excludes work rather than degrading it.',
        }),
        capabilityFacts,
        el('h3', { class: 'card__title', text: 'Fixed endpoints' }),
        endpointBlock(target),
        el('h3', { class: 'card__title', text: 'Administrative state' }),
        stateControls(target),
      ],
    });

    detailSection.tabIndex = -1;
    detailSection.setAttribute('aria-label', `Detail for target ${target.id}`);
    detailBox.hidden = false;
    render(detailBox, detailSection);
    if (focus) {
      detailSection.focus();
    }
  }

  /**
   * The provider's configured endpoints.
   *
   * A target names an endpoint by index inside its provider, and the list
   * response does not report which index — so every endpoint the provider has is
   * shown, and the ambiguity is stated instead of being resolved by guesswork.
   *
   * @param {object} target
   * @returns {Node}
   */
  function endpointBlock(target) {
    if (view.providers === null) {
      return el('p', {
        class: 'panel__note',
        text: `The provider list could not be read, so the endpoint behind this target is not shown (${view.providersError || 'reason unknown'}).`,
      });
    }
    const provider = view.providers.get(target.provider);
    if (!provider || !Array.isArray(provider.endpoints) || provider.endpoints.length === 0) {
      return el('p', {
        class: 'panel__note',
        text: "The router reported no endpoint for this target's provider.",
      });
    }

    const lines = provider.endpoints.map((endpoint) =>
      el('div', {
        class: 'mono',
        text: `${endpoint.scheme}://${endpoint.host}:${endpoint.port}${endpoint.base_path}`,
      }),
    );

    return el('div', {}, [
      definitionList([
        ['Provider family', provider.family || null],
        ['Provider enabled', yesNo(provider.enabled)],
        ['Egress profile', provider.egress_profile || null],
        ['Credential reference', provider.credential_ref ? el('span', { class: 'mono', text: provider.credential_ref }) : null],
        ['Endpoints', el('div', {}, lines)],
      ]),
      el('p', {
        class: 'panel__note',
        text: provider.endpoints.length > 1
          ? 'Destinations are fixed in configuration and never influenced by a request. The list response does not say which of these endpoints this target uses, so all of them are shown.'
          : 'Destinations are fixed in configuration and never influenced by a request.',
      }),
    ]);
  }

  /**
   * The state-change form.
   *
   * Everything destructive is confirmed before anything is sent, and nothing on
   * screen changes until the router has answered and the list has been read
   * back (specification 15.4).
   *
   * @param {object} target
   * @returns {Node}
   */
  function stateControls(target) {
    if (!canOperate) {
      return el('p', {
        class: 'panel__note',
        text: "Changing a target's administrative state requires the operate_targets permission. This session can read the target but not act on it.",
      });
    }
    if (target.state === 'quarantined' && !canQuarantine) {
      return el('p', {
        class: 'panel__note',
        text: 'This target is quarantined. Lifting a quarantine is itself a quarantine-level action and requires the quarantine_targets permission, which this session does not hold.',
      });
    }

    const choices = canQuarantine ? STATES : STATES.filter((entry) => entry.value !== 'quarantined');

    const status = el('p', { class: 'status-line', role: 'status', 'aria-live': 'polite' });
    status.textContent = view.status;
    /** @param {string} message */
    const say = (message) => {
      view.status = message;
      status.textContent = message;
    };

    const stateChoice = el(
      'select',
      {},
      choices.map((entry) => el('option', { value: entry.value }, entry.label)),
    );
    stateChoice.value = choices.some((entry) => entry.value === view.draft.state)
      ? view.draft.state
      : choices[0].value;
    view.draft.state = stateChoice.value;

    const reason = el('input', { type: 'text', autocomplete: 'off', maxlength: '200' });
    reason.value = view.draft.reason;
    reason.addEventListener('input', () => {
      view.draft.reason = reason.value;
    });

    const duration = el('input', { type: 'number', min: '60', max: '604800', step: '60' });
    duration.value = view.draft.duration;
    duration.addEventListener('input', () => {
      view.draft.duration = duration.value;
    });

    const durationField = field({
      id: 'target-duration',
      label: 'Quarantine duration in seconds',
      hint: `How long the router holds the quarantine before releasing it. It applies ${DEFAULT_QUARANTINE_SECONDS} seconds when none is given.`,
      control: duration,
    });
    // `.field` sets `display: flex`, which an author stylesheet wins over the
    // `hidden` attribute — so the wrapper, which carries no display rule, is
    // what gets hidden.
    const durationBox = el('div', {}, durationField);

    const syncDuration = () => {
      durationBox.hidden = stateChoice.value !== 'quarantined';
    };
    syncDuration();

    stateChoice.addEventListener('change', () => {
      view.draft.state = stateChoice.value;
      syncDuration();
      say(stateInfo(stateChoice.value).effect);
    });

    const confirmBox = el('div');
    confirmBox.hidden = true;

    const apply = actionButton('Apply state change', () => {
      startChange();
    });

    /** Validate, then ask for confirmation. Nothing is sent from here. */
    function startChange() {
      const desired = stateChoice.value;
      const info = stateInfo(desired);

      if (desired === target.state) {
        say(`The router already reports this target as ${info.label.toLowerCase()}. Nothing was sent.`);
        return;
      }
      if (desired === 'quarantined' && view.draft.reason.trim() === '') {
        say('A quarantine requires a reason; the router rejects one without it and the reason is what the audit record carries.');
        reason.focus();
        return;
      }

      const detail =
        desired === 'quarantined'
          ? `${info.effect} The reason and this principal are written to the audit log.`
          : `${info.effect} The change is recorded in the audit log.`;

      const prompt = confirmPrompt({
        message: `Move ${target.id} from ${stateInfo(target.state).label.toLowerCase()} to ${info.label.toLowerCase()}?`,
        detail,
        confirmLabel: `Yes, ${info.label.toLowerCase()} it`,
        // A typed phrase is reserved for the action that overrides the router's
        // own recovery; applying it to every state change would make it
        // something operators type without reading.
        phrase: desired === 'quarantined' ? target.id : undefined,
        onConfirm: () => sendChange(target, desired),
        onCancel: () => {
          confirmBox.hidden = true;
          render(confirmBox, []);
          apply.disabled = false;
          apply.focus();
          say('Nothing was sent.');
        },
      });

      apply.disabled = true;
      confirmBox.hidden = false;
      render(confirmBox, prompt);
      say(`Confirm to send the change. ${info.effect}`);
    }

    /**
     * Re-read, compare, send, and read back.
     *
     * @param {object} snapshot The row the operator was shown.
     * @param {string} desired
     * @returns {Promise<void>}
     */
    async function sendChange(snapshot, desired) {
      say('Re-reading the target so the change is applied to what the router holds now…');

      try {
        await loadTargets();
      } catch (error) {
        if (error && error.name === 'AbortError') {
          return;
        }
        say(`The target could not be re-read, so nothing was sent: ${explain(error)}`);
        ctx.notify('error', `Nothing was changed. ${explain(error)}`);
        return;
      }

      const current = view.rows.find((row) => row.id === snapshot.id);
      if (!current) {
        say('The target is no longer in the configuration the router returned. Nothing was sent.');
        paintAll();
        ctx.notify('warn', `${snapshot.id} is no longer a configured target; nothing was changed.`);
        return;
      }
      if (current.state !== snapshot.state || Boolean(current.quarantined) !== Boolean(snapshot.quarantined)) {
        // This is the comparison `If-Match: *` cannot make on the operator's
        // behalf: what they were shown, against what the router holds now.
        say('The target changed since this screen read it, so nothing was sent. Review it and decide again.');
        paintAll();
        ctx.notify(
          'warn',
          `${snapshot.id} moved to ${stateInfo(current.state).label.toLowerCase()} under you; nothing was changed.`,
        );
        return;
      }

      const body = { state: desired };
      const trimmed = view.draft.reason.trim();
      if (trimmed !== '') {
        body.reason = trimmed;
      }
      if (desired === 'quarantined') {
        const seconds = Number.parseInt(view.draft.duration, 10);
        if (Number.isFinite(seconds) && seconds > 0) {
          body.duration_seconds = seconds;
        }
      }

      say('Sending the change to the router…');
      let result;
      try {
        // `If-Match: *` — see the note at the top of this module. The router
        // accepts it per RFC 9110, and it is the only precondition a browser can
        // present while the list carries no per-target entity tag.
        const response = await ctx.api.patch(targetPath(snapshot.id), body, '*');
        result = response.data;
      } catch (error) {
        if (error && error.name === 'AbortError') {
          return;
        }
        const message =
          error instanceof ApiError && error.isStale
            ? `The router reports the target changed since it was read: ${explain(error)}`
            : error instanceof ApiError && error.needsReauthentication
              ? `This action needs a fresher sign-in: ${explain(error)}`
              : explain(error);
        say(`The change was refused. ${message}`);
        ctx.notify('error', `${snapshot.id} was not changed. ${message}`);
        // Read back regardless: after a refusal the screen should show the
        // router's state, not the state the operator was hoping for.
        try {
          await loadTargets();
          paintAll();
        } catch (readError) {
          if (!readError || readError.name !== 'AbortError') {
            ctx.notify('warn', `The list could not be re-read: ${explain(readError)}`);
          }
        }
        return;
      }

      // No optimistic paint: the list is read back and the panel rebuilt from
      // what the router now reports.
      try {
        await loadTargets();
      } catch (error) {
        if (!error || error.name !== 'AbortError') {
          ctx.notify(
            'warn',
            `The change was accepted but the list could not be re-read: ${explain(error)}`,
          );
        }
      }

      const confirmedState = result && result.state ? String(result.state) : desired;
      view.draft = {
        state: confirmedState,
        reason: '',
        duration: String(DEFAULT_QUARANTINE_SECONDS),
      };
      say(`The router accepted the change and reports the target as ${stateInfo(confirmedState).label.toLowerCase()}.`);
      paintAll(true);
      // The router reports the administrative state and the live quarantine
      // separately, so the two are only both worth saying when they disagree.
      const alsoQuarantined =
        confirmedState !== 'quarantined' && Boolean(result && result.quarantined);
      ctx.notify(
        'ok',
        `${snapshot.id} is now ${stateInfo(confirmedState).label.toLowerCase()}${alsoQuarantined ? ', and remains quarantined' : ''}.`,
      );
    }

    return el('div', {}, [
      el('p', {
        class: 'panel__note',
        text: 'The list endpoint publishes no per-target entity tag, so a change is sent with If-Match: * after the target has been re-read and compared with what you were shown. A target that moved underneath you is reported, never overwritten.',
      }),
      field({
        id: 'target-state',
        label: 'New administrative state',
        hint: "Enabled admits new requests. Draining admits none and lets in-flight requests finish. Maintenance and disabled withdraw the target. Quarantine additionally overrides the router's automated recovery.",
        control: stateChoice,
      }),
      field({
        id: 'target-reason',
        label: 'Reason',
        hint: 'Recorded in the audit log against this principal. Required for a quarantine, and worth writing for anything an on-call engineer will read later.',
        control: reason,
      }),
      durationBox,
      buttonRow([apply]),
      confirmBox,
      status,
    ]);
  }

  // ------------------------------------------------------------------- boot -

  /** @param {unknown} error */
  function renderLoadFailure(error) {
    render(container, [
      pageHeader(meta.title, meta.lede),
      panel({
        title: 'The target list could not be read',
        content: [
          el('p', { class: 'page-lede', text: explain(error) }),
          el('p', {
            class: 'panel__note',
            text: 'Nothing is shown rather than a stale or partial list: an operator acting on targets needs to know this is what the router holds now.',
          }),
          buttonRow([
            actionButton(
              'Try again',
              async () => {
                await loadAll();
                build();
              },
              { busyLabel: 'Reading…' },
            ),
          ]),
        ],
      }),
    ]);
  }

  function build() {
    render(container, [
      pageHeader(meta.title, meta.lede),
      summaryBox,
      listPanel,
      detailBox,
      pagerBox,
      definitionCard,
      testCard,
    ]);
    paintAll();
  }

  try {
    // Awaiting before the first paint is what earns the shell's loading state.
    await loadAll();
  } catch (error) {
    if (error && error.name === 'AbortError') {
      // Navigation, not failure. The shell swallows it.
      throw error;
    }
    renderLoadFailure(error);
    return;
  }

  build();
}
