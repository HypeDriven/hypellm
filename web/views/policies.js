/**
 * Routing policies: draft, validate, simulate, publish.
 *
 * Specification 15.3 asks this screen for "priority matrix by user/group/model,
 * draft diff, validation, simulation, approval, rollback". Validation,
 * simulation and approval are backed by endpoints today — `GET/POST
 * /admin/v1/policies` and the `:validate`, `:simulate`, `:publish` actions of
 * specification 16. The priority matrix, the draft diff and rollback are not:
 * no endpoint returns the active bindings, and a draft's configuration text is
 * never read back. Those panels say so in the shared wording of
 * `notAvailable` rather than showing a plausible-looking approximation, because
 * the whole value of a management console is that an operator can read it as a
 * statement of what the router said.
 *
 * The screen is ordered as the work is done: what is active now, which drafts
 * exist, how to add one, then validate → simulate → publish for the draft the
 * operator selected.
 *
 * Four decisions here are worth the explanation:
 *
 * - **Nothing about a publication is optimistic** (specification 15.4). The
 *   publish button opens a confirmation that has to be completed by typing the
 *   draft identifier, the request carries the precondition the router demands,
 *   and the version and digest shown afterwards are the ones the *router*
 *   returned — never a value this screen predicted.
 * - **Simulation states what it did not do.** The router runs the production
 *   routing function over `IdealLiveState`: no provider is called, and every
 *   health, latency, queue and capacity term is zero. A candidate list read as
 *   "what would happen right now" would be wrong in exactly the situation —
 *   a degraded fleet — where someone is most likely to be looking at it.
 * - **The selection lives in the address bar**, so a link to a draft can be
 *   pasted into an incident channel. It is written with `history.replaceState`
 *   rather than by assigning to `location.hash`: assigning would fire
 *   `hashchange`, and the shell would remount the screen and throw away the
 *   simulation scenario the operator had just typed.
 * - **A result never outlives its draft.** Changing the selection clears the
 *   validation and simulation panels. A stale "valid" pill sitting above a
 *   different draft's identifier is the kind of misreading that gets a bad
 *   configuration published.
 */

import { ApiError } from '../api.js';
import { el, formatCount, formatTime, pill, text } from '../components/dom.js';
import {
  actionButton,
  confirmPrompt,
  definitionList,
  emptyState,
  notAvailable,
  panel,
} from '../components/layout.js';
import { banner, buttonRow, field, pageHeader, render, table } from '../components/table.js';

/** Screen metadata, read by the router to build navigation. */
export const meta = {
  path: '/policies',
  title: 'Routing policies',
  lede:
    'Draft a routing configuration, validate it, simulate how it would route, and publish it. A draft changes nothing until it is published.',
  // `GET /admin/v1/policies` accepts either `simulate_policy` or `edit_policy`,
  // and an approver reaches the screen through `publish_policy`. The screen
  // degrades per panel: each action is offered only to a session that holds the
  // permission the corresponding handler requires.
  permission: ['edit_policy', 'simulate_policy', 'publish_policy'],
};

/** The operations the canonical request model defines (`hypellm_core::canonical`). */
const OPERATIONS = ['chat', 'responses', 'embeddings', 'tokenize', 'rerank'];

/** The router's own default when a simulation omits `input_tokens`. */
const DEFAULT_INPUT_TOKENS = '1000';

/**
 * One line an operator can act on, for a failure this screen reports itself.
 *
 * The shell's banner is the normal destination for a thrown error; this exists
 * for the two places where the message belongs next to the control that caused
 * it — a draft list that would not load, and a refusal to publish, which is
 * usually a statement about the draft rather than a fault.
 *
 * @param {unknown} error
 * @returns {string}
 */
function problem(error) {
  if (error instanceof ApiError) {
    const parts = [error.message];
    if (Array.isArray(error.details) && error.details.length > 0) {
      parts.push(error.details.map((detail) => detail.message || String(detail)).join('; '));
    }
    if (error.requestId) {
      parts.push(`request ${error.requestId}`);
    }
    return parts.join(' — ');
  }
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return 'the router did not answer as expected';
}

/** @param {unknown} error @returns {boolean} */
function isAbort(error) {
  return Boolean(error) && error.name === 'AbortError';
}

/** A monospace identifier or digest. @param {unknown} value @returns {HTMLElement} */
function mono(value) {
  return el('span', { class: 'mono', text: value === null || value === undefined ? '—' : String(value) });
}

/**
 * Render the routing policy screen.
 *
 * @param {HTMLElement} container Empty element to render into.
 * @param {object} ctx
 * @param {import('../api.js').Api} ctx.api
 * @param {object} ctx.session
 * @param {(path: string) => void} ctx.navigate
 * @param {(tone: string, message: string) => void} ctx.notify
 * @param {URLSearchParams} ctx.query
 * @param {(permission: string) => boolean} ctx.can
 * @returns {Promise<void>}
 */
export async function mount(container, ctx) {
  const canEdit = ctx.can('edit_policy');
  const canSimulate = ctx.can('simulate_policy');
  const canPublish = ctx.can('publish_policy');
  // `:validate` accepts either of the two editing permissions.
  const canValidate = canEdit || canSimulate;

  const state = {
    /** @type {object[]} The `data` of the last `GET /policies`. */
    drafts: [],
    /** @type {string|null} A message when that list could not be read. */
    listError: null,
    /** @type {string|null} The draft every action below operates on. */
    selected: ctx.query.get('draft'),
    /** @type {object|null} The last `:validate` response for `selected`. */
    validation: null,
    /** @type {object|null} The last `:simulate` response for `selected`. */
    simulation: null,
    /** @type {string|null} A message when the last simulation was refused. */
    simulationError: null,
    /** @type {object|null} The last `:publish` response, as the router returned it. */
    published: null,
    /** @type {string|null} A message when the last publication was refused. */
    publishError: null,
    /** The active configuration, and where this screen learned of it. */
    active: { version: null, digest: null, source: '' },
    /** @type {string[]} Alias identifiers offered as suggestions, when readable. */
    aliases: [],
  };

  // ------------------------------------------------------------- loading --
  //
  // Every load is awaited in sequence rather than gathered with `Promise.all`.
  // The API client cancels the previous request when a new one starts, so two
  // concurrent reads would abort each other; sequencing is not a style choice
  // here, it is the difference between a screen that loads and one that does
  // not.

  /** Read the configuration that is live right now. */
  async function loadActive() {
    if (ctx.can('read_summary')) {
      try {
        const { data } = await ctx.api.get('/overview');
        state.active = {
          version: data.config_version,
          digest: data.config_digest,
          source: 'Read from the router when this screen loaded.',
        };
        return;
      } catch (error) {
        if (isAbort(error)) {
          throw error;
        }
        state.active = {
          version: ctx.session.config_version,
          digest: ctx.session.config_digest,
          source: `The summary could not be re-read (${problem(error)}); these values are the ones the session reported at sign-in.`,
        };
        return;
      }
    }
    state.active = {
      version: ctx.session.config_version,
      digest: ctx.session.config_digest,
      source:
        'Reported when this session began. This session cannot read the router summary, so the values are not re-read here.',
    };
  }

  /** Read the drafts the router is holding. */
  async function loadDrafts() {
    try {
      const { data } = await ctx.api.get('/policies');
      state.drafts = Array.isArray(data.data) ? data.data : [];
      state.listError = null;
    } catch (error) {
      if (isAbort(error)) {
        throw error;
      }
      state.drafts = [];
      state.listError =
        error instanceof ApiError && error.status === 403
          ? 'This session may publish but not draft or simulate, and the draft list requires one of those permissions. Ask for the policy_editor or policy_approver role to see drafts here.'
          : problem(error);
    }
  }

  /**
   * Read the alias identifiers, purely as suggestions for the model field.
   *
   * A failure is not worth interrupting the screen for: the field is a free
   * text input either way, and the router is the authority on whether an alias
   * exists. The hint says the list is unavailable rather than leaving an empty
   * suggestion list to imply there are no aliases.
   */
  async function loadAliases() {
    if (!canSimulate || !ctx.can('read_summary')) {
      return;
    }
    try {
      const { data } = await ctx.api.get('/aliases');
      const rows = Array.isArray(data.data) ? data.data : [];
      state.aliases = rows.map((alias) => String(alias.id)).filter((id) => id !== '');
    } catch (error) {
      if (isAbort(error)) {
        throw error;
      }
      state.aliases = [];
    }
  }

  await loadActive();
  await loadDrafts();
  await loadAliases();

  // -------------------------------------------------------------- panels --

  const activeBody = el('div');
  const draftsBody = el('div');
  const validationBody = el('div', { class: 'policy-stack' });
  const validationStatus = el('p', { class: 'policy-status', role: 'status', 'aria-live': 'polite' });
  const simulationResult = el('div', { class: 'policy-stack' });
  const simulationStatus = el('p', { class: 'policy-status', role: 'status', 'aria-live': 'polite' });
  const publishBody = el('div', { class: 'policy-stack' });
  // Focusable so that focus can be moved onto the outcome of a publication: the
  // confirmation the operator was standing on is removed when the panel
  // re-renders, and focus must land somewhere that says what happened rather
  // than on the danger button they just used.
  const publishStatus = el('p', {
    class: 'policy-status',
    role: 'status',
    'aria-live': 'polite',
    tabindex: '-1',
  });
  const newDraftStatus = el('p', { class: 'policy-status', role: 'status', 'aria-live': 'polite' });

  /** @param {string} id @returns {object|undefined} */
  function draftById(id) {
    return state.drafts.find((draft) => String(draft.id) === id);
  }

  /**
   * Point every action at a different draft.
   *
   * The previous draft's validation and simulation are dropped: they describe a
   * configuration that is no longer on screen, and a result that outlives its
   * subject is worse than no result.
   *
   * @param {string|null} id
   */
  function select(id) {
    if (state.selected === id) {
      return;
    }
    state.selected = id;
    state.validation = null;
    state.simulation = null;
    state.simulationError = null;
    state.published = null;
    state.publishError = null;
    validationStatus.textContent = '';
    simulationStatus.textContent = '';
    publishStatus.textContent = '';

    // A copyable link to the draft, without a `hashchange` and the remount that
    // would come with it.
    const suffix = id ? `?draft=${encodeURIComponent(id)}` : '';
    history.replaceState(null, '', `#${meta.path}${suffix}`);

    renderDrafts();
    renderValidation();
    renderSimulation();
    renderPublish();
  }

  // -------------------------------------------------- active configuration -

  function renderActive() {
    const version = state.active.version;
    render(
      activeBody,
      definitionList([
        ['Version', version === null || version === undefined ? '—' : `v${version}`],
        ['Digest', el('span', { class: 'digest', text: state.active.digest || '—' })],
        ['Source', state.active.source],
      ]),
    );
  }

  // ---------------------------------------------------------------- drafts -

  /** The router's own view of a draft's validation state. @param {object} draft */
  function draftStatePill(draft) {
    if (!draft.validated) {
      return pill('Not validated', 'neutral');
    }
    if (draft.valid) {
      return pill('Valid', 'ok');
    }
    const count = Number(draft.error_count) || 0;
    return pill(count === 1 ? '1 error' : `${count} errors`, 'danger');
  }

  function renderDrafts() {
    if (state.listError) {
      render(draftsBody, [
        banner('error', state.listError),
        buttonRow([
          actionButton(
            'Try again',
            async () => {
              await loadDrafts();
              renderDrafts();
              renderPublish();
            },
            { tone: 'quiet', busyLabel: 'Loading…' },
          ),
        ]),
      ]);
      return;
    }

    if (state.drafts.length === 0) {
      render(
        draftsBody,
        emptyState(
          'The router is holding no policy drafts',
          canEdit
            ? 'Nothing has been drafted since the router started. Submit a configuration below to create the first draft.'
            : 'Nothing has been drafted since the router started. Creating a draft needs the edit_policy permission.',
        ),
      );
      return;
    }

    render(
      draftsBody,
      table({
        caption: 'Policy drafts the router is holding',
        columns: [
          { label: 'Draft', cell: (row) => mono(row.id) },
          { label: 'Author', cell: (row) => String(row.author || '—') },
          { label: 'Created', cell: (row) => formatTime(row.created_at) },
          { label: 'Validation', cell: (row) => draftStatePill(row) },
          { label: 'Digest', cell: (row) => (row.digest ? mono(row.digest) : text('—')) },
          {
            label: 'Selection',
            cell: (row) => {
              const id = String(row.id);
              const isSelected = state.selected === id;
              const button = el('button', {
                type: 'button',
                class: 'button button--quiet',
                'aria-pressed': isSelected ? 'true' : 'false',
                text: isSelected ? 'Selected' : 'Select',
              });
              button.addEventListener('click', () => {
                select(id);
              });
              return button;
            },
          },
        ],
        rows: state.drafts,
      }),
    );
  }

  // ------------------------------------------------------------- new draft -

  const draftText = el('textarea', {
    spellcheck: 'false',
    autocomplete: 'off',
    wrap: 'off',
    rows: '18',
  });

  const newDraftPanel = canEdit
    ? panel({
        title: 'New draft',
        note: 'A draft is inert. It is parsed only when you validate it, and it routes nothing until it is published.',
        content: el('div', { class: 'policy-stack' }, [
          field({
            id: 'policy-draft-text',
            label: 'Configuration',
            hint:
              'The router\'s line-oriented configuration grammar (specification 11.1): one "type key=value" record per line, # for comments. It is sent verbatim and is not interpreted by this page.',
            control: draftText,
          }),
          el('p', {
            class: 'field__hint',
            text:
              'Drafts are immutable and are held in the router\'s memory, not in the durable log: a restart discards them, and the management API never reads the text back. Keep your own copy — the text stays in this box after submission so a follow-up draft can be amended from it.',
          }),
          buttonRow([
            actionButton(
              'Create draft',
              async () => {
                const configuration = draftText.value;
                if (configuration.trim() === '') {
                  newDraftStatus.textContent = 'A draft needs a configuration; the box is empty.';
                  draftText.focus();
                  return;
                }
                const { data } = await ctx.api.post('/policies', { configuration });
                const id = data && data.id ? String(data.id) : null;
                newDraftStatus.textContent = id
                  ? `Created draft ${id}. It is not validated and nothing has changed for traffic.`
                  : 'The router created a draft but did not return its identifier.';
                await loadDrafts();
                renderDrafts();
                if (id) {
                  select(id);
                } else {
                  renderPublish();
                }
                ctx.notify('ok', id ? `Draft ${id} created.` : 'Draft created.');
              },
              { busyLabel: 'Creating…' },
            ),
          ]),
          newDraftStatus,
        ]),
      })
    : null;

  // ------------------------------------------------------------ validation -

  function renderValidation() {
    if (!state.selected) {
      render(validationBody, emptyState('No draft selected', 'Select a draft above to validate it.'));
      return;
    }
    if (!state.validation) {
      render(
        validationBody,
        emptyState(
          `Draft ${state.selected} has not been validated in this session`,
          'Validation parses the configuration and reports every structural and semantic error the router found. It changes nothing.',
        ),
      );
      return;
    }

    const result = state.validation;
    const errors = Array.isArray(result.errors) ? result.errors : [];
    render(validationBody, [
      definitionList([
        ['Draft', mono(result.id)],
        ['Result', result.valid ? pill('Valid', 'ok') : pill('Rejected', 'danger')],
        [
          'Digest',
          result.digest
            ? el('span', { class: 'digest', text: String(result.digest) })
            : text('— the router computes a digest only for a configuration that parsed'),
        ],
      ]),
      errors.length === 0
        ? emptyState(
            'The parser reported no errors',
            'Every record was understood and no semantic check failed.',
          )
        : table({
            caption: 'Errors reported by the configuration parser, in file order',
            columns: [
              { label: 'Line', numeric: true, cell: (row) => String(row.line) },
              { label: 'Column', numeric: true, cell: (row) => String(row.column) },
              { label: 'Code', cell: (row) => mono(row.code) },
              { label: 'Message', cell: (row) => String(row.message || '') },
            ],
            rows: errors,
          }),
    ]);
  }

  const validateButton = actionButton(
    'Validate',
    async () => {
      if (!state.selected) {
        return;
      }
      const id = state.selected;
      const { data } = await ctx.api.post(`/policies/${encodeURIComponent(id)}:validate`, {});
      state.validation = data;
      const errors = Array.isArray(data.errors) ? data.errors.length : 0;
      validationStatus.textContent = data.valid
        ? `Draft ${id} is valid.`
        : `Draft ${id} was rejected with ${errors === 1 ? '1 error' : `${errors} errors`}.`;
      renderValidation();
      // The list carries `validated`, `valid` and `digest`; re-reading it keeps
      // the table and the publish panel consistent with what just happened.
      await loadDrafts();
      renderDrafts();
      renderPublish();
    },
    { busyLabel: 'Validating…' },
  );

  const validationPanel = canValidate
    ? panel({
        title: 'Validation',
        note: 'Structural and semantic validation of the selected draft. A draft must be validated before it can be published.',
        actions: [validateButton],
        content: el('div', { class: 'policy-stack' }, [validationStatus, validationBody]),
      })
    : null;

  // ------------------------------------------------------------ simulation -

  const scenarioPrincipal = el('input', {
    type: 'text',
    autocomplete: 'off',
    spellcheck: 'false',
    value: String(ctx.session.principal || ''),
  });
  const scenarioGroups = el('input', { type: 'text', autocomplete: 'off', spellcheck: 'false' });
  const scenarioModel = el('input', {
    type: 'text',
    autocomplete: 'off',
    spellcheck: 'false',
    required: true,
    list: state.aliases.length > 0 ? 'policy-alias-options' : null,
  });
  const scenarioOperation = el(
    'select',
    {},
    OPERATIONS.map((name) => el('option', { value: name }, name)),
  );
  const scenarioTokens = el('input', {
    type: 'number',
    min: '0',
    step: '1',
    inputmode: 'numeric',
    value: DEFAULT_INPUT_TOKENS,
  });

  const aliasOptions =
    state.aliases.length > 0
      ? el(
          'datalist',
          { id: 'policy-alias-options' },
          state.aliases.map((id) => el('option', { value: id })),
        )
      : null;

  function renderSimulation() {
    if (!state.selected) {
      render(
        simulationResult,
        emptyState('No draft selected', 'Select a draft above to simulate a request against it.'),
      );
      return;
    }
    if (state.simulationError) {
      render(simulationResult, banner('error', state.simulationError));
      return;
    }
    if (!state.simulation) {
      render(
        simulationResult,
        emptyState(
          `Draft ${state.selected} has not been simulated in this session`,
          'Describe a request above and run it. No provider is contacted and no prompt text leaves this page.',
        ),
      );
      return;
    }

    const result = state.simulation;
    const candidates = Array.isArray(result.candidates) ? result.candidates : [];
    const exclusions = Array.isArray(result.exclusions) ? result.exclusions : [];

    render(simulationResult, [
      definitionList([
        ['Draft', mono(result.draft)],
        ['Policy digest', el('span', { class: 'digest', text: String(result.policy_digest || '') })],
        ['Pinned', result.pinned ? pill('Hard pin', 'warn') : text('no')],
        [
          'Would choose',
          result.chosen ? mono(result.chosen) : text('nothing — no target survived the eligibility filters'),
        ],
      ]),
      candidates.length === 0
        ? emptyState(
            'No candidate was eligible',
            'Every target the alias permits was excluded. The exclusion table says which filter removed each one.',
          )
        : table({
            caption: 'Ranked candidates, in the order the router would attempt them',
            columns: [
              { label: 'Rank', numeric: true, cell: (row) => String(row.rank) },
              { label: 'Target', cell: (row) => mono(row.target) },
              { label: 'Score', numeric: true, cell: (row) => formatCount(row.score) },
            ],
            rows: candidates,
          }),
      exclusions.length === 0
        ? emptyState(
            'No target was excluded',
            'Every target the alias permits was eligible for this scenario.',
          )
        : table({
            caption: 'Targets excluded from this scenario, with the reason the router recorded',
            columns: [
              { label: 'Target', cell: (row) => mono(row.target) },
              { label: 'Reason', cell: (row) => mono(row.reason) },
            ],
            rows: exclusions,
          }),
      el('p', {
        class: 'field__hint',
        text:
          'Reason codes are the same strings the decision trace and the structured logs use, so a simulation and an incident can be compared directly. Security, residency and capability constraints appear here as exclusions rather than as low scores: specification 6.3 makes them eligibility filters, never penalties.',
      }),
    ]);
  }

  /** Run the simulation the form describes. @returns {Promise<void>} */
  async function runSimulation() {
    if (!state.selected) {
      simulationStatus.textContent = 'Select a draft first.';
      return;
    }

    const model = scenarioModel.value.trim();
    if (model === '') {
      simulationStatus.textContent = 'A model alias is required; the router has nothing to resolve without one.';
      scenarioModel.focus();
      return;
    }

    const rawTokens = scenarioTokens.value.trim();
    let inputTokens = null;
    if (rawTokens !== '') {
      const parsed = Number(rawTokens);
      if (!Number.isSafeInteger(parsed) || parsed < 0) {
        simulationStatus.textContent = 'Input tokens must be a whole number of zero or more.';
        scenarioTokens.focus();
        return;
      }
      inputTokens = parsed;
    }

    const groups = scenarioGroups.value
      .split(',')
      .map((group) => group.trim())
      .filter((group) => group !== '');

    const body = { model, operation: scenarioOperation.value, groups };
    const principal = scenarioPrincipal.value.trim();
    if (principal !== '') {
      body.principal = principal;
    }
    if (inputTokens !== null) {
      body.input_tokens = inputTokens;
    }

    const id = state.selected;
    simulationStatus.textContent = '';
    try {
      const { data } = await ctx.api.post(`/policies/${encodeURIComponent(id)}:simulate`, body);
      state.simulation = data;
      state.simulationError = null;
      const candidates = Array.isArray(data.candidates) ? data.candidates.length : 0;
      const exclusions = Array.isArray(data.exclusions) ? data.exclusions.length : 0;
      simulationStatus.textContent = `Draft ${id}: ${candidates} eligible ${
        candidates === 1 ? 'candidate' : 'candidates'
      }, ${exclusions} excluded, ${data.chosen ? `first choice ${data.chosen}` : 'no target chosen'}.`;
    } catch (error) {
      if (isAbort(error)) {
        return;
      }
      // Reported here rather than through the shell banner: a refusal is nearly
      // always a statement about the draft or the scenario, and it belongs next
      // to the form that produced it.
      state.simulation = null;
      state.simulationError = problem(error);
      simulationStatus.textContent = 'The simulation was refused.';
    }
    renderSimulation();
  }

  const runButton = actionButton('Run simulation', runSimulation, { busyLabel: 'Simulating…' });

  const scenarioForm = el('form', { novalidate: true }, [
    field({
      id: 'policy-sim-principal',
      label: 'Principal',
      hint: 'Whose request to simulate. Defaults to you. The tenant is always your own — the router refuses to simulate another tenant\'s policy.',
      control: scenarioPrincipal,
    }),
    field({
      id: 'policy-sim-groups',
      label: 'Groups',
      hint: 'Group identifiers, separated by commas. An identifier the router cannot parse is ignored rather than rejected, so check the spelling if a binding does not appear to apply.',
      control: scenarioGroups,
    }),
    field({
      id: 'policy-sim-model',
      label: 'Model alias',
      hint:
        state.aliases.length > 0
          ? 'The alias the client would ask for. The suggestions are the aliases of the configuration that is active now, not of this draft.'
          : 'The alias the client would ask for, exactly as a client would send it.',
      control: scenarioModel,
    }),
    field({
      id: 'policy-sim-operation',
      label: 'Operation',
      hint: 'The canonical operation. A target that does not serve it is excluded rather than scored down.',
      control: scenarioOperation,
    }),
    field({
      id: 'policy-sim-tokens',
      label: 'Input tokens',
      hint:
        'A size, not a prompt. Specification 15.4 keeps the descriptor sanitized: this screen sends a token count so context-window filters can be evaluated, and never prompt text. Leave it empty to accept the router\'s default of 1000.',
      control: scenarioTokens,
    }),
    aliasOptions,
    buttonRow([runButton]),
  ]);

  // A real form, so Enter submits from any field; the handler stops the browser
  // navigating and re-uses the button, whose own guard makes a second run while
  // one is in flight impossible.
  scenarioForm.addEventListener('submit', (event) => {
    event.preventDefault();
    runButton.click();
  });

  const simulationPanel = canSimulate
    ? panel({
        title: 'Simulation',
        note: 'Explains what the draft would decide for one request. The router evaluates the production routing function and calls no provider.',
        content: el('div', { class: 'policy-stack' }, [
          el('p', {
            class: 'field__hint',
            text:
              'Live state is idealized: health, latency, queue depth and capacity all count as perfect, and no breaker is open. The result is what the policy permits and prefers, not what a degraded fleet would do at this moment.',
          }),
          scenarioForm,
          simulationStatus,
          simulationResult,
        ]),
      })
    : null;

  // --------------------------------------------------------------- publish -

  /** Ask the router to activate the selected draft. @returns {Promise<void>} */
  async function publishSelected() {
    const id = state.selected;
    if (!id) {
      return;
    }
    try {
      // Specification 15.4 requires `If-Match` on mutation, and the router
      // enforces it against a tag derived from the active configuration's
      // version and digest. No read endpoint returns that tag today, so the
      // only precondition this screen can honestly present is RFC 9110's `*`.
      // It asserts that a configuration exists; it cannot detect a concurrent
      // publication. The panel says so rather than implying a guard that is not
      // there, and this becomes the tag that was read the moment the management
      // API exposes one.
      const { data } = await ctx.api.request('POST', `/policies/${encodeURIComponent(id)}:publish`, {
        body: {},
        ifMatch: '*',
      });
      state.published = data;
      state.publishError = null;
      // The version and digest displayed are the router's answer, never a value
      // predicted here: specification 15.4 requires activation to return the
      // active digest, and that returned digest is the only one worth showing.
      state.active = {
        version: data.version,
        digest: String(data.digest || ''),
        source:
          'Returned by the publication, and therefore the configuration now serving traffic. The publication answers with the full digest; a summary read reports the short form of the same value.',
      };
      publishStatus.textContent = `Draft ${id} is active as v${data.version}.`;
      ctx.notify('ok', `Draft ${id} published as v${data.version}.`);
      renderActive();
      await loadDrafts();
      renderDrafts();
    } catch (error) {
      if (isAbort(error)) {
        return;
      }
      state.publishError = problem(error);
      publishStatus.textContent = 'The publication was refused. Nothing changed.';
    }
    renderPublish();
    publishStatus.focus();
  }

  function renderPublish() {
    if (!canPublish) {
      render(
        publishBody,
        emptyState(
          'This session cannot publish',
          'Publishing needs the publish_policy permission, which this session does not hold. Drafting and simulating are separated from activation on purpose (specification 9.3): ask an approver to review the draft.',
        ),
      );
      return;
    }
    if (!state.selected) {
      render(publishBody, emptyState('No draft selected', 'Select a draft above to publish it.'));
      return;
    }

    const id = state.selected;
    const draft = draftById(id);
    const notes = [];
    let blocked = null;

    if (!draft) {
      notes.push(
        'This draft is not in the list this screen read, so its validation state is unknown here. The router will refuse the publication if it is not a validated, error-free draft.',
      );
    } else {
      if (!draft.validated) {
        blocked = 'The draft has not been validated. The router refuses to publish a draft it has not parsed.';
      } else if (!draft.valid) {
        blocked = 'The draft failed validation. Fix the configuration and submit it as a new draft.';
      }
      if (String(draft.author) === String(ctx.session.principal)) {
        notes.push(
          'You authored this draft. Unless this deployment deliberately permits self-approval, the router will refuse it and answer self_approval_not_permitted: a draft is meant to be published by a second person.',
        );
      }
    }

    const confirmSlot = el('div');
    const publishButton = actionButton(
      `Publish ${id}`,
      () => {
        render(
          confirmSlot,
          confirmPrompt({
            message: `Publish draft ${id} and make it the active routing configuration.`,
            detail:
              'Activation is atomic and takes effect for every request that starts after it; requests already in flight keep the configuration they began with. There is no rollback endpoint — returning to the previous configuration means submitting it again as a new draft and publishing that.',
            confirmLabel: 'Publish now',
            phrase: id,
            onConfirm: async () => {
              await publishSelected();
            },
            onCancel: () => {
              render(confirmSlot, []);
              publishButton.focus();
            },
          }),
        );
      },
      {
        tone: 'danger',
        disabled: Boolean(blocked),
        title: blocked || undefined,
      },
    );

    render(publishBody, [
      state.publishError ? banner('error', state.publishError) : null,
      definitionList([
        ['Draft', mono(id)],
        ['Author', draft ? String(draft.author || '—') : '—'],
        ['Validation', draft ? draftStatePill(draft) : text('unknown to this screen')],
        ['Draft digest', draft && draft.digest ? mono(draft.digest) : text('—')],
      ]),
      blocked ? banner('warn', blocked) : null,
      ...notes.map((note) => el('p', { class: 'field__hint', text: note })),
      el('p', {
        class: 'field__hint',
        text:
          'Publication is sent with the precondition If-Match: *. The management API does not yet return an entity tag for the active configuration, so this screen cannot detect a publication made by someone else in the meantime. Confirm the active version above before you continue.',
      }),
      state.published
        ? definitionList(
            [
              ['Published draft', mono(state.published.draft)],
              ['Active version', `v${state.published.version}`],
              ['Active digest', el('span', { class: 'digest', text: String(state.published.digest || '') })],
            ],
            { wide: true },
          )
        : null,
      buttonRow([publishButton]),
      confirmSlot,
    ]);
  }

  // ----------------------------------------------------------------- paint -

  render(container, [
    pageHeader(meta.title, meta.lede),

    panel({
      title: 'Active configuration',
      note: 'What every request is being routed by right now.',
      content: activeBody,
    }),

    panel({
      title: 'Drafts',
      note: 'Immutable, in the order the router lists them. Select one to validate, simulate or publish it.',
      actions: [
        actionButton(
          'Refresh',
          async () => {
            await loadDrafts();
            renderDrafts();
            renderPublish();
          },
          { tone: 'quiet', busyLabel: 'Loading…' },
        ),
      ],
      content: draftsBody,
    }),

    newDraftPanel,
    validationPanel,
    simulationPanel,

    panel({
      title: 'Publish',
      note: 'Approval and atomic activation. Nothing here is applied before the router has confirmed it.',
      content: el('div', { class: 'policy-stack' }, [publishStatus, publishBody]),
    }),

    panel({
      title: 'Priority matrix',
      content: notAvailable(
        'The priority matrix by user, group and model',
        'No endpoint returns the bindings of the active configuration, so this screen cannot show which principal, group or alias prefers which target. Until one exists, a draft simulation above is the way to find out what a binding does, and the decision explorer shows what it did for a real request.',
      ),
    }),

    panel({
      title: 'Draft comparison and rollback',
      content: notAvailable(
        'Draft diff and rollback',
        'A draft\'s configuration text is never returned by the management API, and the active configuration is not readable as text, so there is nothing this screen could honestly diff. There is likewise no rollback endpoint: an earlier configuration is restored by submitting it as a new draft and publishing that, which keeps every activation in the audit log.',
      ),
    }),
  ]);

  renderActive();
  renderDrafts();
  renderValidation();
  renderSimulation();
  renderPublish();

  // A draft named in the address bar may not exist — a stale link, or a draft
  // lost to a restart. Saying so beats leaving the panels apparently waiting.
  if (state.selected && !state.listError && state.drafts.length > 0 && !draftById(state.selected)) {
    ctx.notify('warn', `Draft ${state.selected} is not among the drafts the router is holding.`);
  }
}
