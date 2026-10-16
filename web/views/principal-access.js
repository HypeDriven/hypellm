/**
 * Principal access: one principal's ceiling.
 *
 * A principal is who a key or a person authenticates as (`svc:dsh`,
 * `user:admin`). This screen drafts the three things that bound everything
 * that principal — and every key it holds — may do:
 *
 * - **Models**, as `grant` records scoped to the principal. Grants are default
 *   deny and the most specific matching grant wins, so a principal grant for
 *   one alias outranks a tenant-wide `model=*` grant, and a principal-wide
 *   `model=*` grant outranks the tenant's for every alias the principal has no
 *   exact grant for.
 * - **Slaves**, as one `binding` scoped to the principal that denies the
 *   targets left unticked. A deny is an eligibility filter and is sticky
 *   downward, so nothing narrower can re-enable it. The screen never writes an
 *   `allow`: a principal-level allow overturns a tenant-level deny, and a
 *   ceiling must not be able to widen anything.
 * - **Priority and limits**, as one `quota` scoped to the principal: its queue
 *   class, and its concurrency, queue depth, request and token rates and spend
 *   budget. A published change is enforced at once, without a restart; what
 *   the principal has in flight, has queued and has spent carries over.
 *   Tenant-level limits bind as well — both layers are checked — so they are
 *   shown beside these, read-only, because they throttle everyone in the
 *   tenant and stay policy text.
 *
 * Every change is a draft through `POST /admin/v1/policies:edit`. Nothing
 * applies until a *different* person publishes it.
 *
 * Two honesty rules, as on the Slave access panel:
 *
 * - **What is written is shown as written.** "Inherit" means this principal
 *   has no record here, not a prediction. The *outcome* column is the router's
 *   own answer from `POST /admin/v1/policies/active:simulate` (and, for a new
 *   draft, the draft's simulation), not a computation in this file.
 * - **A record this screen did not write and cannot address is shown, not
 *   edited.** Grants and quotas written without an `id` are editable only as
 *   policy text; the screen says so beside them rather than offering a control
 *   the router would refuse.
 *
 * Per-key narrowing — a key restricted to a subset of its principal's ceiling
 * — is on the Keys screen.
 */

import { ApiError } from '../api.js';
import { el, pill } from '../components/dom.js';
import { actionButton, emptyState, notAvailable, panel } from '../components/layout.js';
import {
  listOf,
  loadActiveRecords,
  proposeEdits,
  recordsOf,
  recordsUnavailable,
  requiresEditPolicy,
  textField,
} from '../components/records.js';
import { banner, buttonRow, pageHeader, render, table } from '../components/table.js';

/** Screen metadata, read by the router to build navigation. */
export const meta = {
  path: '/principal-access',
  title: 'Principal access',
  lede:
    'Which models a principal may see and use, which slaves may serve it, and how its requests queue. Every change is a draft that someone else publishes.',
  permission: ['edit_policy', 'simulate_policy'],
};

const GRANT_CHOICES = ['inherit', 'allow', 'deny'];
const CLASSES = ['batch', 'standard', 'interactive'];
const PERIODS = ['daily', 'monthly'];

/**
 * The limits a principal's quota may carry, in the grammar's field names.
 * `max` is the largest value the router stores for that field.
 */
const LIMITS = [
  { name: 'concurrency', label: 'Concurrent requests', unit: 'requests at once', max: 4294967295 },
  { name: 'queued', label: 'Queue depth', unit: 'requests waiting when the concurrency limit is reached', max: 4294967295 },
  { name: 'rps', label: 'Request rate', unit: 'requests per second', max: 4294967295 },
  { name: 'burst', label: 'Request burst', unit: 'requests above the rate, briefly', max: 4294967295 },
  { name: 'tpm', label: 'Token rate', unit: 'tokens per minute (input estimate, reconciled to usage)', max: Number.MAX_SAFE_INTEGER },
  { name: 'token_burst', label: 'Token burst', unit: 'tokens above the rate, briefly', max: Number.MAX_SAFE_INTEGER },
  { name: 'budget', label: 'Spend budget', unit: 'minor currency units (cents) per period, at the configured prices', max: Number.MAX_SAFE_INTEGER },
];
const LIMIT_NAMES = new Set([...LIMITS.map((l) => l.name), 'budget_period']);

/** The identifier alphabet `is_token` in `hypellm-config::edit` accepts. */
const IDENTIFIER = /^[A-Za-z0-9._:/-]{1,128}$/;

/**
 * A stable record identifier: FNV-1a over the parts, so drafting the same
 * choice twice edits one record rather than adding a second.
 *
 * @param {string} prefix @param {...string} parts
 * @returns {string}
 */
function recordId(prefix, ...parts) {
  let hash = 0x811c9dc5;
  for (const ch of parts.join('|')) {
    hash ^= ch.codePointAt(0);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${prefix}-${hash.toString(16).padStart(8, '0')}`;
}

/** The operation a simulation of this alias should ask about. @param {object} alias */
function operationFor(alias) {
  if (alias.capability === 'rerank') return 'rerank';
  if (alias.capability === 'embeddings') return 'embeddings';
  return 'chat';
}

/**
 * Render the screen.
 *
 * @param {HTMLElement} container
 * @param {object} ctx
 * @returns {Promise<void>}
 */
export async function mount(container, ctx) {
  const body = el('div', { class: 'policy-stack' });
  const outcome = el('div', { class: 'policy-stack', role: 'status', 'aria-live': 'polite' });
  render(container, [pageHeader(meta.title, meta.lede), outcome, body]);

  /** @type {{records: object[]|null, etag: string|null}} */
  let active = { records: null, etag: null };
  /** @type {string[]} */
  let known = [];
  let subject = ctx.query && ctx.query.get('principal') ? String(ctx.query.get('principal')) : '';

  await reload();

  async function reload() {
    try {
      active = await loadActiveRecords(ctx.api);
    } catch (error) {
      if (error && error.name === 'AbortError') return;
      body.replaceChildren(emptyState('The active configuration could not be read.', String(error.message || error)));
      return;
    }
    known = await principals();
    paint();
  }

  /**
   * Every principal the configuration or the access view names. `/access`
   * needs manage_principals; without it the list is the configuration's alone.
   */
  async function principals() {
    const found = new Set();
    const add = (scope) => {
      if (typeof scope === 'string' && scope.startsWith('principal:')) found.add(scope.slice('principal:'.length));
    };
    for (const record of active.records || []) {
      const fields = record.fields || {};
      add(fields.scope);
      add(fields.subject);
      if (record.kind === 'identity' && fields.principal) found.add(fields.principal);
    }
    try {
      const { data } = await ctx.api.get('/access', { shared: true });
      for (const row of [...(data.identities || []), ...(data.service_principals || [])]) {
        if (row.principal) found.add(String(row.principal));
      }
    } catch (error) {
      if (error && error.name === 'AbortError') throw error;
      if (!(error instanceof ApiError)) throw error;
    }
    return [...found].sort();
  }

  /** Groups whose `members` list names the principal, for simulation. */
  function groupsOf(principal) {
    return recordsOf(active.records, 'group')
      .filter((group) => listOf(group.members).includes(principal))
      .map((group) => group.id);
  }

  function paint() {
    if (!active.records) {
      body.replaceChildren(recordsUnavailable('Principal access'));
      return;
    }
    const canEdit = ctx.can('edit_policy');
    const pickerInput = el('input', {
      type: 'text',
      id: 'principal-access-subject',
      list: 'principal-access-known',
      value: subject,
      autocomplete: 'off',
      spellcheck: 'false',
      placeholder: 'svc:dsh',
    });
    const datalist = el('datalist', { id: 'principal-access-known' }, known.map((p) => el('option', { value: p })));
    const pickerStatus = el('p', { class: 'field__hint', role: 'status' });
    const show = actionButton('Show', () => {
      const value = String(pickerInput.value).trim();
      if (!IDENTIFIER.test(value)) {
        pickerStatus.textContent = 'A principal is an identifier such as svc:dsh or user:admin.';
        return;
      }
      subject = value;
      outcome.replaceChildren();
      paint();
    });
    const picker = el('div', { class: 'policy-stack' }, [
      el('label', { for: 'principal-access-subject', text: 'Principal' }),
      pickerInput,
      datalist,
      buttonRow([show]),
      pickerStatus,
      subject
        ? el('p', {}, [el('a', { href: `#/usage?principal=${encodeURIComponent(subject)}` }, `What ${subject} used recently`)])
        : null,
    ]);

    if (!subject) {
      body.replaceChildren(
        picker,
        el('p', {
          text: 'Pick a principal. Principals named in the configuration, by an identity, or by a key are suggested; any identifier may be typed.',
        }),
      );
      return;
    }
    if (!canEdit) {
      body.replaceChildren(picker, requiresEditPolicy());
      return;
    }

    const scope = `principal:${subject}`;
    const models = modelsSection(scope);
    const slaves = slavesSection(scope);
    const priority = quotaSection(scope);
    const draft = actionButton(
      'Save as draft',
      async () => {
        const limits = priority.edits();
        if (limits === null) return;
        const edits = [...models.edits(), ...slaves.edits(), ...limits];
        if (edits.length === 0) {
          outcome.replaceChildren(el('p', { text: 'Nothing changed, so no draft was created.' }));
          return;
        }
        const data = await proposeEdits(ctx, edits, outcome, { etag: () => active.etag, onPublished: reload });
        if (data && data.valid && data.draft_id) await models.preview(String(data.draft_id));
      },
      { busyLabel: 'Drafting…' },
    );
    body.replaceChildren(picker, models.element, slaves.element, priority.element, buttonRow([draft]));
  }

  // -- Models -----------------------------------------------------------------

  function modelsSection(scope) {
    const principal = scope.slice('principal:'.length);
    const aliases = recordsOf(active.records, 'alias');
    const grants = recordsOf(active.records, 'grant');
    const mine = (model) => grants.filter((g) => g.scope === scope && (g.model || '*') === model);
    /** @type {Map<string, HTMLSelectElement>} */
    const cells = new Map();
    /** @type {Map<string, HTMLElement>} */
    const outcomes = new Map();

    const rows = [{ model: '*', label: 'All other models', detail: 'Every alias this principal has no row of its own for' }].concat(
      aliases.map((alias) => ({ model: alias.id, label: alias.id, detail: alias.description || '', alias })),
    );

    function control(row) {
      const written = mine(row.model);
      if (written.length > 1 || (written.length === 1 && !written[0].id)) {
        return el('span', {
          class: 'panel__note',
          text:
            written.length > 1
              ? 'Several grants are written here; edit the policy text.'
              : `Written as policy text without an id (${written[0].allow === 'false' ? 'deny' : 'allow'}); edit it there.`,
        });
      }
      const current = written[0];
      const value = current ? (current.allow === 'false' ? 'deny' : 'allow') : 'inherit';
      const field = textField({
        id: `principal-access-model-${row.model}`,
        label: `Grant for ${row.label}`,
        value,
        choices: GRANT_CHOICES,
      });
      cells.set(row.model, /** @type {HTMLSelectElement} */ (field.input));
      return field.input;
    }

    const element = panel({
      title: 'Models',
      note:
        'Grants written for this principal. Inherit means none is written here and the tenant or a group decides. ' +
        'The outcome column is the router’s simulation of the active configuration for this principal.',
      content: [
        table({
          caption: `Model grants for ${principal}`,
          columns: [
            { label: 'Model', cell: (row) => el('code', { text: row.label }) },
            { label: 'Description', cell: (row) => row.detail },
            { label: 'Written', cell: (row) => control(row) },
            {
              label: 'Outcome now',
              cell: (row) => {
                if (!row.alias) return '—';
                const slot = el('span', { text: '…' });
                outcomes.set(row.model, slot);
                return slot;
              },
            },
          ],
          rows,
          empty: 'The configuration declares no aliases.',
        }),
      ],
    });
    void simulateAll('/policies/active:simulate', 'now');

    /** Ask the router, alias by alias, what it would decide for this principal. */
    async function simulateAll(path, when) {
      if (!ctx.can('simulate_policy')) {
        for (const slot of outcomes.values()) slot.replaceChildren(el('span', { class: 'panel__note', text: 'needs simulate_policy' }));
        return;
      }
      const groups = groupsOf(principal);
      for (const row of rows) {
        if (!row.alias) continue;
        const slot = outcomes.get(row.model);
        if (!slot) continue;
        try {
          const { data } = await ctx.api.request('POST', path, {
            body: { model: row.alias.id, principal, groups, operation: operationFor(row.alias) },
            shared: true,
          });
          slot.replaceChildren(verdict(data, when));
        } catch (error) {
          if (error && error.name === 'AbortError') return;
          slot.replaceChildren(el('span', { class: 'panel__note', text: error instanceof ApiError ? error.message : 'no answer' }));
        }
      }
    }

    function edits() {
      const out = [];
      for (const [model, select] of cells) {
        const wanted = String(select.value);
        const current = mine(model)[0];
        if (wanted === 'inherit') {
          if (current) out.push({ op: 'remove', kind: 'grant', id: current.id });
          continue;
        }
        const allow = wanted === 'allow' ? 'true' : 'false';
        if (current && (current.allow === 'false' ? 'false' : 'true') === allow) continue;
        out.push(
          current
            ? { op: 'set', kind: 'grant', id: current.id, fields: { allow } }
            : { op: 'set', kind: 'grant', id: recordId('pg', scope, model), fields: { scope, model, allow } },
        );
      }
      return out;
    }

    /** After a draft exists: what it would decide, beside what is in force. */
    async function preview(draftId) {
      outcome.append(
        el('p', { class: 'panel__note', text: `The outcome column now shows draft ${draftId}, which is not in force until it is published.` }),
      );
      await simulateAll(`/policies/${encodeURIComponent(draftId)}:simulate`, 'draft');
    }

    return { element, edits, preview };
  }

  /**
   * One simulation, as a pill: may the principal use the alias, and if so
   * which target it would be served by.
   */
  function verdict(data, when) {
    const exclusions = Array.isArray(data.exclusions) ? data.exclusions : [];
    if (exclusions.some((e) => e.reason === 'not_authorized_for_alias')) {
      return pill(when === 'draft' ? 'draft: not permitted' : 'not permitted', 'warn');
    }
    if (data.chosen) {
      return el('span', {}, [pill(when === 'draft' ? 'draft: permitted' : 'permitted', 'ok'), ' via ', el('code', { text: String(data.chosen) })]);
    }
    return el('span', {}, [
      pill(when === 'draft' ? 'draft: permitted, no target' : 'permitted, no target', 'danger'),
      ' ',
      el('span', { class: 'panel__note', text: [...new Set(exclusions.map((e) => e.reason))].join(', ') }),
    ]);
  }

  // -- Slaves -----------------------------------------------------------------

  function slavesSection(scope) {
    const providers = new Map(recordsOf(active.records, 'provider').map((p) => [p.id, p]));
    const targets = recordsOf(active.records, 'target');
    const bindings = recordsOf(active.records, 'binding');
    const ownId = recordId('pa', scope);
    const own = bindings.find((b) => b.id === ownId);
    const denied = new Set(listOf(own && own.deny));
    const others = bindings.filter((b) => b.scope === scope && b.id !== ownId && listOf(b.deny).length > 0);
    /** @type {Map<string, HTMLInputElement>} */
    const boxes = new Map();

    const byProvider = new Map();
    for (const target of targets) {
      const list = byProvider.get(target.provider) || [];
      list.push(target);
      byProvider.set(target.provider, list);
    }

    const groups = [...byProvider.entries()].map(([providerId, list]) => {
      const provider = providers.get(providerId) || {};
      const where = provider.host ? `${provider.host}${provider.port ? `:${provider.port}` : ''}` : 'no host';
      return el('fieldset', { class: 'checkset' }, [
        el('legend', { class: 'checkset__legend', text: `${providerId} — ${where}` }),
        ...list.map((target) => {
          const id = `principal-access-target-${target.id}`;
          const box = el('input', {
            type: 'checkbox',
            id,
            checked: !denied.has(target.id),
          });
          boxes.set(target.id, /** @type {HTMLInputElement} */ (box));
          return el('div', { class: 'checkset__item' }, [
            box,
            el('label', { for: id, text: target.id }),
            el('span', { class: 'checkset__hint', text: target.model ? `model ${target.model}` : '' }),
          ]);
        }),
      ]);
    });

    const content = [
      ...groups,
      el('p', {
        class: 'panel__note',
        text:
          'Unticked targets are denied to this principal. Targets added to the configuration later are allowed until denied here.',
      }),
    ];
    if (others.length > 0) {
      content.push(
        banner('warn', [
          'Other bindings for this principal also deny targets, and they still apply: ',
          ...others.flatMap((b, i) => [i ? ', ' : '', el('code', { text: `${b.id} (${b.deny})` })]),
          '. Edit them on the Routing policies screen.',
        ]),
      );
    }
    content.push(
      el('p', { class: 'panel__note' }, [
        'Managed fleet machines have their own per-user grants on the ',
        el('a', { href: '#/fleet' }, 'Fleet screen'),
        '.',
      ]),
    );
    if (targets.length === 0) content.unshift(notAvailable('Slave selection', 'The configuration declares no targets.'));

    const element = panel({ title: 'Slaves', note: 'Which machine and model pairs may serve this principal.', content });

    function edits() {
      const deny = [...boxes].filter(([, box]) => !box.checked).map(([id]) => id);
      const same = deny.length === denied.size && deny.every((id) => denied.has(id));
      if (same) return [];
      if (deny.length === 0) return own ? [{ op: 'remove', kind: 'binding', id: ownId }] : [];
      return [{ op: 'set', kind: 'binding', id: ownId, fields: { scope, model: '*', deny } }];
    }

    return { element, edits };
  }

  // -- Priority and limits -----------------------------------------------------

  function quotaSection(scope) {
    const principal = scope.slice('principal:'.length);
    const quotas = recordsOf(active.records, 'quota');
    const mine = quotas.filter((q) => q.scope === scope);
    const tenant = ctx.session && ctx.session.tenant;
    const tenantQuota = quotas.find((r) => r.scope === `tenant:${tenant}`);
    const tenantClass = (tenantQuota && tenantQuota.class) || 'standard';
    const current = mine[0];
    const note =
      'Under contention, interactive requests are admitted before standard, and standard before batch. ' +
      `This tenant’s class is ${tenantClass}. Limits apply to every key ${principal} holds, together; ` +
      'a published change is enforced at once, keeping what is in flight and what has been spent. ' +
      'A key’s own token allowance is separate: it is set on the Keys screen.';

    if (mine.length > 1 || (current && !current.id)) {
      return {
        element: panel({
          title: 'Priority and limits',
          note,
          content: [
            el('p', {
              text:
                mine.length > 1
                  ? 'Several quotas are written for this principal; edit the policy text.'
                  : 'This principal’s quota is written as policy text without an id; edit it there.',
            }),
            limitsTable(current, tenantQuota, null),
          ],
        }),
        edits: () => [],
      };
    }

    const classField = textField({
      id: 'principal-access-class',
      label: 'Queue class',
      value: current ? current.class || 'standard' : 'inherit',
      choices: ['inherit', ...CLASSES],
      hint: 'Inherit uses the tenant’s class. A quota that sets any limit also sets a class, so choose one then.',
    });
    /** @type {Map<string, HTMLInputElement|HTMLSelectElement>} */
    const inputs = new Map();
    for (const limit of LIMITS) {
      const input = el('input', {
        type: 'text',
        inputmode: 'numeric',
        name: `principal-access-${limit.name}`,
        id: `principal-access-${limit.name}`,
        value: current && current[limit.name] !== undefined ? String(current[limit.name]) : '',
        autocomplete: 'off',
        spellcheck: 'false',
        'aria-label': `${limit.label} for ${principal}`,
        placeholder: 'no limit',
      });
      inputs.set(limit.name, input);
    }
    const period = textField({
      id: 'principal-access-budget_period',
      label: 'Budget period',
      value: (current && current.budget_period) || 'daily',
      choices: PERIODS,
      hint: 'A fixed window of 24 hours or 30 days that starts again each time it runs out — not a calendar day or month.',
    });
    const unpriced = recordsOf(active.records, 'price').length === 0;
    inputs.set('budget_period', /** @type {HTMLSelectElement} */ (period.input));
    const status = el('p', { class: 'field__hint', role: 'status', 'aria-live': 'polite' });

    const element = panel({
      title: 'Priority and limits',
      note,
      content: [
        classField.element,
        limitsTable(current, tenantQuota, inputs),
        period.element,
        unpriced
          ? banner(
              'warn',
              'No price schedule is configured, so no request costs anything and a spend budget never refuses. Add `price` records to the policy text for it to take effect.',
            )
          : null,
        status,
      ].filter(Boolean),
    });

    /**
     * The edits that bring this principal's quota to what the form says, or
     * `null` after reporting a value the router would refuse.
     */
    function edits() {
      status.textContent = '';
      /** @type {Record<string, string|null>} */
      const wanted = {};
      for (const limit of LIMITS) {
        const input = /** @type {HTMLInputElement} */ (inputs.get(limit.name));
        const text = String(input.value).trim();
        if (text === '') continue;
        if (!/^[0-9]+$/.test(text) || Number(text) < 1 || Number(text) > limit.max) {
          status.textContent =
            `${limit.label} must be a whole number from 1 to ${limit.max}. Leave it empty for no principal-level limit — 0 is not accepted, because the policy text reads 0 as “unlimited”.`;
          input.focus();
          return null;
        }
        wanted[limit.name] = text;
      }
      if (wanted.budget !== undefined) wanted.budget_period = String(period.input.value);
      const klass = String(classField.input.value);
      const limited = Object.keys(wanted).length > 0;

      if (!limited && klass === 'inherit') {
        return current ? [{ op: 'remove', kind: 'quota', id: current.id }] : [];
      }
      if (limited && klass === 'inherit') {
        status.textContent = `A quota with limits also sets a queue class. Choose one — the tenant’s is ${tenantClass}.`;
        classField.input.focus();
        return null;
      }

      /** @type {Record<string, string|null>} */
      const fields = { ...wanted, class: klass };
      if (!current) {
        return [{ op: 'set', kind: 'quota', id: recordId('pq', scope), fields: { scope, ...fields } }];
      }
      // Only what changed, and an explicit null for each limit cleared, so a
      // field this form did not touch is never rewritten.
      /** @type {Record<string, string|null>} */
      const changed = {};
      for (const [name, value] of Object.entries(fields)) {
        if (String(current[name] ?? '') !== value) changed[name] = value;
      }
      for (const name of LIMIT_NAMES) {
        if (current[name] !== undefined && !(name in fields)) changed[name] = null;
      }
      return Object.keys(changed).length === 0 ? [] : [{ op: 'set', kind: 'quota', id: current.id, fields: changed }];
    }

    return { element, edits };
  }

  /**
   * One row per limit: this principal's (editable when `inputs` is given) and
   * the tenant's, which also binds and is shown read-only.
   */
  function limitsTable(current, tenantQuota, inputs) {
    const tenantValue = (name) =>
      tenantQuota && tenantQuota[name] !== undefined ? String(tenantQuota[name]) : 'no limit';
    return table({
      caption: 'Limits for this principal, beside the tenant’s',
      columns: [
        { label: 'Limit', cell: (row) => el('span', { text: row.label }) },
        {
          label: 'This principal',
          cell: (row) =>
            inputs
              ? inputs.get(row.name)
              : el('span', { text: current && current[row.name] !== undefined ? String(current[row.name]) : 'no limit' }),
        },
        { label: 'Unit', cell: (row) => el('span', { class: 'panel__note', text: row.unit }) },
        { label: 'Tenant (also applies)', cell: (row) => el('span', { text: tenantValue(row.name) }) },
      ],
      rows: LIMITS,
      empty: '',
    });
  }
}
