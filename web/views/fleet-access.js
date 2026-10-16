/**
 * Who may use which slave, and which model on it, from the Fleet screen.
 *
 * Reads `GET /admin/v1/fleet/access` and writes `fleet_grant` records — and
 * `settings fleet_access_default` — through `POST /admin/v1/policies:edit`.
 * Nothing changes until that draft is published, normally by a second person.
 *
 * Resolution is the router's, not this screen's: the most specific scope with
 * a matching grant decides (principal, then group, then tenant, then global);
 * within one scope an exact host beats `*` and a specific model beats "all
 * models"; a tie between allow and deny is a deny; and a caller no grant
 * mentions gets the default. This screen does not recompute that, so it shows
 * what is *written* for the chosen subject, with "inherit" meaning "this
 * subject has no grant here" — not a prediction of the outcome.
 */

import { ApiError } from '../api.js';
import { el, pill } from '../components/dom.js';
import { actionButton, emptyState, panel } from '../components/layout.js';
import { proposeEdits, textField } from '../components/records.js';
import { buttonRow, table } from '../components/table.js';

const CHOICES = ['inherit', 'allow', 'deny'];

/**
 * A stable identifier for the grant at one (scope, host, model) position.
 *
 * Derived rather than random, so drafting the same cell twice edits one
 * record. FNV-1a over the three selectors, in the identifier alphabet.
 *
 * @param {string} scope @param {string} host @param {string} model
 * @returns {string}
 */
function grantId(scope, host, model) {
  let hash = 0x811c9dc5;
  for (const ch of `${scope}|${host}|${model}`) {
    hash ^= ch.codePointAt(0);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `fa-${hash.toString(16).padStart(8, '0')}`;
}

/**
 * The Slave access panel.
 *
 * @param {object} ctx The view context.
 * @returns {HTMLElement}
 */
export function accessPanel(ctx) {
  const body = el('div', { class: 'policy-stack' });
  const outcome = el('div', { class: 'policy-stack', role: 'status', 'aria-live': 'polite' });

  const section = panel({
    title: 'Slave access',
    note:
      'Which users may be served by which machine, and by which model on it. Every change is a ' +
      'draft; nothing applies until it is published. A user no grant mentions gets the default.',
    content: el('div', { class: 'policy-stack' }, [body, outcome]),
  });

  /** @type {object|null} */
  let data = null;
  let subject = '';
  /** @type {Map<string, HTMLSelectElement>} */
  let cells = new Map();

  void reload();

  async function reload() {
    try {
      ({ data } = await ctx.api.request('GET', '/fleet/access', { shared: true }));
    } catch (error) {
      if (error && error.name === 'AbortError') return;
      if (error instanceof ApiError && error.status === 403) {
        body.replaceChildren(emptyState('Slave access is not visible to this session.', 'read_fleet is needed.'));
        return;
      }
      body.replaceChildren(emptyState('Slave access could not be read.', String(error.message || error)));
      return;
    }
    paint();
  }

  /** @returns {string[]} Every scope token the caller may pick. */
  function scopes() {
    const subjects = data.subjects;
    if (!subjects) return [];
    return [
      ...subjects.principals.map((p) => `principal:${p}`),
      ...subjects.groups.map((g) => `group:${g}`),
      ...subjects.tenants.map((t) => `tenant:${t}`),
      'global',
    ];
  }

  /** @returns {object|undefined} */
  function written(scope, host, model) {
    return (data.grants || []).find((g) => g.scope === scope && g.host === host && g.model === model);
  }

  /** Rows of the matrix: every slave, then each host's "all models", then each model. */
  function rows() {
    const out = [{ host: '*', model: '*', label: 'All slaves', detail: 'All models' }];
    for (const host of data.hosts || []) {
      out.push({ host: host.id, model: '*', label: host.id, detail: 'All models on this slave' });
      for (const model of host.models || []) {
        out.push({
          host: host.id,
          model: `target:${model.target}`,
          label: host.id,
          detail: `${model.target}${model.aliases.length ? ` (${model.aliases.join(', ')})` : ''}`,
        });
      }
    }
    return out;
  }

  function paint() {
    const mayDraft = ctx.can('edit_policy') && data.subjects;
    const defaultLine = el('p', {}, [
      'Default for users no grant mentions: ',
      pill(data.default, data.default === 'allow' ? 'ok' : 'warn'),
    ]);

    if (!mayDraft) {
      body.replaceChildren(
        defaultLine,
        grantsTable(),
        el('p', { text: 'Changing access needs the edit_policy permission.' }),
      );
      return;
    }

    const available = scopes();
    if (!subject || !available.includes(subject)) subject = available[0] || 'global';
    const picker = textField({
      id: 'fleet-access-subject',
      label: 'User, group or tenant',
      value: subject,
      choices: available,
      hint: 'principal: is one user or key holder; group: and tenant: cover many.',
    });
    picker.input.addEventListener('change', () => {
      subject = String(picker.input.value);
      outcome.replaceChildren();
      paint();
    });

    cells = new Map();
    const matrix = table({
      caption: `Access written for ${subject}`,
      columns: [
        { label: 'Slave', cell: (row) => row.label },
        { label: 'Model', cell: (row) => row.detail },
        {
          label: 'Access',
          cell: (row) => {
            const current = written(subject, row.host, row.model);
            const value = current ? (current.allow ? 'allow' : 'deny') : 'inherit';
            const field = textField({
              id: `fleet-access-${row.host}-${row.model}`,
              label: `Access to ${row.detail} on ${row.label}`,
              value,
              choices: CHOICES,
            });
            cells.set(`${row.host}\u0000${row.model}`, /** @type {HTMLSelectElement} */ (field.input));
            return field.input;
          },
        },
      ],
      rows: rows(),
      empty: 'No machine carries a model this tenant can reach.',
    });

    const draft = actionButton('Create draft', () => submit(), { busyLabel: 'Drafting…' });
    body.replaceChildren(defaultLine, defaultControl(), picker.element, matrix, buttonRow([draft]), grantsTable());
  }

  /** The default toggle, with the option that keeps existing users whole. */
  function defaultControl() {
    const next = data.default === 'allow' ? 'deny' : 'allow';
    const keep = el('input', {
      type: 'checkbox',
      id: 'fleet-access-keep',
      checked: true,
      'aria-label': 'Grant every existing user access to all slaves and models',
    });
    const parts = [];
    if (next === 'deny') {
      parts.push(
        el('label', { for: 'fleet-access-keep' }, [
          keep,
          ' Grant every existing user access to all slaves and models, so only users added later start with none',
        ]),
      );
    }
    const flip = actionButton(`Draft default = ${next}`, async () => {
      const edits = [{ op: 'set', kind: 'settings', fields: { fleet_access_default: next } }];
      if (next === 'deny' && keep.checked) {
        for (const principal of data.subjects.principals) {
          const scope = `principal:${principal}`;
          const existing = written(scope, '*', '*');
          edits.push({
            op: 'set',
            kind: 'fleet_grant',
            id: existing ? existing.id : grantId(scope, '*', '*'),
            fields: { scope, host: '*', model: '*', allow: 'true' },
          });
        }
      }
      await proposeEdits(ctx, edits, outcome, { onPublished: reload });
    }, { busyLabel: 'Drafting…', tone: next === 'deny' ? 'danger' : 'default' });
    return el('div', { class: 'policy-stack' }, [...parts, buttonRow([flip])]);
  }

  async function submit() {
    const edits = [];
    for (const row of rows()) {
      const select = cells.get(`${row.host}\u0000${row.model}`);
      if (!select) continue;
      const wanted = String(select.value);
      const current = written(subject, row.host, row.model);
      if (wanted === 'inherit') {
        if (current) edits.push({ op: 'remove', kind: 'fleet_grant', id: current.id });
        continue;
      }
      const allow = wanted === 'allow';
      if (current && current.allow === allow) continue;
      edits.push({
        op: 'set',
        kind: 'fleet_grant',
        id: current ? current.id : grantId(subject, row.host, row.model),
        fields: { scope: subject, host: row.host, model: row.model, allow: allow ? 'true' : 'false' },
      });
    }
    if (edits.length === 0) {
      outcome.replaceChildren(el('p', { text: 'Nothing changed, so no draft was created.' }));
      return;
    }
    await proposeEdits(ctx, edits, outcome, { onPublished: reload });
  }

  function grantsTable() {
    return table({
      caption: 'Fleet grants in the active configuration',
      columns: [
        { label: 'Scope', cell: (g) => g.scope },
        { label: 'Slave', cell: (g) => g.host },
        { label: 'Model', cell: (g) => g.model },
        { label: 'Access', cell: (g) => pill(g.allow ? 'allow' : 'deny', g.allow ? 'ok' : 'danger') },
        { label: 'Record', cell: (g) => el('code', { text: g.id }) },
      ],
      rows: data.grants || [],
      empty: 'No fleet grant is written; every user gets the default.',
    });
  }

  return section;
}
