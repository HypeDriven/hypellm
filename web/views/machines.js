/**
 * The Machines screen: shared memory, and who waits for it first.
 *
 * Several targets can live on one physical machine — a DGX Spark serving a
 * resident Qwen, a MiniMax-H3 and a YuE2 — and their work shares its memory.
 * Each target declares what one request or job holds while it runs and the
 * class it waits in; work starts only when it fits, and a waiting higher class
 * holds back a lower one even when the lower one would fit.
 *
 * The top half is live (`GET /admin/v1/machines`): what is held, by which
 * target, and the waiting line in the order it will be admitted. The bottom
 * half edits the same records as policy drafts (`POST /admin/v1/policies:edit`)
 * — a machine's capacity, which machine a provider runs on, and each target's
 * memory and class — and a draft still has to be published before anything
 * changes.
 */

import { ApiError } from '../api.js';
import { el, formatDuration, pill } from '../components/dom.js';
import { actionButton, emptyState, notAvailable, panel, toolbar } from '../components/layout.js';
import {
  loadActiveRecords,
  proposeEdits,
  recordsOf,
  recordsUnavailable,
  requiresEditPolicy,
  textField,
} from '../components/records.js';
import { buttonRow, card, pageHeader, render, table } from '../components/table.js';

/** Screen metadata, read by the shell to build navigation. */
export const meta = {
  path: '/machines',
  title: 'Machines',
  permission: 'read_summary',
  lede:
    'Memory shared by the targets on one machine: what running work holds, what is waiting for it and in which order, and the priorities that decide that order.',
};

const GIB = 1024 ** 3;
const CLASSES = ['interactive', 'standard', 'batch'];
const REFRESH_MILLIS = 5000;

/**
 * Bytes as GiB, one decimal.
 *
 * @param {number} value
 * @returns {string}
 */
function gib(value) {
  return `${(Number(value || 0) / GIB).toFixed(1)} GiB`;
}

/**
 * A GiB field's value as whole bytes, or null when it is not a number.
 *
 * @param {string} text
 * @returns {number|null}
 */
function bytesOf(text) {
  const value = Number(String(text).trim());
  if (!Number.isFinite(value) || value < 0) return null;
  return Math.round(value * GIB);
}

/**
 * Tone for a waiting class: the first served is the most prominent.
 *
 * @param {string} cls
 * @returns {string}
 */
function classTone(cls) {
  switch (cls) {
    case 'interactive':
      return 'good';
    case 'batch':
      return 'warn';
    default:
      return 'neutral';
  }
}

/**
 * Held memory against capacity.
 *
 * @param {number} held
 * @param {number} capacity
 * @returns {HTMLElement}
 */
function memoryBar(held, capacity) {
  const meter = el('meter', {
    class: 'meter',
    min: '0',
    max: String(Math.max(capacity, 1)),
    value: String(Math.min(held, capacity)),
    'aria-label': `${gib(held)} of ${gib(capacity)} held by running work`,
  });
  return el('div', { class: 'meter-row' }, [
    meter,
    el('span', { class: 'meter-row__label', text: `${gib(held)} / ${gib(capacity)} held` }),
  ]);
}

/**
 * Read the machines, or null when this router has none to report.
 *
 * @param {import('../api.js').Api} api
 * @returns {Promise<object[]|null>}
 */
async function load(api) {
  try {
    const { data } = await api.get('/machines');
    return Array.isArray(data.data) ? data.data : [];
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return null;
    throw error;
  }
}

/**
 * One machine's live state.
 *
 * @param {object} machine
 * @returns {HTMLElement}
 */
function liveCard(machine) {
  const targets = machine.targets || [];
  const declared = table({
    caption: `Targets on ${machine.id}`,
    columns: ['Target', 'Holds while running', 'Class'],
    rows: targets.map((t) => [
      el('code', { text: t.id }),
      t.run_memory_bytes ? gib(t.run_memory_bytes) : 'nothing (resident)',
      t.class ? pill(t.class, classTone(t.class)) : 'the caller’s',
    ]),
  });
  if (!machine.live) {
    return card(`Machine ${machine.id}`, [
      el('p', { class: 'panel__note', text: machine.description || '' }),
      el('p', {
        text: 'No live figures: this management API has no admission controller attached, or the configuration naming this machine is not active yet.',
      }),
      declared,
    ]);
  }
  const holders = machine.holders || [];
  const waiting = machine.waiting || [];
  return card(`Machine ${machine.id}`, [
    el('p', { class: 'panel__note', text: machine.description || '' }),
    memoryBar(machine.held_bytes, machine.memory_bytes),
    table({
      caption: 'Running now',
      columns: ['Target', 'Running', 'Holding'],
      rows: holders.map((h) => [el('code', { text: h.target }), String(h.holds), gib(h.bytes)]),
      empty: 'Nothing running holds memory here.',
    }),
    table({
      caption: 'Waiting, first to be admitted at the top',
      columns: ['#', 'Class', 'Needs', 'Waited'],
      rows: waiting.map((w, index) => [
        String(index + 1),
        pill(w.class, classTone(w.class)),
        gib(w.bytes),
        formatDuration(w.waited_ms),
      ]),
      empty: 'Nothing is waiting for memory.',
    }),
    declared,
  ]);
}

/**
 * Render the screen.
 *
 * @param {HTMLElement} container
 * @param {object} ctx
 * @returns {Promise<() => void>}
 */
export async function mount(container, ctx) {
  let stopped = false;
  let timer = null;
  let machines = await load(ctx.api);

  if (machines === null) {
    render(container, [
      pageHeader(meta.title, meta.lede),
      notAvailable('Machine memory', 'This router does not serve GET /admin/v1/machines.'),
    ]);
    return () => {
      stopped = true;
    };
  }

  const live = el('div', { class: 'policy-stack' });
  const editor = el('div', { class: 'policy-stack' });
  const outcome = el('div', { class: 'policy-stack', role: 'status', 'aria-live': 'polite' });
  const refresh = actionButton('Refresh', () => reload(), { tone: 'quiet', busyLabel: 'Reading…' });
  let active = { records: null, etag: null };

  render(container, [
    pageHeader(meta.title, meta.lede),
    toolbar([el('div', { class: 'panel__actions' }, refresh)], { label: 'Machine controls' }),
    live,
    panel({
      title: 'Capacity and priority',
      note:
        'Each change becomes a policy draft that validates at once and must be published before the router uses it. ' +
        'Classes are served interactive first, then standard, then batch; within a class, first come first served. ' +
        'A target that holds nothing while running (a resident model) is never held back.',
      content: el('div', { class: 'policy-stack' }, [outcome, editor]),
    }),
  ]);
  paintLive();
  timer = window.setInterval(() => {
    reload().catch((error) => {
      if (error && error.name === 'AbortError') return;
      window.clearInterval(timer);
      timer = null;
      ctx.notify('warn', `automatic refresh stopped: ${error && error.message ? error.message : 'the read failed'}`);
    });
  }, REFRESH_MILLIS);

  if (ctx.can('edit_policy')) {
    void loadRecords();
  } else {
    editor.replaceChildren(requiresEditPolicy());
  }

  async function reload() {
    const next = await load(ctx.api);
    if (stopped || next === null) return;
    machines = next;
    paintLive();
  }

  async function loadRecords() {
    try {
      active = await loadActiveRecords(ctx.api);
    } catch (error) {
      if (error && error.name === 'AbortError') return;
      editor.replaceChildren(emptyState('The active configuration could not be read.', String(error.message || error)));
      return;
    }
    if (!stopped) paintEditor();
  }

  function submit(edits) {
    return proposeEdits(ctx, edits, outcome, {
      etag: () => active.etag,
      onPublished: async () => {
        await loadRecords();
        await reload();
      },
    });
  }

  function paintLive() {
    live.replaceChildren(
      ...(machines.length
        ? machines.map(liveCard)
        : [
            emptyState(
              'No machines are declared.',
              'Declare one below, put its providers on it, and give each target the memory one of its requests or jobs holds while it runs.',
            ),
          ]),
    );
  }

  function paintEditor() {
    if (!active.records) {
      editor.replaceChildren(recordsUnavailable('The machine editor'));
      return;
    }
    const declared = recordsOf(active.records, 'machine');
    const providers = recordsOf(active.records, 'provider');
    const targets = recordsOf(active.records, 'target');
    const machineIds = declared.map((m) => m.id);

    const machineCards = declared.map((machine) => {
      const prefix = `machine-${machine.id}`;
      const capacity = textField({
        id: `${prefix}-memory`,
        label: 'Memory work may hold (GiB)',
        type: 'number',
        value: String(Number(machine.memory_bytes || 0) / GIB),
        hint: 'Leave out what is resident regardless: the operating system and any model that never unloads.',
      });
      const description = textField({ id: `${prefix}-description`, label: 'Description', value: machine.description || '' });
      const onIt = new Set(providers.filter((p) => p.machine === machine.id).map((p) => p.id));
      const rows = targets
        .filter((t) => onIt.has(t.provider))
        .map((target) => {
          const tp = `${prefix}-${target.id}`;
          const memory = textField({
            id: `${tp}-memory`,
            label: `${target.id}: holds while running (GiB)`,
            type: 'number',
            value: target.run_memory_bytes ? String(Number(target.run_memory_bytes) / GIB) : '0',
          });
          const cls = textField({
            id: `${tp}-class`,
            label: `${target.id}: class`,
            value: target.class || '',
            choices: ['', ...CLASSES],
          });
          return { target, memory, cls };
        });
      return card(`Machine ${machine.id}`, [
        capacity.element,
        description.element,
        ...rows.flatMap((row) => [row.memory.element, row.cls.element]),
        rows.length ? null : el('p', { text: 'No provider is placed on this machine yet.' }),
        buttonRow([
          actionButton('Draft these changes', () => {
            const total = bytesOf(capacity.input.value);
            if (!total) {
              outcome.replaceChildren(el('p', { text: 'The machine needs a memory figure above zero.' }));
              return Promise.resolve(null);
            }
            const edits = [
              {
                op: 'set',
                kind: 'machine',
                id: machine.id,
                fields: { memory_bytes: total, description: description.input.value.trim() || null },
              },
            ];
            for (const row of rows) {
              const bytes = bytesOf(row.memory.input.value);
              if (bytes === null) {
                outcome.replaceChildren(el('p', { text: `${row.target.id}: the memory is not a number.` }));
                return Promise.resolve(null);
              }
              edits.push({
                op: 'set',
                kind: 'target',
                id: row.target.id,
                fields: { run_memory_bytes: bytes || null, class: row.cls.input.value || null },
              });
            }
            return submit(edits);
          }, { busyLabel: 'Drafting…' }),
          actionButton('Remove machine…', () => {
            const edits = [{ op: 'remove', kind: 'machine', id: machine.id }];
            for (const provider of providers.filter((p) => p.machine === machine.id)) {
              edits.push({ op: 'set', kind: 'provider', id: provider.id, fields: { machine: null } });
            }
            for (const row of rows) {
              edits.push({ op: 'set', kind: 'target', id: row.target.id, fields: { run_memory_bytes: null, class: null } });
            }
            return submit(edits);
          }, { tone: 'quiet', busyLabel: 'Drafting…' }),
        ]),
      ]);
    });

    // Placement: which machine each provider runs on.
    const placement = providers.map((provider) => ({
      provider,
      choice: textField({
        id: `placement-${provider.id}`,
        label: provider.id,
        value: provider.machine || '',
        choices: ['', ...machineIds],
      }),
    }));
    const placementCard = card('Which machine each provider runs on', [
      el('p', {
        class: 'panel__note',
        text: 'A provider on no machine is not memory-checked. Taking one off a machine clears its targets’ memory and class, which mean nothing without it.',
      }),
      ...placement.map((p) => p.choice.element),
      buttonRow([
        actionButton('Draft placement', () => {
          const edits = [];
          for (const { provider, choice } of placement) {
            const next = choice.input.value || null;
            if (next === (provider.machine || null)) continue;
            edits.push({ op: 'set', kind: 'provider', id: provider.id, fields: { machine: next } });
            if (!next) {
              for (const target of targets.filter((t) => t.provider === provider.id)) {
                if (target.run_memory_bytes || target.class) {
                  edits.push({ op: 'set', kind: 'target', id: target.id, fields: { run_memory_bytes: null, class: null } });
                }
              }
            }
          }
          if (edits.length === 0) {
            outcome.replaceChildren(el('p', { text: 'Nothing changed.' }));
            return Promise.resolve(null);
          }
          return submit(edits);
        }, { busyLabel: 'Drafting…' }),
      ]),
    ]);

    const newId = textField({ id: 'machine-new-id', label: 'Machine id', hint: 'Lowercase letters, digits, - . _' });
    const newMemory = textField({ id: 'machine-new-memory', label: 'Memory work may hold (GiB)', type: 'number' });
    const addCard = card('Declare a machine', [
      newId.element,
      newMemory.element,
      buttonRow([
        actionButton('Draft new machine', () => {
          const id = newId.input.value.trim();
          const total = bytesOf(newMemory.input.value);
          if (!id || !total) {
            outcome.replaceChildren(el('p', { text: 'A machine needs an id and a memory figure above zero.' }));
            return Promise.resolve(null);
          }
          return submit([{ op: 'set', kind: 'machine', id, fields: { memory_bytes: total } }]);
        }, { busyLabel: 'Drafting…' }),
      ]),
    ]);

    editor.replaceChildren(...machineCards, placementCard, addCard);
  }

  return () => {
    stopped = true;
    if (timer !== null) window.clearInterval(timer);
  };
}
