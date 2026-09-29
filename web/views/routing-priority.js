/**
 * Routing priority, edited as policy drafts.
 *
 * Two orderings decide which target a request prefers, and both are edited
 * here: an alias's `targets` list, and a binding's `prefer` list (its rank),
 * together with the binding's `priority` and `weight`. Reordering produces a
 * draft through `POST /admin/v1/policies:edit`; the draft is validated at once
 * and still has to be published before routing changes.
 */

import { el } from '../components/dom.js';
import { actionButton, emptyState } from '../components/layout.js';
import {
  listOf,
  loadActiveRecords,
  proposeEdits,
  recordsOf,
  recordsUnavailable,
  requiresEditPolicy,
  textField,
} from '../components/records.js';
import { buttonRow, card } from '../components/table.js';

/**
 * An ordered list with up/down controls.
 *
 * @param {string[]} initial
 * @param {string} label What the list orders, for button names.
 * @returns {{element: HTMLElement, value: () => string[]}}
 */
function orderedList(initial, label) {
  const items = [...initial];
  const list = el('ol', { 'aria-label': label });

  function move(index, delta) {
    const to = index + delta;
    if (to < 0 || to >= items.length) return;
    [items[index], items[to]] = [items[to], items[index]];
    paint();
    // Keep the keyboard on the item that moved.
    const button = list.children[to]?.querySelector(delta < 0 ? '[data-dir="up"]' : '[data-dir="down"]');
    if (button && !button.disabled) button.focus();
  }

  function paint() {
    list.replaceChildren(
      ...items.map((item, index) => {
        const up = el('button', {
          type: 'button',
          class: 'button button--quiet',
          'aria-label': `Move ${item} up`,
          dataset: { dir: 'up' },
          disabled: index === 0 || null,
          text: '↑',
        });
        const down = el('button', {
          type: 'button',
          class: 'button button--quiet',
          'aria-label': `Move ${item} down`,
          dataset: { dir: 'down' },
          disabled: index === items.length - 1 || null,
          text: '↓',
        });
        up.addEventListener('click', () => move(index, -1));
        down.addEventListener('click', () => move(index, 1));
        return el('li', {}, [el('code', { text: item }), ' ', up, down]);
      }),
    );
  }

  paint();
  return { element: list, value: () => [...items] };
}

/**
 * The routing-priority panel content.
 *
 * @param {object} ctx The view context.
 * @returns {HTMLElement}
 */
export function routingPriority(ctx) {
  const body = el('div', { class: 'policy-stack' });
  const outcome = el('div', { class: 'policy-stack', role: 'status', 'aria-live': 'polite' });
  const root = el('div', { class: 'policy-stack' }, [outcome, body]);
  let active = { records: null, etag: null };

  if (!ctx.can('edit_policy')) {
    body.append(requiresEditPolicy());
    return root;
  }

  void reload();

  async function reload() {
    try {
      active = await loadActiveRecords(ctx.api);
    } catch (error) {
      if (error && error.name === 'AbortError') return;
      body.replaceChildren(emptyState('The active configuration could not be read.', String(error.message || error)));
      return;
    }
    paint();
  }

  function submit(edits) {
    return proposeEdits(ctx, edits, outcome, { etag: () => active.etag, onPublished: reload });
  }

  function paint() {
    if (!active.records) {
      body.replaceChildren(recordsUnavailable('The priority matrix'));
      return;
    }
    const aliases = recordsOf(active.records, 'alias');
    const bindings = recordsOf(active.records, 'binding');

    const aliasCards = aliases.map((alias) => {
      const order = orderedList(listOf(alias.targets), `Targets of ${alias.id}, most preferred first`);
      return card(`Alias ${alias.id}`, [
        el('p', { class: 'panel__note', text: 'Targets in order of preference.' }),
        order.element,
        buttonRow([
          actionButton('Draft this order', () =>
            submit([{ op: 'set', kind: 'alias', id: alias.id, fields: { targets: order.value() } }]),
            { busyLabel: 'Drafting…' },
          ),
        ]),
      ]);
    });

    const bindingCards = bindings.map((binding) => {
      const prefix = `binding-${binding.id}`;
      const order = orderedList(listOf(binding.prefer), `Preferred targets of ${binding.id}, rank 0 first`);
      const priority = textField({ id: `${prefix}-priority`, label: 'Priority', type: 'number', value: binding.priority || '' });
      const weight = textField({ id: `${prefix}-weight`, label: 'Weight', type: 'number', value: binding.weight || '' });
      return card(`Binding ${binding.id}`, [
        el('p', { class: 'panel__note', text: `Scope ${binding.scope}${binding.model ? `, model ${binding.model}` : ''}.` }),
        priority.element,
        weight.element,
        listOf(binding.prefer).length ? order.element : el('p', { text: 'This binding declares no preferred targets.' }),
        buttonRow([
          actionButton('Draft this binding', () => {
            const fields = {};
            const p = String(priority.input.value).trim();
            const w = String(weight.input.value).trim();
            // An emptied field is removed only if it was set; the router's
            // default then applies.
            if (p !== '') fields.priority = Number(p);
            else if (binding.priority !== undefined) fields.priority = null;
            if (w !== '') fields.weight = Number(w);
            else if (binding.weight !== undefined) fields.weight = null;
            if (listOf(binding.prefer).length) fields.prefer = order.value();
            return submit([{ op: 'set', kind: 'binding', id: binding.id, fields }]);
          }, { busyLabel: 'Drafting…' }),
        ]),
      ]);
    });

    body.replaceChildren(
      el('h3', { text: 'Aliases' }),
      ...(aliasCards.length ? aliasCards : [emptyState('No aliases are declared.')]),
      el('h3', { text: 'Bindings' }),
      ...(bindingCards.length ? bindingCards : [emptyState('No bindings are declared.')]),
    );
  }

  return root;
}
