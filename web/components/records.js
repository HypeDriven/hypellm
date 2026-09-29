/**
 * Structured edits to the active configuration.
 *
 * `POST /admin/v1/policies:edit` turns a small list of record edits into a
 * policy draft of the whole active configuration, and validates it at once.
 * Nothing here changes routing or the fleet: the draft still has to be
 * published through the same workflow as a hand-written one, by a second
 * person unless this deployment permits self-approval (specification 15.4).
 * The outcome panel says so every time, because a form that looks like it
 * saved something is exactly the impression it must not give.
 *
 * The record list comes from `GET /admin/v1/policies/active`. A router that
 * does not return one gets an explicit "not available" rather than an empty
 * form that would look like a configuration with nothing in it.
 */

import { ApiError } from '../api.js';
import { el } from './dom.js';
import { actionButton, confirmPrompt, notAvailable } from './layout.js';
import { banner, buttonRow, field } from './table.js';

/**
 * Read the active configuration's records.
 *
 * @param {import('../api.js').Api} api
 * @returns {Promise<{records: object[]|null, etag: string|null, version: number|null}>}
 */
export async function loadActiveRecords(api) {
  const { data, etag } = await api.get('/policies/active', { shared: true });
  return {
    records: Array.isArray(data.records) ? data.records : null,
    etag,
    version: data.version ?? null,
  };
}

/**
 * The records of one kind, as `{fields}` objects.
 *
 * @param {object[]} records
 * @param {string} kind
 * @returns {object[]}
 */
export function recordsOf(records, kind) {
  return (records || [])
    .filter((record) => record.kind === kind)
    .map((record) => record.fields || {});
}

/**
 * Split a comma-joined list field.
 *
 * @param {string|undefined} value
 * @returns {string[]}
 */
export function listOf(value) {
  if (!value) return [];
  return String(value)
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item !== '');
}

/**
 * The explicit state for a session that may not draft.
 *
 * @returns {HTMLElement}
 */
export function requiresEditPolicy() {
  return el('div', { class: 'empty-state' }, [
    el('p', { class: 'empty-state__title', text: 'Requires policy edit permission' }),
    el('p', {
      class: 'empty-state__detail',
      text:
        'Changing machines, deployments or routing priority creates a policy draft, which ' +
        'needs the edit_policy permission. This session does not hold it.',
    }),
  ]);
}

/**
 * The state for a router that does not return the active records.
 *
 * @param {string} what
 * @returns {HTMLElement}
 */
export function recordsUnavailable(what) {
  return notAvailable(
    what,
    'GET /admin/v1/policies/active did not return the configuration records, so this ' +
      'screen cannot show what is declared.',
  );
}

/**
 * A text or number input wrapped in a labelled field.
 *
 * @param {object} options
 * @param {string} options.id
 * @param {string} options.label
 * @param {string} [options.value]
 * @param {string} [options.hint]
 * @param {'text'|'number'} [options.type]
 * @param {string[]} [options.choices] Render a `<select>` over these instead.
 * @returns {{element: HTMLElement, input: HTMLInputElement|HTMLSelectElement}}
 */
export function textField({ id, label, value = '', hint, type = 'text', choices }) {
  let input;
  if (choices) {
    const options = choices.map((choice) =>
      el('option', { value: choice, selected: choice === value || null }, choice === '' ? '(default)' : choice),
    );
    input = el('select', { name: id }, options);
  } else {
    input = el('input', { type, name: id, value: String(value ?? ''), autocomplete: 'off', spellcheck: 'false' });
  }
  return { element: field({ id, label, hint, control: input }), input };
}

/**
 * Send edits and report what the router did with them.
 *
 * The result is rendered into `outlet`: the validation verdict, every error
 * the router listed, a link to the draft on the policies screen, and — for a
 * session that may publish a valid draft — a publish control that needs the
 * draft identifier typed, as the policies screen does.
 *
 * @param {object} ctx The view context.
 * @param {object[]} edits
 * @param {HTMLElement} outlet
 * @param {object} [options]
 * @param {() => (string|null)} [options.etag] The active configuration's tag.
 * @param {() => (void|Promise<void>)} [options.onPublished]
 * @returns {Promise<object|null>} The router's answer, or null when refused.
 */
export async function proposeEdits(ctx, edits, outlet, { etag, onPublished } = {}) {
  outlet.replaceChildren();
  let data;
  try {
    // Shared: a screen refresh must not cancel a draft being created.
    ({ data } = await ctx.api.request('POST', '/policies:edit', { body: { edits }, shared: true }));
  } catch (error) {
    if (error && error.name === 'AbortError') throw error;
    const message = error instanceof ApiError ? error.message : String(error);
    outlet.append(banner('error', `The router refused the change; no draft was created. ${message}`));
    return null;
  }

  const draftId = String(data.draft_id || '');
  const errors = Array.isArray(data.errors) ? data.errors : [];
  const draftLink = el('a', { href: `#/policies?draft=${encodeURIComponent(draftId)}` }, `draft ${draftId}`);

  if (data.valid) {
    outlet.append(
      banner('ok', [
        'Created ',
        draftLink,
        '. It validates, but nothing has changed yet: it must be published before the router ' +
          'uses it, and publishing normally needs a second person.',
      ]),
    );
  } else {
    outlet.append(
      banner('error', [
        'Created ',
        draftLink,
        `, but it does not validate (${errors.length} error${errors.length === 1 ? '' : 's'}). ` +
          'It cannot be published as it stands.',
      ]),
    );
  }
  if (errors.length > 0) {
    outlet.append(
      el(
        'ul',
        {},
        errors.map((error) =>
          el('li', {}, [
            el('code', { text: String(error.code || '') }),
            ` — ${String(error.message || '')}`,
          ]),
        ),
      ),
    );
  }

  if (data.valid && ctx.can('publish_policy')) {
    const confirmBox = el('div');
    const publish = actionButton('Publish…', () => {
      confirmBox.replaceChildren(
        confirmPrompt({
          message: `Publish draft ${draftId}?`,
          detail:
            'Activation is atomic and applies to every request that starts after it. If you ' +
            'authored this draft, the router refuses unless self-approval is permitted.',
          confirmLabel: 'Publish it',
          phrase: draftId,
          onConfirm: async () => {
            try {
              const { data: published } = await ctx.api.request(
                'POST',
                `/policies/${encodeURIComponent(draftId)}:publish`,
                { body: {}, ifMatch: (etag && etag()) || '*', shared: true },
              );
              confirmBox.replaceChildren(
                banner('ok', `Draft ${draftId} is active as v${published.version}.`),
              );
              ctx.notify('ok', `Draft ${draftId} published as v${published.version}.`);
              if (onPublished) await onPublished();
            } catch (error) {
              if (error && error.name === 'AbortError') throw error;
              const message = error instanceof ApiError ? error.message : String(error);
              confirmBox.replaceChildren(banner('error', `The publication was refused. Nothing changed. ${message}`));
            }
          },
          onCancel: () => confirmBox.replaceChildren(),
        }),
      );
    });
    outlet.append(buttonRow([publish]), confirmBox);
  }
  return data;
}
