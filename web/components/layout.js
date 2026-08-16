/**
 * Shared building blocks the screens of specification 15.3 need.
 *
 * `dom.js` builds nodes and `table.js` builds the page furniture; this module
 * holds the handful of patterns that recur across screens and that would
 * otherwise be reimplemented — slightly differently each time — in ten places.
 *
 * Two of them exist for reasons that are not cosmetic:
 *
 * - [`confirmPrompt`] and [`actionButton`] make a destructive action a
 *   deliberate, single, non-optimistic act. Specification 15.4: "The SPA
 *   performs optimistic UI only for reversible view state, never for
 *   security-sensitive mutations." Nothing here paints a result before the
 *   router has confirmed it, and neither control can be fired twice while its
 *   request is in flight.
 * - [`notAvailable`] is the one honest answer for a screen whose data no
 *   endpoint yet returns. An operator has to be able to trust that what a
 *   screen shows is what the router said, so a capability the router does not
 *   expose is named as missing rather than filled with a plausible example.
 *
 * Every node here is constructed, never parsed from a string, for the reasons
 * set out at the top of `dom.js`.
 */

import { append, el, text } from './dom.js';

/**
 * A definition list of label/value pairs.
 *
 * The default layout for "what is this object" panels — target detail, key
 * metadata, a decision trace header — where a two-column table would imply a
 * comparison that is not there.
 *
 * @param {Array<[string, Node|string]|null|undefined|false>} entries
 * @param {object} [options]
 * @param {boolean} [options.wide] Give values their own line, for long values
 *   such as a digest, a reason string, or a list of scopes.
 * @returns {HTMLElement}
 */
export function definitionList(entries, { wide = false } = {}) {
  const list = el('dl', { class: wide ? 'deflist deflist--wide' : 'deflist' });
  for (const entry of entries) {
    if (!entry) {
      continue;
    }
    const [label, value] = entry;
    list.appendChild(el('dt', { text: label }));
    // An absent value is shown as an em dash rather than an empty cell: the
    // difference between "the router reported nothing" and "the screen forgot
    // to render it" should never be invisible.
    const shown = value === null || value === undefined || value === '' ? text('—') : value;
    list.appendChild(el('dd', {}, shown));
  }
  return list;
}

/**
 * A card with a title and a row of actions in its header.
 *
 * `card` from `table.js` covers the titled block; this adds the action slot
 * that most screens need — refresh, create, export — without every screen
 * inventing its own header markup.
 *
 * @param {object} options
 * @param {string} options.title
 * @param {Node[]} [options.actions] Buttons or links, aligned to the end.
 * @param {Array<Node|string>|Node|string} options.content
 * @param {string} [options.note] A sentence under the title.
 * @returns {HTMLElement}
 */
export function panel({ title, actions = [], content, note }) {
  const heading = el('h2', { class: 'card__title', text: title });
  const head = el('div', { class: 'panel__head' }, [
    el('div', {}, [heading, note ? el('p', { class: 'panel__note', text: note }) : null]),
    actions.length > 0 ? el('div', { class: 'panel__actions' }, actions) : null,
  ]);
  return el('section', { class: 'card' }, [head, content]);
}

/**
 * A filter or action row.
 *
 * Grouped and labelled rather than a bare row of controls, so that a screen
 * reader announces "Filters" once instead of leaving the operator to infer
 * what a run of unlabelled inputs is for.
 *
 * @param {Array<Node|null>} controls
 * @param {object} [options]
 * @param {string} [options.label] Accessible name for the group.
 * @returns {HTMLElement}
 */
export function toolbar(controls, { label = 'Filters' } = {}) {
  return el('div', { class: 'toolbar', role: 'group', 'aria-label': label }, controls);
}

/**
 * A compact labelled control for a [`toolbar`].
 *
 * `field` from `table.js` is the stacked form layout; this is its inline
 * sibling. The label is a real `<label for>` in both, because a placeholder is
 * not a label — it disappears exactly when the operator needs it.
 *
 * @param {object} options
 * @param {string} options.id
 * @param {string} options.label
 * @param {HTMLElement} options.control
 * @returns {HTMLElement}
 */
export function inlineField({ id, label, control }) {
  control.id = id;
  return el('div', { class: 'toolbar__field' }, [
    el('label', { class: 'toolbar__label', for: id }, label),
    control,
  ]);
}

/**
 * A button whose action is awaited, disabled while it runs, and not re-entrant.
 *
 * `onClick` may return a promise. While it is pending the button is disabled
 * and relabelled, so a double click cannot produce two revocations, two
 * rotations, or two publications. A rejection is deliberately *not* swallowed:
 * it propagates to the shell's error boundary in `app.js`, which is the single
 * place that knows how to name an `ApiError` and its request id. Handle it in
 * `onClick` when the screen wants a specific message instead.
 *
 * @param {string} label
 * @param {() => (void|Promise<void>)} onClick
 * @param {object} [options]
 * @param {'default'|'quiet'|'danger'} [options.tone]
 * @param {string} [options.busyLabel]
 * @param {boolean} [options.disabled]
 * @param {string} [options.title]
 * @returns {HTMLButtonElement}
 */
export function actionButton(label, onClick, { tone = 'default', busyLabel = 'Working…', disabled = false, title } = {}) {
  const variant = tone === 'default' ? '' : ` button--${tone}`;
  const button = el('button', {
    type: 'button',
    class: `button${variant}`,
    disabled: disabled || null,
    title: title || null,
    text: label,
  });

  let busy = false;
  button.addEventListener('click', () => {
    if (busy) {
      return;
    }
    const result = onClick();
    if (!result || typeof result.then !== 'function') {
      return;
    }
    busy = true;
    button.disabled = true;
    button.textContent = busyLabel;
    result
      .finally(() => {
        busy = false;
        button.disabled = disabled;
        button.textContent = label;
      })
      .catch((error) => {
        // Re-raised, not reported: `app.js` owns the banner, and it is the only
        // place that knows how to name an `ApiError` and its request id.
        // Throwing from a microtask reaches its window error boundary.
        queueMicrotask(() => {
          throw error;
        });
      });
  });

  return button;
}

/**
 * A confirmation prompt for a destructive action.
 *
 * Rendered inline rather than as a modal: the operator can still read the row
 * they are about to act on, which is the information the decision actually
 * needs. When `phrase` is given the confirm button stays disabled until it is
 * typed exactly — reserved for actions that cannot be undone (revoking a key,
 * quarantining a target), because a friction that is applied to everything is
 * a friction that gets typed without reading.
 *
 * @param {object} options
 * @param {string} options.message What is about to happen, in one sentence.
 * @param {string} [options.detail] Consequences worth spelling out.
 * @param {string} [options.confirmLabel]
 * @param {string} [options.cancelLabel]
 * @param {string} [options.phrase] Text the operator must type to enable confirm.
 * @param {() => (void|Promise<void>)} options.onConfirm
 * @param {() => void} [options.onCancel]
 * @returns {HTMLElement}
 */
export function confirmPrompt({
  message,
  detail,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  phrase,
  onConfirm,
  onCancel,
}) {
  const wrapper = el('div', {
    class: 'confirm',
    role: 'group',
    'aria-label': 'Confirm this action',
    tabindex: '-1',
  });

  const confirm = actionButton(confirmLabel, onConfirm, { tone: 'danger' });
  if (phrase) {
    // Disabled here rather than through the option, so that a failed attempt
    // leaves the button usable: the phrase the operator typed is still there,
    // and making them retype it after the router returned an error is punishing
    // them for the router's failure.
    confirm.disabled = true;
  }

  const cancel = el('button', { type: 'button', class: 'button button--quiet' }, cancelLabel);
  cancel.addEventListener('click', () => {
    if (onCancel) {
      onCancel();
    } else {
      wrapper.remove();
    }
  });

  let input = null;
  if (phrase) {
    input = el('input', {
      type: 'text',
      autocomplete: 'off',
      spellcheck: 'false',
      'aria-label': `Type ${phrase} to confirm`,
    });
    input.addEventListener('input', () => {
      confirm.disabled = input.value.trim() !== phrase;
    });
  }

  append(wrapper, [
    el('p', { class: 'confirm__message', text: message }),
    detail ? el('p', { class: 'confirm__detail', text: detail }) : null,
    phrase
      ? el('label', { class: 'confirm__phrase' }, [
          el('span', { text: `Type ${phrase} to confirm` }),
          input,
        ])
      : null,
    el('div', { class: 'button-row' }, [confirm, cancel]),
  ]);

  // Focus follows the prompt once it is in the document; a confirmation the
  // keyboard has to be walked to is one that gets confirmed by accident.
  queueMicrotask(() => {
    if (wrapper.isConnected) {
      (input || confirm).focus();
    }
  });

  return wrapper;
}

/**
 * A secret shown exactly once.
 *
 * Specification 15.3: a created key's secret is "never displayed again", and
 * credential values are write-only. The block therefore says so before the
 * operator has a chance to navigate away, offers a copy, and can be cleared
 * from the document deliberately.
 *
 * The value is never put anywhere but a text node and the clipboard: no URL, no
 * history entry, no storage.
 *
 * @param {object} options
 * @param {string} options.value
 * @param {string} [options.label]
 * @param {string} [options.notice]
 * @param {() => void} [options.onDismiss]
 * @returns {HTMLElement}
 */
export function secretOnce({
  value,
  label = 'Secret',
  notice = 'This value is shown once. The router cannot retrieve it again — store it now.',
  onDismiss,
}) {
  const box = el('div', { class: 'secret', text: value });
  const status = el('p', { class: 'secret__status', role: 'status', 'aria-live': 'polite' });

  const copy = el('button', { type: 'button', class: 'button button--quiet' }, 'Copy');
  copy.addEventListener('click', () => {
    const clipboard = navigator.clipboard;
    if (!clipboard || typeof clipboard.writeText !== 'function') {
      // A non-secure context has no clipboard API. Saying so beats a button
      // that appears to work; the value is selectable either way.
      status.textContent = 'Copying is unavailable here — select the value and copy it manually.';
      return;
    }
    clipboard.writeText(value).then(
      () => {
        status.textContent = 'Copied to the clipboard.';
      },
      () => {
        status.textContent = 'The browser refused the copy — select the value and copy it manually.';
      },
    );
  });

  const dismiss = el('button', { type: 'button', class: 'button button--quiet' }, 'I have stored it');
  const wrapper = el('section', { class: 'secret-block' }, [
    el('h3', { class: 'secret__label', text: label }),
    el('p', { class: 'secret__notice', text: notice }),
    box,
    el('div', { class: 'button-row' }, [copy, dismiss]),
    status,
  ]);

  dismiss.addEventListener('click', () => {
    wrapper.remove();
    if (onDismiss) {
      onDismiss();
    }
  });

  return wrapper;
}

/**
 * A neutral empty state.
 *
 * @param {string} message
 * @param {string} [detail]
 * @returns {HTMLElement}
 */
export function emptyState(message, detail) {
  return el('div', { class: 'empty-state' }, [
    el('p', { class: 'empty-state__title', text: message }),
    detail ? el('p', { class: 'empty-state__detail', text: detail }) : null,
  ]);
}

/**
 * The screen needs something the management API does not yet expose.
 *
 * Deliberately a single shared component with fixed wording. The alternative —
 * each screen inventing its own phrasing, or worse, a sample row — would leave
 * an operator unable to tell a real answer from a placeholder, and that
 * distinction is the whole value of a management console.
 *
 * @param {string} capability What the screen would show, e.g. "Linked identities".
 * @param {string} [detail] What the operator can do instead, if anything.
 * @returns {HTMLElement}
 */
export function notAvailable(capability, detail) {
  return el('div', { class: 'empty-state empty-state--pending' }, [
    el('p', { class: 'empty-state__title', text: `${capability} is not available yet` }),
    el('p', {
      class: 'empty-state__detail',
      text: 'The router does not yet expose this; it is tracked as management API work. Nothing is shown here rather than an approximation.',
    }),
    detail ? el('p', { class: 'empty-state__detail', text: detail }) : null,
  ]);
}

/**
 * The "load the next page" control for a cursor-paginated list.
 *
 * Every list endpoint answers with `{data, next_cursor, has_more}`; returns
 * `null` when there is no next page, so a screen can append the result without
 * testing first.
 *
 * @param {object} envelope The list response body.
 * @param {(cursor: string) => (void|Promise<void>)} onNext
 * @returns {HTMLElement|null}
 */
export function morePager(envelope, onNext) {
  const cursor = envelope && envelope.next_cursor;
  if (!cursor) {
    return null;
  }
  return el(
    'div',
    { class: 'button-row pager' },
    actionButton('Load more', () => onNext(String(cursor)), {
      tone: 'quiet',
      busyLabel: 'Loading…',
    }),
  );
}
