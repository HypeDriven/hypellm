/**
 * Table and layout components.
 *
 * Every cell value goes through `el`/`text` from `dom.js`, so nothing here can
 * turn an API value into markup.
 */

import { append, el, replace } from './dom.js';

/**
 * @typedef {object} Column
 * @property {string} label      Column heading.
 * @property {(row: object) => (Node|string)} cell  Cell renderer.
 * @property {boolean} [numeric] Right-align and use tabular figures.
 */

/**
 * Build a table.
 *
 * @param {object} options
 * @param {string} [options.caption]
 * @param {Column[]} options.columns
 * @param {object[]} options.rows
 * @param {string} [options.empty] Message shown when there are no rows.
 * @returns {HTMLElement}
 */
export function table({ caption, columns, rows, empty = 'Nothing to show.' }) {
  if (!rows || rows.length === 0) {
    return el('div', { class: 'card' }, el('p', { class: 'empty', text: empty }));
  }

  const head = el(
    'tr',
    {},
    columns.map((column) =>
      el('th', { scope: 'col', class: column.numeric ? 'numeric' : null }, column.label),
    ),
  );

  const body = el(
    'tbody',
    {},
    rows.map((row) =>
      el(
        'tr',
        {},
        columns.map((column) =>
          el('td', { class: column.numeric ? 'numeric' : null }, column.cell(row)),
        ),
      ),
    ),
  );

  const element = el('table', { class: 'table' }, [
    caption ? el('caption', { text: caption }) : null,
    el('thead', {}, head),
    body,
  ]);

  return el('div', { class: 'table-scroll' }, element);
}

/**
 * A statistic tile.
 *
 * @param {string} label
 * @param {string|number} value
 * @param {string} [note]
 * @returns {HTMLElement}
 */
export function stat(label, value, note) {
  return el('div', { class: 'stat' }, [
    el('div', { class: 'stat__label', text: label }),
    el('div', { class: 'stat__value', text: String(value) }),
    note ? el('div', { class: 'stat__note', text: note }) : null,
  ]);
}

/**
 * A grid of tiles.
 *
 * @param {Node[]} tiles
 * @returns {HTMLElement}
 */
export function grid(tiles) {
  return el('div', { class: 'grid' }, tiles);
}

/**
 * A titled card.
 *
 * @param {string} title
 * @param {Array<Node|string>|Node|string} content
 * @returns {HTMLElement}
 */
export function card(title, content) {
  return el('section', { class: 'card' }, [
    title ? el('h2', { class: 'card__title', text: title }) : null,
    content,
  ]);
}

/**
 * A page header.
 *
 * @param {string} title
 * @param {string} [lede]
 * @returns {DocumentFragment}
 */
export function pageHeader(title, lede) {
  const fragment = document.createDocumentFragment();
  fragment.appendChild(el('h1', { class: 'page-title', text: title }));
  if (lede) {
    fragment.appendChild(el('p', { class: 'page-lede', text: lede }));
  }
  return fragment;
}

/**
 * A labelled form field.
 *
 * @param {object} options
 * @param {string} options.id
 * @param {string} options.label
 * @param {string} [options.hint]
 * @param {HTMLElement} options.control
 * @returns {HTMLElement}
 */
export function field({ id, label, hint, control }) {
  control.id = id;
  if (hint) {
    control.setAttribute('aria-describedby', `${id}-hint`);
  }
  return el('div', { class: 'field' }, [
    el('label', { class: 'field__label', for: id }, label),
    hint ? el('p', { class: 'field__hint', id: `${id}-hint`, text: hint }) : null,
    control,
  ]);
}

/**
 * A row of buttons.
 *
 * @param {Node[]} buttons
 * @returns {HTMLElement}
 */
export function buttonRow(buttons) {
  return el('div', { class: 'button-row' }, buttons);
}

/**
 * An inline banner.
 *
 * @param {'ok'|'warn'|'error'} tone
 * @param {Array<Node|string>|Node|string} content
 * @returns {HTMLElement}
 */
export function banner(tone, content) {
  return el('div', { class: `banner banner--${tone}`, role: tone === 'error' ? 'alert' : 'status' }, content);
}

/**
 * Render a view into the main container, replacing what was there.
 *
 * @param {HTMLElement} container
 * @param {Array<Node|string>|Node|string} content
 */
export function render(container, content) {
  replace(container, []);
  append(container, content);
}
