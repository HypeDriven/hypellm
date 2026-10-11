'use strict';

(() => {
  const input = document.getElementById('wiki-query');
  const panel = document.getElementById('search-results');
  const status = document.getElementById('search-status');
  const list = document.getElementById('search-list');
  const article = document.querySelector('.document');
  const toc = document.querySelector('.page-toc');
  const index = window.HYPELLM_WIKI_INDEX;
  if (!input || !Array.isArray(index)) return;
  document.querySelector('.search-control').hidden = false;

  const root = document.body.dataset.wikiRoot;
  let timer;

  function search() {
    const query = input.value.trim().toLowerCase();
    panel.hidden = !query;
    article.hidden = Boolean(query);
    toc.hidden = Boolean(query);
    list.replaceChildren();
    if (!query) return;

    const terms = query.split(/\s+/).slice(0, 12);
    const matches = [];
    for (const entry of index) {
      const title = `${entry.page} ${entry.heading}`.toLowerCase();
      const text = `${title} ${entry.text}`.toLowerCase();
      if (!terms.every(term => text.includes(term))) continue;
      const score = terms.reduce((sum, term) => sum + (title.includes(term) ? 4 : 1), 0);
      matches.push({ entry, score });
    }
    matches.sort((a, b) => b.score - a.score);
    const shown = matches.slice(0, 30);
    status.textContent = matches.length
      ? `${matches.length} matching sections${matches.length > shown.length ? ` · showing the first ${shown.length}` : ''}`
      : 'No matching sections. Try a provider, component, command or policy term.';

    for (const { entry } of shown) {
      const row = document.createElement('li');
      row.className = 'search-result';
      const link = document.createElement('a');
      link.href = `${root}${entry.url}`;
      link.textContent = entry.heading;
      const path = document.createElement('p');
      path.className = 'result-path';
      path.textContent = `${entry.group} / ${entry.page}`;
      const snippet = document.createElement('p');
      const text = entry.text.replace(/\s+/g, ' ');
      const position = text.toLowerCase().indexOf(terms[0]);
      const start = Math.max(0, position - 65);
      snippet.textContent = `${start ? '…' : ''}${text.slice(start, start + 240)}${text.length > start + 240 ? '…' : ''}`;
      row.append(link, path, snippet);
      list.append(row);
    }
  }

  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(search, 120);
  });
  input.addEventListener('keydown', event => {
    if (event.key === 'Enter') {
      clearTimeout(timer);
      search();
      document.getElementById('content').scrollIntoView();
    }
  });
  document.addEventListener('keydown', event => {
    const editing = event.target.matches('input, textarea, select, [contenteditable="true"]');
    if (event.key === '/' && !editing && !event.ctrlKey && !event.metaKey && !event.altKey) {
      event.preventDefault();
      input.focus();
    }
    if (event.key === 'Escape' && (input.value || document.activeElement === input)) {
      clearTimeout(timer);
      input.value = '';
      search();
      input.blur();
    }
  });

  // On phones, keep the article close to the search field while retaining all
  // links through native details controls, including when JavaScript is off.
  if (window.matchMedia('(max-width: 720px)').matches) {
    for (const group of document.querySelectorAll('.nav-group')) group.open = false;
    const contents = document.querySelector('.page-toc details');
    if (contents) contents.open = false;
  }
})();
