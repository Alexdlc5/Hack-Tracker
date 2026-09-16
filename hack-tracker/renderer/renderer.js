function fmtTime(iso) {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function cell(text) {
  const td = document.createElement('td');
  td.textContent = text || '';
  td.title = text || '';
  return td;
}

function linkCell(text, onClick) {
  const td = document.createElement('td');
  const a = document.createElement('a');
  a.className = 'link';
  a.textContent = text;
  a.href = '#';
  a.addEventListener('click', (e) => { e.preventDefault(); onClick(); });
  td.appendChild(a);
  return td;
}

// Human and AI-related entries share one table now — unified columns (Model
// Creator / Deployed By are blank for human rows, since those fields simply
// don't apply), with AI-related rows visually marked via the ai-related class.
function renderIncidentRow(entry) {
  const tr = document.createElement('tr');
  if (entry.isAIRelated) tr.className = 'ai-related';
  tr.appendChild(cell(fmtTime(entry.timestamp)));
  tr.appendChild(cell(entry.name));
  tr.appendChild(cell(entry.creator));
  tr.appendChild(cell(entry.deployedBy));
  tr.appendChild(cell(entry.location));
  tr.appendChild(cell(entry.target));
  tr.appendChild(cell(entry.attackType));
  tr.appendChild(cell(entry.reason));
  tr.appendChild(linkCell('Article', () => window.api.openExternal(entry.sourceUrl)));
  tr.appendChild(linkCell('Details', () => window.api.openPath(entry.detailFile)));
  return tr;
}

function renderWarningRow(entry) {
  const tr = document.createElement('tr');
  tr.appendChild(cell(fmtTime(entry.timestamp)));
  tr.appendChild(cell(entry.name));
  tr.appendChild(cell(entry.creator));
  tr.appendChild(cell(entry.location));
  tr.appendChild(cell(entry.target));
  tr.appendChild(cell(entry.attackType));
  tr.appendChild(cell(entry.reason));
  tr.appendChild(linkCell('Article', () => window.api.openExternal(entry.sourceUrl)));
  tr.appendChild(linkCell('Details', () => window.api.openPath(entry.detailFile)));
  return tr;
}

async function loadTables() {
  const { incident, warning } = await window.api.getTables();
  document.querySelector('#incident-table tbody').replaceChildren(...incident.map(renderIncidentRow));
  document.querySelector('#warning-table tbody').replaceChildren(...warning.map(renderWarningRow));
  updateTicker(incident, warning);
}

async function loadArchives() {
  const { incident, warning } = await window.api.listArchives();
  renderArchiveList('incident-archive-list', incident);
  renderArchiveList('warning-archive-list', warning);
}

function renderArchiveList(elId, files) {
  const ul = document.getElementById(elId);
  if (!files.length) {
    ul.replaceChildren(Object.assign(document.createElement('li'), { className: 'archive-empty', textContent: 'No archived entries yet.' }));
    return;
  }
  ul.replaceChildren(...files.map((f) => {
    const li = document.createElement('li');
    const range = f.firstTimestamp === f.lastTimestamp ? fmtTime(f.firstTimestamp) : `${fmtTime(f.firstTimestamp)} – ${fmtTime(f.lastTimestamp)}`;
    li.textContent = `${f.filename} — ${f.count} entries (${range})${f.finalized ? '' : ' [open]'}`;
    li.addEventListener('click', () => window.api.openPath(f.fullPath));
    return li;
  }));
}

// Builds one headline per recent entry across the incident and warning
// tables, sorted by recency, then duplicates the whole track once so the CSS
// animation (translateX -50%) loops seamlessly with no visible gap or jump.
function updateTicker(incident, warning) {
  const track = document.getElementById('ticker-track');
  const items = [
    ...incident.slice(0, 12).map((e) => e.isAIRelated
      ? { category: 'ai', text: `AGENT: ${e.name} (${e.creator}) deployed by ${e.deployedBy || 'unknown'} → ${e.target}` }
      : { category: 'human', text: `HUMAN: ${e.name} → ${e.target} (${e.attackType})` }),
    ...warning.slice(0, 8).map((e) => ({ category: 'warning', text: `WARNING: ${e.creator} — ${e.attackType} risk to ${e.target}` })),
  ].sort((a, b) => 0.5 - Math.random()); // interleave categories rather than long blocks

  if (!items.length) {
    track.replaceChildren(Object.assign(document.createElement('span'), { className: 'ticker-empty', textContent: 'Waiting for incidents…' }));
    return;
  }

  const makeSpan = (item) => {
    const span = document.createElement('span');
    span.className = `ticker-item ${item.category}`;
    const tag = document.createElement('span');
    tag.className = 'tag';
    tag.textContent = item.category.toUpperCase();
    span.appendChild(tag);
    span.appendChild(document.createTextNode(item.text));
    return span;
  };

  track.replaceChildren(...items.map(makeSpan), ...items.map(makeSpan));
}

function renderBarList(elId, entries) {
  const el = document.getElementById(elId);
  if (!entries || !entries.length) {
    el.replaceChildren(Object.assign(document.createElement('div'), { className: 'bar-empty', textContent: 'Not enough data yet.' }));
    return;
  }
  const max = entries[0][1];
  el.replaceChildren(...entries.map(([label, count]) => {
    const row = document.createElement('div');
    row.className = 'bar-row';
    row.innerHTML = `
      <span class="bar-label" title="${label}">${label}</span>
      <span class="bar-track"><span class="bar-fill" style="width:${Math.max(4, (count / max) * 100)}%"></span></span>
      <span class="bar-count">${count}</span>
    `;
    return row;
  }));
}

function sparklinePath(points, width, height) {
  const max = Math.max(1, ...points.map((p) => p.count));
  const step = width / Math.max(1, points.length - 1);
  return points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${(i * step).toFixed(1)} ${(height - (p.count / max) * height).toFixed(1)}`).join(' ');
}

function renderTrend(dailyTrend) {
  const el = document.getElementById('stat-trend');
  const width = 300;
  const height = 32;
  const colors = { incident: 'var(--accent)', aiRelated: 'var(--ai)', warning: 'var(--warning)' };
  const labels = { incident: 'All Incidents', aiRelated: 'AI-Related', warning: 'Warnings' };

  el.replaceChildren(...Object.keys(dailyTrend).map((category) => {
    const points = dailyTrend[category];
    const total = points.reduce((s, p) => s + p.count, 0);
    const row = document.createElement('div');
    row.className = 'trend-row';
    row.innerHTML = `
      <span class="trend-label">${labels[category]} (${total})</span>
      <svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
        <path d="${sparklinePath(points, width, height)}" fill="none" stroke="${colors[category]}" stroke-width="2" />
      </svg>
    `;
    return row;
  }));
}

async function loadSources() {
  const sources = await window.api.getSources();
  const rss = sources.filter((s) => s.type === 'rss');
  const api = sources.filter((s) => s.type === 'api');
  document.getElementById('sources-count').textContent = `${sources.length} sources`;

  const renderList = (elId, list, withLang) => {
    document.getElementById(elId).replaceChildren(...list.map((s) => {
      const li = document.createElement('li');
      const a = document.createElement('a');
      a.className = 'link';
      a.textContent = s.name + (withLang && s.lang !== 'en' ? ` (${s.lang})` : '');
      a.href = '#';
      a.addEventListener('click', (e) => { e.preventDefault(); window.api.openExternal(s.url); });
      li.appendChild(a);
      if (s.description) {
        const span = document.createElement('span');
        span.className = 'source-desc';
        span.textContent = ` — ${s.description}`;
        li.appendChild(span);
      }
      return li;
    }));
  };
  renderList('rss-sources-list', rss, true);
  renderList('api-sources-list', api, false);
}

async function loadStats() {
  const stats = await window.api.getStats();

  document.getElementById('stat-tiles').replaceChildren(
    ...['incident', 'aiRelated', 'warning'].map((c) => {
      const tile = document.createElement('div');
      tile.className = `stat-tile ${c}`;
      const label = { incident: 'Total Incidents', aiRelated: 'AI-Related Incidents', warning: 'Threat Warnings' }[c];
      tile.innerHTML = `<div class="stat-value">${stats.totals[c]}</div><div class="stat-label">${label} (all-time)</div>`;
      return tile;
    })
  );

  renderBarList('stat-attack-types', stats.topAttackTypes);
  renderBarList('stat-locations', stats.topLocations);
  renderBarList('stat-actors', stats.topThreatActors);
  renderBarList('stat-models', stats.topAIModels);
  renderBarList('stat-deployers', stats.topDeployers);
  renderBarList('stat-reasons', stats.topReasons);
  renderTrend(stats.dailyTrend);
}

function renderSearchResults(results) {
  const panel = document.getElementById('search-results');
  const list = document.getElementById('search-results-list');
  const count = document.getElementById('search-results-count');
  count.textContent = `${results.length} result${results.length === 1 ? '' : 's'}`;

  list.replaceChildren(...results.map((r) => {
    const row = document.createElement('div');
    row.className = 'search-result-row';
    const categoryLabel = r.entry.category === 'warning' ? 'Warning' : (r.entry.isAIRelated ? 'Agent' : 'Human');
    const label = r.entry.isAIRelated || r.entry.category === 'warning' ? `${r.entry.name} (${r.entry.creator})` : r.entry.name;
    row.innerHTML = `
      <span>${fmtTime(r.entry.timestamp)}</span>
      <span>${categoryLabel}</span>
      <span>${label}</span>
      <span>${r.entry.target} — ${r.entry.attackType}</span>
      <span>${r.source === 'live' ? 'Live table' : r.source}</span>
      <span></span>
    `;
    const openBtn = document.createElement('a');
    openBtn.className = 'link';
    openBtn.textContent = 'Details';
    openBtn.href = '#';
    openBtn.addEventListener('click', (e) => { e.preventDefault(); window.api.openPath(r.entry.detailFile); });
    row.lastElementChild.appendChild(openBtn);
    return row;
  }));

  panel.classList.remove('hidden');
}

function setupSearch() {
  const input = document.getElementById('search-input');
  const panel = document.getElementById('search-results');
  let debounceTimer;

  input.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    const query = input.value.trim();
    if (!query) { panel.classList.add('hidden'); return; }
    debounceTimer = setTimeout(async () => {
      const results = await window.api.search(query);
      renderSearchResults(results);
    }, 300);
  });

  document.getElementById('close-search').addEventListener('click', () => {
    panel.classList.add('hidden');
    input.value = '';
  });
}

function setupRefreshButton() {
  const btn = document.getElementById('refresh-btn');
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    btn.textContent = 'Checking feeds...';
    await window.api.refreshNow();
    await loadTables();
    await loadArchives();
    await loadStats();
    btn.disabled = false;
    btn.textContent = 'Refresh Now';
  });
}

async function setupWindowSizeControl() {
  const input = document.getElementById('window-size-input');
  input.value = await window.api.getDisplayWindowSize();
  input.addEventListener('change', async () => {
    const size = await window.api.setDisplayWindowSize(Number(input.value));
    input.value = size; // reflect clamped value if out of [20, 200]
    loadTables();
  });
}

window.api.onTableUpdate(() => {
  loadTables();
  loadArchives();
  loadStats();
});

setupRefreshButton();
setupSearch();
setupWindowSizeControl();
loadTables();
loadArchives();
loadStats();
loadSources();
