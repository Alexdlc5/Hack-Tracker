const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.HACK_TRACKER_DATA_DIR || path.join(__dirname, 'data');
const ARCHIVE_FILE_CAP = 10000;
const MIN_DISPLAY_WINDOW = 20;
const MAX_DISPLAY_WINDOW = 200;
const DEFAULT_DISPLAY_WINDOW = 50;
// 'incident' holds both human-executed and AI-related entries together (one
// table, distinguished by the isAIRelated field on each entry) — 'warning'
// stays separate since it's a fundamentally different kind of row (nothing
// has happened yet).
const CATEGORIES = ['incident', 'warning'];

function categoryDir(category) {
  return path.join(DATA_DIR, category); // 'incident' | 'warning'
}
function archiveDir(category) {
  return path.join(categoryDir(category), 'archive');
}
function detailsDir(category) {
  return path.join(categoryDir(category), 'details');
}
function liveFile(category) {
  return path.join(categoryDir(category), 'live.json');
}
function archiveIndexFile(category) {
  return path.join(archiveDir(category), 'index.json');
}
function configFile() {
  return path.join(DATA_DIR, 'config.json');
}

function ensureDirs() {
  for (const category of CATEGORIES) {
    fs.mkdirSync(archiveDir(category), { recursive: true });
    fs.mkdirSync(detailsDir(category), { recursive: true });
  }
}

function readJSON(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function loadLive(category) {
  return readJSON(liveFile(category), []);
}
function saveLive(category, arr) {
  writeJSON(liveFile(category), arr);
}

function sanitizeForFilename(iso) {
  return iso.replace(/[:.]/g, '-');
}

function loadArchiveIndex(category) {
  return readJSON(archiveIndexFile(category), []);
}
function saveArchiveIndex(category, idx) {
  writeJSON(archiveIndexFile(category), idx);
}

function appendToArchive(category, entry) {
  const idx = loadArchiveIndex(category);
  let current = idx[idx.length - 1];

  if (!current || current.finalized) {
    current = {
      filename: `archive_${sanitizeForFilename(entry.timestamp)}.jsonl`,
      firstTimestamp: entry.timestamp,
      lastTimestamp: entry.timestamp,
      count: 0,
      finalized: false,
    };
    idx.push(current);
  }

  fs.appendFileSync(path.join(archiveDir(category), current.filename), `${JSON.stringify(entry)}\n`);
  current.count += 1;
  current.lastTimestamp = entry.timestamp;

  if (current.count >= ARCHIVE_FILE_CAP) {
    const newName = `archive_${sanitizeForFilename(current.firstTimestamp)}_to_${sanitizeForFilename(current.lastTimestamp)}.jsonl`;
    fs.renameSync(path.join(archiveDir(category), current.filename), path.join(archiveDir(category), newName));
    current.filename = newName;
    current.finalized = true;
  }

  saveArchiveIndex(category, idx);
}

function clampDisplayWindow(size) {
  return Math.min(MAX_DISPLAY_WINDOW, Math.max(MIN_DISPLAY_WINDOW, Math.round(size) || DEFAULT_DISPLAY_WINDOW));
}
function getDisplayWindowSize() {
  return clampDisplayWindow(readJSON(configFile(), {}).displayWindowSize || DEFAULT_DISPLAY_WINDOW);
}
function setDisplayWindowSize(size) {
  const clamped = clampDisplayWindow(size);
  writeJSON(configFile(), { displayWindowSize: clamped });
  return clamped;
}

// Every entry is archived immediately (a complete historical record), then
// kept in the live cache — sorted by real timestamp, not insertion order,
// since sources are ingested in a different order than their actual dates —
// up to MAX_DISPLAY_WINDOW so raising the display window never needs a
// re-fetch from archive.
function addEntry(category, entry) {
  appendToArchive(category, entry);

  const arr = loadLive(category);
  arr.push(entry);
  arr.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  if (arr.length > MAX_DISPLAY_WINDOW) arr.length = MAX_DISPLAY_WINDOW;
  saveLive(category, arr);
}

// What the UI should actually display: the live cache, trimmed to the
// user's current display-window setting (20-200).
function loadLiveWindowed(category) {
  return loadLive(category).slice(0, getDisplayWindowSize());
}

function listArchiveFiles(category) {
  const idx = loadArchiveIndex(category);
  return idx
    .map((rec) => ({ ...rec, fullPath: path.join(archiveDir(category), rec.filename) }))
    .reverse(); // newest file first
}

function readArchiveFileEntries(fullPath) {
  try {
    return fs
      .readFileSync(fullPath, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch {
    return [];
  }
}

// ponytail: linear scan over live + every archive file. Fine at MVP scale;
// upgrade path if archives pile up for months is a real search index (e.g. SQLite FTS).
function searchAll(query, limit = 500) {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  const results = [];

  const matches = (entry) =>
    [entry.name, entry.creator, entry.deployedBy, entry.location, entry.target, entry.attackType, entry.reason, entry.sourceTitle, entry.sourceUrl]
      .filter(Boolean)
      .some((field) => String(field).toLowerCase().includes(q));

  for (const category of CATEGORIES) {
    for (const entry of loadLive(category)) {
      if (matches(entry)) results.push({ category, source: 'live', entry });
      if (results.length >= limit) return results;
    }
    for (const file of listArchiveFiles(category)) {
      for (const entry of readArchiveFileEntries(file.fullPath)) {
        if (matches(entry)) results.push({ category, source: file.filename, entry });
        if (results.length >= limit) return results;
      }
    }
  }
  return results;
}

// Every entry is archived immediately on arrival (see addEntry), so the live
// cache is always a strict subset of the archive — reading both and
// concatenating would double-count every entry currently in the live window.
function loadAllEntries(category) {
  return listArchiveFiles(category).flatMap((f) => readArchiveFileEntries(f.fullPath));
}

function tally(entries, field, { excludeUnknown = true } = {}) {
  const counts = new Map();
  for (const e of entries) {
    const v = e[field];
    if (!v) continue;
    if (excludeUnknown && /unknown|unspecified|general threat/i.test(v)) continue;
    counts.set(v, (counts.get(v) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]);
}

function dailyCounts(entries, days) {
  const buckets = [];
  const now = new Date();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(now);
    d.setUTCDate(d.getUTCDate() - i);
    buckets.push({ date: d.toISOString().slice(0, 10), count: 0 });
  }
  const byDate = new Map(buckets.map((b) => [b.date, b]));
  for (const e of entries) {
    const t = new Date(e.timestamp);
    if (isNaN(t.getTime())) continue;
    const bucket = byDate.get(t.toISOString().slice(0, 10));
    if (bucket) bucket.count += 1;
  }
  return buckets;
}

// Scans live + every archive file (same tradeoff as searchAll — fine at MVP
// scale, a real index is the upgrade path if archives grow into the
// hundreds of thousands of entries) to surface trends across all data, not
// just the current display window.
function computeStats() {
  const byCategory = Object.fromEntries(CATEGORIES.map((c) => [c, loadAllEntries(c)]));
  const all = CATEGORIES.flatMap((c) => byCategory[c]);
  const aiIncidents = byCategory.incident.filter((e) => e.isAIRelated);
  const humanIncidents = byCategory.incident.filter((e) => !e.isAIRelated);

  return {
    totals: {
      incident: byCategory.incident.length,
      aiRelated: aiIncidents.length,
      warning: byCategory.warning.length,
    },
    topAttackTypes: tally(all, 'attackType', { excludeUnknown: false }).slice(0, 8),
    topReasons: tally(all, 'reason').slice(0, 8),
    topLocations: tally(all, 'location', { excludeUnknown: false }).slice(0, 10),
    topThreatActors: tally(humanIncidents, 'name').slice(0, 8),
    topAIModels: tally(aiIncidents, 'name').slice(0, 8),
    topDeployers: tally(aiIncidents, 'deployedBy').slice(0, 8),
    dailyTrend: {
      incident: dailyCounts(byCategory.incident, 14),
      aiRelated: dailyCounts(aiIncidents, 14),
      warning: dailyCounts(byCategory.warning, 14),
    },
  };
}

module.exports = {
  DATA_DIR,
  CATEGORIES,
  computeStats,
  MIN_DISPLAY_WINDOW,
  MAX_DISPLAY_WINDOW,
  ensureDirs,
  loadLive,
  loadLiveWindowed,
  saveLive,
  addEntry,
  listArchiveFiles,
  searchAll,
  detailsDir,
  getDisplayWindowSize,
  setDisplayWindowSize,
};
