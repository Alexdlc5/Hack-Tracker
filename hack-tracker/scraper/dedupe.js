// ponytail: naive token-overlap heuristic checked only against the most
// recent live entries (not the full archive). Upgrade path if it starts
// missing/over-merging real duplicates: embedding-based similarity.

function normalize(s) {
  return (s || '').toLowerCase().replace(/[^a-z0-9\s]/g, ' ').replace(/\s+/g, ' ').trim();
}

function jaccard(setA, setB) {
  if (!setA.size && !setB.size) return 0;
  let intersection = 0;
  for (const x of setA) if (setB.has(x)) intersection++;
  const union = setA.size + setB.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

function isDuplicate(candidate, existingList) {
  const window = existingList.slice(0, 300);
  const candSet = new Set(normalize(`${candidate.name} ${candidate.target} ${candidate.attackType}`).split(' '));
  const candTime = new Date(candidate.timestamp).getTime();

  for (const existing of window) {
    if (existing.sourceUrl === candidate.sourceUrl) return true;
    const existingSet = new Set(normalize(`${existing.name} ${existing.target} ${existing.attackType}`).split(' '));
    const sim = jaccard(candSet, existingSet);
    const daysApart = Math.abs(candTime - new Date(existing.timestamp).getTime()) / 86400000;
    if (sim >= 0.6 && daysApart <= 3) return true;
  }
  return false;
}

module.exports = { isDuplicate };
