// Structured breach database (public endpoint, no key required):
// https://haveibeenpwned.com/api/v3/breaches — curated, verified breach
// records. Not date-sorted by the API, and "AddedDate" is when HIBP logged
// it (can lag the real breach), so we window on that as our recency proxy.
const { guessLocation } = require('./classify');

const HIBP_URL = 'https://haveibeenpwned.com/api/v3/breaches';
const LOOKBACK_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

function stripHtml(s) {
  return (s || '').replace(/<[^>]+>/g, '');
}

async function fetchRecentBreaches() {
  const res = await fetch(HIBP_URL, { headers: { 'User-Agent': 'hack-tracker-app' } });
  if (!res.ok) throw new Error(`HIBP returned ${res.status}`);
  const breaches = await res.json();
  const cutoff = Date.now() - LOOKBACK_MS;

  return breaches
    .filter((b) => new Date(b.AddedDate).getTime() >= cutoff)
    .map((b) => ({
      category: 'incident',
      isAIRelated: false,
      name: b.Attribution || 'Unknown / Unattributed',
      creator: null,
      location: guessLocation(`${b.Title} ${stripHtml(b.Description)}`.toLowerCase()),
      target: b.Title,
      attackType: 'Data Breach',
      reason: 'Data Theft',
      timestamp: b.AddedDate,
      sourceUrl: b.DisclosureUrl || `https://haveibeenpwned.com/PwnedWebsites#${b.Name}`,
      sourceTitle: `${b.Title} data breach (${b.PwnCount.toLocaleString()} accounts)`,
      rawText: stripHtml(b.Description),
      feedName: 'Have I Been Pwned',
    }));
}

module.exports = { fetchRecentBreaches };
