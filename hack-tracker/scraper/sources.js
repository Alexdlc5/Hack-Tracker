// Every feed's name/url already lives in feeds.js; the structured "database"
// sources (non-RSS JSON APIs) don't have a shared list elsewhere, so it's
// declared here alongside them for a single combined list the UI can render.
const FEEDS = require('./feeds');

const API_SOURCES = [
  { name: 'ransomware.live', url: 'https://api.ransomware.live/v2/recentvictims', description: 'Dark-web ransomware leak-site postings' },
  { name: 'Have I Been Pwned', url: 'https://haveibeenpwned.com/api/v3/breaches', description: 'Curated, verified data breach disclosures' },
  { name: 'CISA KEV', url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', description: 'Confirmed actively-exploited vulnerabilities' },
];

function listSources() {
  return [
    ...FEEDS.map((f) => ({ name: f.name, url: f.url, type: 'rss', lang: f.lang || 'en' })),
    ...API_SOURCES.map((s) => ({ ...s, type: 'api' })),
  ];
}

module.exports = { listSources };
