// Structured ransomware-incident database (public API, no key required):
// https://www.ransomware.live/ — tracks dark-web leak-site posts directly,
// so attacker group and victim name come from the source, not regex guessing.
const { normalizeTimestamp, isPlausible } = require('./dateUtils');

const RANSOMWARE_LIVE_URL = 'https://api.ransomware.live/v2/recentvictims';

function titleCase(s) {
  return s.replace(/\w\S*/g, (w) => w[0].toUpperCase() + w.slice(1));
}

// ransomware.live gives a 2-letter ISO country code directly — more
// reliable than guessing from text, so map the common ones and fall back to
// the raw code (still meaningful) rather than a generic "Unspecified".
const COUNTRY_NAMES = {
  US: 'United States', GB: 'United Kingdom', DE: 'Germany', FR: 'France', ES: 'Spain',
  CN: 'China', RU: 'Russia', IR: 'Iran', KP: 'North Korea', KR: 'South Korea',
  IN: 'India', AU: 'Australia', CA: 'Canada', JP: 'Japan', BR: 'Brazil',
  UA: 'Ukraine', IL: 'Israel', NL: 'Netherlands', IT: 'Italy', SE: 'Sweden',
  PL: 'Poland', MX: 'Mexico', CH: 'Switzerland', BE: 'Belgium', SG: 'Singapore',
  NZ: 'New Zealand', ZA: 'South Africa', VN: 'Vietnam', TW: 'Taiwan',
};
function countryName(code) {
  if (!code) return 'Unspecified / Global';
  return COUNTRY_NAMES[code] || code;
}

// attackdate is sometimes bad data straight from the source — e.g. an
// attackdate months AFTER the record's own discovered date, which is
// impossible. discovered (when ransomware.live's own crawler found the leak
// post) can't be from the future, so it's the reliable fallback.
function pickTimestamp(v) {
  const attackDate = normalizeTimestamp(v.attackdate);
  if (isPlausible(attackDate)) return attackDate;
  return normalizeTimestamp(v.discovered) || attackDate;
}

async function fetchRansomwareVictims() {
  const res = await fetch(RANSOMWARE_LIVE_URL, { headers: { 'User-Agent': 'hack-tracker-app' } });
  if (!res.ok) throw new Error(`ransomware.live returned ${res.status}`);
  const victims = await res.json();

  return victims
    .filter((v) => v.victim)
    .map((v) => ({
      category: 'incident',
      isAIRelated: false,
      name: titleCase(v.group || 'unknown'),
      creator: null,
      location: countryName(v.country),
      target: v.victim,
      attackType: 'Ransomware',
      reason: 'Financial Gain',
      timestamp: pickTimestamp(v),
      // Never surface the .onion claim_url in the app — prefer the press
      // article, falling back to ransomware.live's own public HTTPS page.
      sourceUrl: (v.press && v.press.source) || v.url,
      sourceTitle: `${v.victim} — claimed by ${titleCase(v.group || 'unknown')} ransomware`,
      rawText: v.description || '',
      feedName: 'ransomware.live',
    }));
}

module.exports = { fetchRansomwareVictims, pickTimestamp };
