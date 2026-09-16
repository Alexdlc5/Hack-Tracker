// Centralizes timestamp handling for every source (RSS pubDate, ransomware.live's
// attackdate/discovered, HIBP's AddedDate) so they end up as unambiguous UTC ISO strings.
const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, sept: 8, oct: 9, nov: 10, dec: 11 };

// Matches "Aug 25, 2026", "August 25, 2026", "Sept. 3, 2026", etc. — used as a
// fallback when a source gives no structured date and the date only appears in prose.
function extractTextDate(text) {
  const m = String(text || '').match(/\b(jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})\b/i);
  if (!m) return null;
  const month = MONTHS[m[1].toLowerCase()];
  const d = new Date(Date.UTC(Number(m[3]), month, Number(m[2])));
  return isNaN(d.getTime()) ? null : d.toISOString();
}

// A space-separated near-ISO datetime with no timezone/offset (e.g.
// ransomware.live's "2026-11-18 00:00:00.000000") is parsed by JS as LOCAL
// time instead of UTC, silently shifting the timestamp by the machine's UTC
// offset. Force it to be read as UTC instead.
function normalizeTimestamp(value) {
  if (!value) return null;
  let s = String(value).trim();
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/.test(s) && !/[+-]\d{2}:?\d{2}$/.test(s) && !s.endsWith('Z')) {
    s = `${s.replace(' ', 'T')}Z`;
  }
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d.toISOString();
}

// Source data is sometimes just wrong (a ransomware leak-site post claiming
// an attack date months after the post was even discovered). A date more
// than a day in the future is never a real incident timestamp — treat it as
// unreliable rather than let it sort to the top of the table.
const FUTURE_GRACE_MS = 24 * 60 * 60 * 1000;
function isPlausible(iso) {
  return !!iso && new Date(iso).getTime() <= Date.now() + FUTURE_GRACE_MS;
}

// Tries the structured value first, falls back to scanning free text for a
// written-out date, falls back to "now" only as a last resort.
function resolveTimestamp(structuredValue, fallbackText) {
  const normalized = normalizeTimestamp(structuredValue);
  if (normalized && isPlausible(normalized)) return normalized;
  const textDate = extractTextDate(fallbackText);
  if (textDate && isPlausible(textDate)) return textDate;
  return new Date().toISOString();
}

module.exports = { normalizeTimestamp, extractTextDate, resolveTimestamp, isPlausible };
