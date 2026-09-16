// Free translation (no API key): https://mymemory.translated.net/. Two hard
// limits on the anonymous tier: 500 chars per request, and a small daily
// character quota shared across all requests (roughly enough for a couple
// of short articles per day) — the server enforces the daily quota itself
// (returns quotaFinished/403), so this just fails a chunk gracefully and
// moves on rather than trying to track the quota locally.
const MYMEMORY_URL = 'https://api.mymemory.translated.net/get';
const CHUNK_SIZE = 450; // stays safely under MyMemory's 500-char hard limit

// Splits on a word boundary near CHUNK_SIZE rather than mid-word, since a
// word chopped in half often translates to nonsense.
function splitIntoChunks(text, size) {
  const chunks = [];
  let i = 0;
  while (i < text.length) {
    let end = Math.min(i + size, text.length);
    if (end < text.length) {
      const lastSpace = text.lastIndexOf(' ', end);
      if (lastSpace > i) end = lastSpace;
    }
    const chunk = text.slice(i, end).trim();
    if (chunk) chunks.push(chunk);
    i = end;
  }
  return chunks;
}

async function translateChunk(text, langpair) {
  const url = `${MYMEMORY_URL}?q=${encodeURIComponent(text)}&langpair=${langpair}`;
  const res = await fetch(url, { headers: { 'User-Agent': 'hack-tracker-app' } });
  if (!res.ok) return null;
  const data = await res.json();
  if (data.responseStatus !== 200 || !data.responseData) return null;
  return data.responseData.translatedText;
}

// Translates as much of `text` as the shared per-cycle budget allows, in
// order, and joins what it got. Machine-translated output can read a little
// stiff, but classify.js matches on keywords/substrings, not sentence
// structure, so it doesn't need special grammar handling downstream — the
// translated text just needs to contain the right English words in roughly
// the right order, which MyMemory's output reliably does (verified against
// real French cybersecurity text: "confirmed a" + "data breach" + "ransomware"
// all came through correctly).
async function translateToEnglish(text, sourceLang, budget) {
  if (!text || sourceLang === 'en') return text;
  const chunks = splitIntoChunks(text, CHUNK_SIZE);
  const translated = [];
  for (const chunk of chunks) {
    if (budget.remaining <= 0) break;
    budget.remaining -= 1;
    try {
      const t = await translateChunk(chunk, `${sourceLang}|en`);
      if (t) translated.push(t);
    } catch {
      // one chunk failing (quota, network) shouldn't lose the rest already translated
    }
  }
  return translated.join(' ');
}

module.exports = { translateToEnglish, splitIntoChunks };
