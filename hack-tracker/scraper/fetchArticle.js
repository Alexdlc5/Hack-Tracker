const { extract } = require('@extractus/article-extractor');

function stripTags(html) {
  return String(html || '')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&#39;|&rsquo;|&lsquo;/g, "'")
    .replace(/&quot;|&rdquo;|&ldquo;/g, '"')
    // Catch-all for remaining numeric entities (e.g. &#160;) that would
    // otherwise survive as literal text — classify.js's target-extraction
    // regex allows "." and "&" mid-word, so a leftover "&#160;" right after a
    // company name gets swallowed into it (observed as "IDScan.&" in real output).
    .replace(/&#\d+;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

// article-extractor happily "extracts" a bot-challenge page as if it were a
// real article (confirmed on DataBreaches.net, which Cloudflare-blocks
// automated fetches): title comes back as "Attention Required! | Cloudflare"
// and the challenge boilerplate is long enough to pass the length check
// below. Treat known challenge/block pages as a failed fetch instead of
// feeding classify() that boilerplate as if it were the article body.
const BOT_BLOCK_SIGNATURES = [
  'attention required! | cloudflare', 'just a moment...', 'access denied',
  'are you a robot', 'enable javascript and cookies to continue', 'checking your browser',
];
function isBotBlockPage(title, content) {
  const t = (title || '').toLowerCase();
  const c = (content || '').toLowerCase();
  return BOT_BLOCK_SIGNATURES.some((s) => t.includes(s) || c.includes(s));
}

function extractMeta(html, prop) {
  const re = new RegExp(`<meta[^>]+(?:property|name)=["']${prop}["'][^>]+content=["']([^"']*)["']`, 'i');
  const m = html.match(re);
  return m ? m[1] : null;
}

// ponytail: naive fallback — grabs every <p> tag as the article body. Good
// enough when article-extractor fails on an unusual page layout (observed on
// real pages, not hypothetical); upgrade path is a heavier readability
// library if this proves insufficient across many more sites.
function fallbackExtractRaw(html) {
  const title = extractMeta(html, 'og:title') || (html.match(/<title>([^<]*)<\/title>/i) || [])[1] || '';
  const contentHtml = Array.from(html.matchAll(/<p[^>]*>[\s\S]*?<\/p>/gi))
    .map((m) => m[0])
    .join(' ');
  const published = extractMeta(html, 'article:published_time') || extractMeta(html, 'og:updated_time');
  if (!title || stripTags(contentHtml).length < 200) return null;
  return { title: stripTags(title), contentHtml, published };
}

// Returns the article body as RAW html (contentHtml, links intact) — needed
// because in-article links live inside the article body, not page chrome
// (nav/ads/related-widgets), so link-scanning must be scoped to this, not
// the whole page.
async function fetchArticleRaw(url) {
  try {
    const article = await extract(url);
    if (article && article.content && article.content.length > 200 && !isBotBlockPage(article.title, article.content)) {
      return { title: article.title, contentHtml: article.content, published: article.published };
    }
  } catch {
    // fall through to the regex-based fallback below
  }

  try {
    const html = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' } }).then((r) => r.text());
    const fallback = fallbackExtractRaw(html);
    if (fallback && isBotBlockPage(fallback.title, fallback.contentHtml)) return null;
    return fallback;
  } catch {
    return null;
  }
}

// Plain-text version for classify() — same content, tags stripped.
async function fetchArticle(url) {
  const raw = await fetchArticleRaw(url);
  if (!raw) return null;
  return { title: raw.title, content: stripTags(raw.contentHtml), published: raw.published };
}

module.exports = { fetchArticle, fetchArticleRaw, isBotBlockPage, fallbackExtractRaw };
