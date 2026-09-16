const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Parser = require('rss-parser');
const FEEDS = require('./feeds');
const { classify, looksAttackRelated } = require('./classify');
const { isDuplicate } = require('./dedupe');
const { writeDetailFile } = require('./detailFile');
const { fetchRansomwareVictims } = require('./ransomwareLive');
const { fetchRecentBreaches } = require('./hibp');
const { fetchRecentKEV } = require('./cisaKev');
const { fetchArticle, fetchArticleRaw } = require('./fetchArticle');
const { resolveTimestamp } = require('./dateUtils');
const { translateToEnglish } = require('./translate');
const store = require('../store');

const parser = new Parser({ timeout: 20000 });
const SEEN_URLS_FILE = path.join(store.DATA_DIR, 'seen-urls.json');
const SEEN_URLS_CAP = 8000;
const MAX_LINKS_PER_ARTICLE = 3;
const MAX_LINKED_FETCHES_PER_CYCLE = 25;
// MyMemory's free tier has a small shared daily quota (server-enforced) — this
// just bounds how many translation attempts one cycle makes before giving up,
// not the actual quota. Chunks are ~450 chars, so this is a handful of articles.
const MAX_TRANSLATION_CHUNKS_PER_CYCLE = 10;

function loadSeenUrls() {
  try {
    return new Set(JSON.parse(fs.readFileSync(SEEN_URLS_FILE, 'utf8')));
  } catch {
    return new Set();
  }
}
function saveSeenUrls(set) {
  const arr = Array.from(set).slice(-SEEN_URLS_CAP);
  fs.writeFileSync(SEEN_URLS_FILE, JSON.stringify(arr));
}

// Shared by every source (RSS-classified or structured-database): dedupe,
// write the detail report, persist, and notify the renderer.
function ingestCandidate(candidate, seenUrls, onEntryAdded) {
  if (!candidate.sourceUrl || seenUrls.has(candidate.sourceUrl)) return;
  seenUrls.add(candidate.sourceUrl);

  const entry = {
    id: crypto.randomUUID(),
    category: candidate.category,
    isAIRelated: !!candidate.isAIRelated,
    timestamp: resolveTimestamp(candidate.timestamp, `${candidate.sourceTitle} ${candidate.rawText}`),
    name: candidate.name,
    creator: candidate.creator,
    deployedBy: candidate.deployedBy,
    location: candidate.location || 'Unspecified / Global',
    target: candidate.target,
    attackType: candidate.attackType,
    reason: candidate.reason,
    matchedKeywords: candidate.matchedKeywords,
    sourceUrl: candidate.sourceUrl,
    sourceTitle: candidate.sourceTitle,
  };

  const liveArr = store.loadLive(candidate.category);
  if (isDuplicate(entry, liveArr)) return;

  const detailFile = writeDetailFile(entry, { rawText: candidate.rawText, feedName: candidate.feedName });
  entry.detailFile = detailFile;
  delete entry.matchedKeywords; // only needed for the detail report, not the table row

  store.addEntry(candidate.category, entry);
  if (onEntryAdded) onEntryAdded(candidate.category, entry);
}

// A roundup/analysis article often isn't an incident itself but links to one
// it references in passing (e.g. "...earlier this summer" linking the actual
// dedicated report). Only same-domain links that look like article permalinks
// are followed — nav/tag/author/asset links are filtered out.
function extractOutboundLinks(html, baseUrl, max) {
  const base = new URL(baseUrl);
  const candidates = [];
  const seen = new Set();
  const re = /<a\s+[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = re.exec(html))) {
    let abs;
    try {
      abs = new URL(m[1], base);
    } catch {
      continue;
    }
    if (abs.hostname !== base.hostname || abs.href === base.href || seen.has(abs.href)) continue;
    const p = abs.pathname.toLowerCase();
    if (/\.(jpg|jpeg|png|gif|css|js|pdf|svg|webp|ico)$/.test(p)) continue;
    if (/\/(tag|tags|author|category|categories|page|search|login|subscribe|about|contact)\//.test(p)) continue;
    if (p.split('/').filter(Boolean).length < 2) continue; // too shallow to be an article permalink
    seen.add(abs.href);
    candidates.push({ url: abs.href, anchorText: m[2].replace(/<[^>]+>/g, ' ').trim() });
  }
  // A long article can have many in-body links; the first few in document
  // order aren't necessarily the relevant ones. Prioritize links whose own
  // visible text suggests a specific incident (mentions an AI company/
  // attack-type keyword) over generic "read more"-style links.
  const relevant = candidates.filter((c) => looksAttackRelated(c.anchorText));
  return (relevant.length ? relevant : candidates).slice(0, max).map((c) => c.url);
}

// Some feeds (DataBreaches.net, SecurityWeek) give a 1-2 sentence RSS teaser
// instead of the full article — too short for classify() to find incident
// language or an attack-type keyword even when the real article clearly has
// both (confirmed against real CenterPoint Energy / Premier Medical Group
// articles). Below this length it's worth the extra fetch to check.
const SHORT_SNIPPET_THRESHOLD = 600;

// A snippet too short to classify is worth one retry against the full
// fetched article before falling back to outbound-link-following (which
// solves a different problem: a roundup that isn't itself an incident but
// references one elsewhere). Shares the same per-cycle budget.
async function retryWithFullArticle(link, title, rawText, timestamp, feedName, seenUrls, onEntryAdded, budget) {
  if (budget.remaining <= 0 || rawText.length >= SHORT_SNIPPET_THRESHOLD) return false;
  budget.remaining -= 1;

  const full = await fetchArticle(link);
  if (!full || !full.content) return false;

  let reclassified;
  try {
    reclassified = classify({ title: full.title || title, contentText: full.content, link });
  } catch (err) {
    console.error(`[scraper] classify error on full-article retry: ${err.message}`);
    return false;
  }
  if (!reclassified) return false;

  ingestCandidate(
    {
      ...reclassified,
      timestamp: full.published || timestamp,
      sourceUrl: link,
      sourceTitle: full.title || title,
      rawText: full.content,
      feedName,
    },
    seenUrls,
    onEntryAdded
  );
  return true;
}

// Follows outbound links from an article that wasn't itself classified as an
// incident but is topically close enough to be worth checking — capped by a
// shared per-cycle budget so one busy feed can't blow out the cycle time.
async function checkOutboundLinks(sourceUrl, sourceLabel, seenUrls, onEntryAdded, budget) {
  if (budget.remaining <= 0) return;
  // Scoped to the article BODY, not the whole page — the raw page also
  // contains nav/ad/related-widget links that would otherwise dominate the
  // first few <a> tags found and crowd out the real in-article references.
  const raw = await fetchArticleRaw(sourceUrl);
  if (!raw || !raw.contentHtml) return;

  for (const linkedUrl of extractOutboundLinks(raw.contentHtml, sourceUrl, MAX_LINKS_PER_ARTICLE)) {
    if (budget.remaining <= 0) break;
    if (seenUrls.has(linkedUrl)) continue;
    budget.remaining -= 1;

    const article = await fetchArticle(linkedUrl);
    if (!article) continue;

    let classified;
    try {
      classified = classify({ title: article.title, contentText: article.content, link: linkedUrl });
    } catch (err) {
      console.error(`[scraper] classify error on linked article: ${err.message}`);
      continue;
    }
    if (!classified) continue;

    ingestCandidate(
      {
        ...classified,
        timestamp: article.published,
        sourceUrl: linkedUrl,
        sourceTitle: article.title,
        rawText: article.content,
        feedName: `${sourceLabel} (linked article)`,
      },
      seenUrls,
      onEntryAdded
    );
  }
}

async function ingestRSSFeeds(seenUrls, onEntryAdded) {
  const linkBudget = { remaining: MAX_LINKED_FETCHES_PER_CYCLE };
  const translationBudget = { remaining: MAX_TRANSLATION_CHUNKS_PER_CYCLE };
  for (const feed of FEEDS) {
    let parsed;
    try {
      parsed = await parser.parseURL(feed.url);
    } catch (err) {
      console.error(`[scraper] failed to fetch ${feed.name}: ${err.message}`);
      continue;
    }

    const isTranslated = feed.lang && feed.lang !== 'en';

    for (const item of parsed.items || []) {
      const link = item.link || item.guid;
      if (!link || seenUrls.has(link)) continue;

      let rawText = item['content:encoded'] || item.content || item.contentSnippet || item.summary || '';
      let title = item.title || '(untitled)';

      // classify()'s keyword matching doesn't care about sentence structure,
      // only which English words appear where — so translated text needs no
      // special grammar handling downstream, just needs to reach classify()
      // in English at all. Verified against real French cybersecurity text:
      // MyMemory's translation preserved "confirmed a"/"data breach"/
      // "ransomware" exactly as classify() expects them.
      if (isTranslated) {
        try {
          title = await translateToEnglish(title, feed.lang, translationBudget);
          rawText = await translateToEnglish(rawText, feed.lang, translationBudget);
        } catch (err) {
          console.error(`[scraper] translation error on ${feed.name}: ${err.message}`);
          continue;
        }
      }

      let classified;
      try {
        classified = classify({ title, contentText: rawText, link });
      } catch (err) {
        console.error(`[scraper] classify error: ${err.message}`);
        continue;
      }
      if (!classified) {
        // Skip link-following/full-article-retry for translated feeds — those
        // paths would each need their own translation pass, and the free
        // tier's daily quota is too tight to spend on secondary lookups.
        let recovered = false;
        if (!isTranslated && looksAttackRelated(`${title} ${rawText}`)) {
          recovered = await retryWithFullArticle(
            link, title, rawText, item.isoDate || item.pubDate, feed.name, seenUrls, onEntryAdded, linkBudget
          );
          // Not an incident itself, but worth checking whether it links to one
          // (e.g. a roundup mentioning "...hacked Hugging Face earlier this
          // summer" with a link to the dedicated report).
          if (!recovered) await checkOutboundLinks(link, feed.name, seenUrls, onEntryAdded, linkBudget);
        }
        // Mark seen now (only after giving up on recovery) so a non-incident
        // item isn't re-fetched every cycle. Must happen AFTER retry/link
        // attempts, not before — ingestCandidate() does its own seenUrls
        // check keyed on this same URL and silently no-ops if it's already
        // marked, which was swallowing every real incident recovered this way.
        seenUrls.add(link);
        continue;
      }

      ingestCandidate(
        {
          ...classified,
          timestamp: item.isoDate || item.pubDate,
          sourceUrl: link,
          sourceTitle: title,
          rawText,
          feedName: feed.name,
        },
        seenUrls,
        onEntryAdded
      );
    }
  }
}

// Structured-database sources: already-classified, so they skip classify()
// entirely and go straight into the shared ingest pipeline.
async function ingestDatabaseSource(name, fetchFn, seenUrls, onEntryAdded) {
  let candidates;
  try {
    candidates = await fetchFn();
  } catch (err) {
    console.error(`[scraper] failed to fetch ${name}: ${err.message}`);
    return;
  }
  for (const candidate of candidates) {
    ingestCandidate(candidate, seenUrls, onEntryAdded);
  }
}

async function runCycle(onEntryAdded) {
  const seenUrls = loadSeenUrls();

  await ingestRSSFeeds(seenUrls, onEntryAdded);
  await ingestDatabaseSource('ransomware.live', fetchRansomwareVictims, seenUrls, onEntryAdded);
  await ingestDatabaseSource('Have I Been Pwned', fetchRecentBreaches, seenUrls, onEntryAdded);
  await ingestDatabaseSource('CISA KEV', fetchRecentKEV, seenUrls, onEntryAdded);

  saveSeenUrls(seenUrls);
}

module.exports = { runCycle, extractOutboundLinks, ingestCandidate };
