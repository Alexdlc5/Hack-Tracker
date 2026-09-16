// Lightweight smoke test for the non-network logic: classification rules,
// dedupe heuristic, and the live-table/archive rotation. Run with `node test.js`.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { classify, looksAttackRelated } = require('./scraper/classify');
const { isDuplicate } = require('./scraper/dedupe');
const { normalizeTimestamp, extractTextDate } = require('./scraper/dateUtils');
const { isBotBlockPage } = require('./scraper/fetchArticle');
const { splitIntoChunks } = require('./scraper/translate');

// --- fetchArticle.isBotBlockPage() ---
// Regression: @extractus/article-extractor happily "extracts" a Cloudflare
// bot-challenge page as if it were a real article (confirmed on
// DataBreaches.net, which blocks automated fetches) — title comes back as
// "Attention Required! | Cloudflare" and the boilerplate is long enough to
// pass the normal length check. Must be detected and treated as a failed fetch.
assert.strictEqual(isBotBlockPage('Attention Required! | Cloudflare', 'some boilerplate'), true, 'Cloudflare challenge page title should be detected');
assert.strictEqual(isBotBlockPage('Some Real Headline', 'A ransomware gang breached a US hospital and stole data.'), false, 'a real article must not be flagged as a bot-block page');

// --- dateUtils ---
assert.strictEqual(normalizeTimestamp('2026-11-18 00:00:00.000000'), '2026-11-18T00:00:00.000Z', 'space-separated datetime with no offset should be read as UTC, not local time');
assert.strictEqual(normalizeTimestamp('2026-09-16T04:00:41.272162+00:00'), '2026-09-16T04:00:41.272Z', 'explicit-offset ISO datetime should parse straightforwardly');
assert.strictEqual(extractTextDate('the breach was disclosed on Aug 25, 2026 by the company'), '2026-08-25T00:00:00.000Z', 'abbreviated month + day + year should extract');
assert.strictEqual(extractTextDate('reported August 3, 2026 after investigation'), '2026-08-03T00:00:00.000Z', 'full month name + day + year should extract');
assert.strictEqual(extractTextDate('no date here'), null, 'text with no date should return null');

const { pickTimestamp } = require('./scraper/ransomwareLive');
// Regression: this exact shape (attackdate months after discovered) came
// from real ransomware.live data and put a future-dated entry at the top
// of the table. discovered should win when attackdate is implausible.
assert.strictEqual(
  pickTimestamp({ attackdate: '2026-11-18 00:00:00.000000', discovered: '2026-01-15T13:48:29.435004+00:00' }),
  '2026-01-15T13:48:29.435Z',
  'implausible future attackdate should fall back to discovered'
);
assert.strictEqual(
  pickTimestamp({ attackdate: '2026-09-14T12:00:08.849000+00:00', discovered: '2026-09-14T12:01:00+00:00' }),
  '2026-09-14T12:00:08.849Z',
  'plausible attackdate should be used as-is'
);

// --- classify() ---
// The app was USA-only originally; it now covers incidents globally and
// carries a `location` field instead of filtering by country.
const globalHumanResult = classify({ title: 'Hackers hit a company in France', contentText: 'A ransomware gang breached the network.', link: 'a' });
assert.ok(globalHumanResult && globalHumanResult.category === 'incident' && !globalHumanResult.isAIRelated, 'a non-US human incident must classify (global coverage, not USA-only)');
assert.strictEqual(globalHumanResult.location, 'France', 'location should be identified from the article text');

assert.strictEqual(
  classify({ title: 'New ransomware strain explained', contentText: 'Ransomware could allow an attacker to encrypt files in the United States.', link: 'b' }),
  null,
  'advisory/explainer without incident language should be skipped'
);

assert.strictEqual(
  classify({ title: 'No attack type here', contentText: 'A company in the United States announced a new product.', link: 'c' }),
  null,
  'article with no attack-type keyword should be skipped'
);

const humanResult = classify({
  title: 'LockBit breached a US hospital',
  contentText: 'The ransomware group LockBit said it breached a hospital in the United States and stole data.',
  link: 'd',
});
assert.ok(humanResult && humanResult.category === 'incident' && !humanResult.isAIRelated, 'should classify as human incident, not AI-related');
assert.strictEqual(humanResult.name, 'LockBit', 'should identify known threat actor');
assert.strictEqual(humanResult.attackType, 'Ransomware');

const aiResult = classify({
  title: 'AI agent used in attack',
  contentText: 'An autonomous AI agent powered by Claude was used to run a phishing campaign against a company in the United States, and it was confirmed a breach occurred.',
  link: 'e',
});
assert.ok(aiResult && aiResult.category === 'incident' && aiResult.isAIRelated, 'should classify as an AI-related incident, marked isAIRelated');
assert.strictEqual(aiResult.creator, 'Anthropic');

const supplyChainResult = classify({
  title: 'Malicious model found on Hugging Face',
  contentText: 'Researchers confirmed a backdoored model uploaded to Hugging Face was compromised and used to run arbitrary code on machines in the United States that loaded it.',
  link: 'f',
});
assert.ok(supplyChainResult && supplyChainResult.category === 'incident' && supplyChainResult.isAIRelated, 'malicious model on an ML hub should classify as AI-related');

const aiPlatformResult = classify({
  title: 'Hugging Face discloses data breach',
  contentText: 'Hugging Face disclosed a data breach after attackers compromised employee credentials, exposing secrets belonging to users in the United States.',
  link: 'g',
});
assert.ok(aiPlatformResult && aiPlatformResult.category === 'incident' && aiPlatformResult.isAIRelated, 'a breach of an AI platform should classify as AI-related');
assert.strictEqual(aiPlatformResult.creator, 'Hugging Face');

// Regression: an article mentioning "ransomware" in one paragraph (generic
// industry context) and "hacked"/AI-agent language in an unrelated paragraph
// elsewhere must NOT be stitched into a fake incident.
const scatteredKeywordsResult = classify({
  title: 'OpenAI commits $1B in AI credits to frontline cyber defenders',
  contentText: 'OpenAI pledged $1 billion in credits for cyber defenders in the United States. This makes water systems attractive targets for ransomware operators looking to force extortion payments. Many experts say attackers increasingly use autonomous agents to carry out intrusions. The initiative comes as OpenAI faces scrutiny after admitting two models went rogue and hacked Hugging Face earlier this summer.',
  link: 'h',
});
assert.strictEqual(scatteredKeywordsResult, null, 'scattered unrelated keywords across an article must not produce a fake incident');

// Regression: real nation-state espionage report (Chinese spies used Claude
// to break into ~30 orgs) — lede states the incident plainly, but the
// specific attack-type categorization only appears later in the analysis.
// Also verifies position-based keyword matching: the article ALSO mentions
// an unrelated earlier ransom-extortion incident later on for comparison,
// which must not override the actual (earlier-appearing) categorization.
const nationStateResult = classify({
  title: 'Chinese spies used Claude to break into critical orgs',
  contentText: 'Chinese spies told Claude to break into about 30 critical orgs. Some attacks succeeded, marking the first documented case of agentic AI obtaining access to targets in the United States. The incident also suggests heavily funded state-sponsored groups are getting better at autonomizing attacks. This is different from an earlier data extortion campaign that saw attackers demand ransoms for stolen data.',
  link: 'i',
});
assert.ok(nationStateResult && nationStateResult.category === 'incident' && nationStateResult.isAIRelated, 'nation-state AI-agent campaign should classify as AI-related');
assert.strictEqual(nationStateResult.creator, 'Anthropic');
assert.strictEqual(nationStateResult.attackType, 'Nation-State / Espionage', 'earlier-appearing categorization should win over a later tangential mention');
assert.strictEqual(nationStateResult.target, 'See source article', 'nationality demonym and the AI tool name must not be captured as the target');

// Regression: a court-outcome recap (sentencing/extradition/plea/conviction)
// must NOT be classified as a live incident, even though it uses incident-like
// past tense to describe what the group did historically and quotes officials
// "in a statement". Found via a real CyberScoop article about a Conti
// ransomware developer's sentencing.
const sentencingResult = classify({
  title: 'Conti ransomware crew member sentenced to four years in prison',
  contentText: 'A 44-year-old Ukrainian national was sentenced to four years in prison for his long-running participation in Conti, a ransomware group that attacked more than 1,000 organizations globally before it disbanded in 2022, the Justice Department said Thursday.',
  link: 'j',
});
assert.strictEqual(sentencingResult, null, 'a sentencing/court-outcome recap must not be classified as a new incident');

// Regression: same legal-outcome veto, but also verifies that classify()
// strips HTML tags before matching — a real DataBreaches.net/CyberScoop
// article had "were <a href=...>extradited to the United States</a>", which
// (before stripping) breaks the literal "were extradited" substring match
// and also breaks the "in a statement" phrase later on.
const extraditionResult = classify({
  title: 'Five alleged leaders of Black Axe extradited to US',
  contentText: 'Five alleged leaders of the South African wing of Black Axe, a global cybercrime group, were <a href="https://justice.gov/pr">extradited to the United States</a> Friday to face multiple charges, the Justice Department said. Officials accuse the five of running phishing and advance fee scams in the United States since 2011.',
  link: 'k',
});
assert.strictEqual(extraditionResult, null, 'legal-outcome veto must apply after HTML tags are stripped, not before');

// Regression: HTML tags embedded mid-keyword (as real RSS content:encoded
// fields do) must not prevent an otherwise-valid incident from matching.
const htmlSplitIncidentResult = classify({
  title: 'Acme Corp breach',
  contentText: 'Acme Corp <a href="https://example.com/x">confirmed a</a> ransomware attack on its network in the United States, and said hackers stole customer data.',
  link: 'l',
});
assert.ok(htmlSplitIncidentResult, 'a real incident split across an inline HTML tag should still classify (tags must be stripped first)');

// Regression: breach-notification-letter phrasing ("X is notifying N
// patients...", "hackers accessed files") is as common as the
// already-covered "notified customers" past-tense phrasing, and a
// present-tense ransomware-claim headline ("group claims attack on X") is as
// common as the already-covered "claimed responsibility". Found via real
// Premier Medical Group (SecurityWeek) and Cedar County Hospital
// (DataBreaches.net) articles that were false negatives without these.
const notifyingResult = classify({
  title: '280,000 Impacted by Premier Medical Group Data Breach',
  contentText: 'New York healthcare provider Premier Medical Group is notifying over 280,000 patients that their personal and medical information was stolen in a data breach. Hackers accessed files containing patients’ names and health insurance information.',
  link: 'm',
});
assert.ok(notifyingResult, '"is notifying" / "hackers accessed" breach-notice phrasing should be recognized as incident language');
assert.strictEqual(notifyingResult.target, 'Premier Medical Group', '"Impacted" (headline count lead-in, like "Over 500 Organizations Hit by...") must not be captured as the target');
assert.strictEqual(notifyingResult.reason, 'Data Theft', '"was stolen" should be recognized as a Data Theft motive keyword');

const ransomwareClaimResult = classify({
  title: "Ransomware group claims attack on Missouri's Cedar County Memorial Hospital",
  contentText: 'The hospital shut down its IT networks after a disruption left its electronic health record and patient portal unavailable.',
  link: 'n',
});
assert.ok(ransomwareClaimResult, 'present-tense "claims attack" ransomware-claim headline should be recognized as incident language');

// Regression: a product-announcement article whose lede cites an unrelated
// PAST incident as "why now" backstory must not be classified as if the
// CURRENT subject were attacked. Found via a real Ars Technica article:
// "Microsoft unveils AI security tools" whose 3rd lede sentence ("The new
// tools come less than a week after OpenAI ... infiltrated ... Hugging
// Face") independently satisfies the lede-gate for a totally different company.
const announcementBackstoryResult = classify({
  title: 'Acme unveils new security tools it says outperform rivals',
  contentText: 'Acme is introducing new tools to help customers reduce their exposure to security risks. The new tools come less than a week after OpenAI infiltrated the servers of startup Hugging Face in the United States and stole credentials.',
  link: 'o',
});
assert.strictEqual(announcementBackstoryResult, null, 'a "comes N days/weeks after" backstory sentence about a DIFFERENT company must not count as this article\'s own incident');

// Regression: the backstory veto above must be narrow enough that a genuine
// incident report about its OWN subject — which can legitimately say "the
// breach was confirmed a week after a report said it happened" — still
// classifies. Found via a real TechCrunch/IDScan article with this exact shape.
const selfReferentialAfterResult = classify({
  title: 'Acme confirms data breach',
  contentText: 'Acme Corp has confirmed that a data breach involved the theft of records from its systems in the United States, a week after a report said the company had been breached during a year-long hack.',
  link: 'p',
});
assert.ok(selfReferentialAfterResult, 'an incident report describing its OWN subject must still classify even though it contains a "week after" clause');

// Regression: headline title-case capitalizes verbs too ("Cisco Warns of
// Ongoing Exploitation"), and the previous target-extraction regex swallowed
// them into the target ("Cisco Warns of Ongoing"). Found via a real
// CyberScoop/SecurityAffairs Cisco zero-day article.
const headlineVerbResult = classify({
  title: 'Acme Corp Warns of Ongoing Exploitation in the United States',
  contentText: 'Acme Corp said attackers compromised customer systems by exploiting a zero-day vulnerability, and multiple customers were compromised prior to disclosure.',
  link: 'q',
});
assert.ok(headlineVerbResult);
assert.strictEqual(headlineVerbResult.target, 'Acme Corp', 'a reporting verb ("Warns") in a title-case headline must not be swallowed into the target');

// Regression: a leftover numeric HTML entity (e.g. "&#160;") right after a
// company name, combined with the target regex's "." mid-word allowance,
// let the NEXT sentence's capitalized first word (a byline) get swallowed
// into the target. Found via a real TechCrunch/IDScan article
// ("breach at IDScan.&#160; Krebs reported...") producing target "IDScan.&"
// and then "IDScan. Krebs" across two separate fixes.
const entityBoundaryResult = classify({
  title: 'Acme breach disclosed',
  contentText: 'Researchers confirmed a data breach at Acme.&#160; Reporter said the company was compromised in the United States.',
  link: 'r',
});
assert.ok(entityBoundaryResult);
assert.strictEqual(entityBoundaryResult.target, 'Acme', 'a stripped numeric entity must not let a sentence boundary be crossed into the next sentence\'s capitalized word');

// Regression: "compromised VPN" / "targeted API" read exactly like "attack
// on Acme Corp" to the target regex, so a generic tech acronym was returned
// as the target instead of continuing on to the article's real named victim
// mentioned later. Found via a real Hacker News article ("Iran-Linked
// Hackers ... Hit Stryker With Wiper Attack") where this produced "VPN".
const acronymTargetResult = classify({
  title: 'Hackers deploy malware against a company in the United States',
  contentText: 'Threat actors compromised VPN credentials and used them to deploy malware. They later carried out an attack on Stryker, destroying data across its network.',
  link: 's',
});
assert.ok(acronymTargetResult);
assert.strictEqual(acronymTargetResult.target, 'Stryker', 'a generic tech acronym ("VPN") must not be captured as the target ahead of the real named victim');

// Regression: real headlines use a curly/typographic apostrophe (’) in
// possessives ("Missouri’s Cedar County Memorial Hospital"), not the
// straight ASCII one the target regex's character class allowed — this
// truncated the match right before it, producing target "Missouri" (a
// state name, not the actual victim) instead of anything past the apostrophe.
const curlyApostropheResult = classify({
  title: "Ransomware group claims attack on Missouri’s Cedar County Memorial Hospital",
  contentText: 'The hospital shut down its IT networks after a disruption left its systems unavailable.',
  link: 't',
});
assert.ok(curlyApostropheResult);
assert.ok(curlyApostropheResult.target.startsWith('Missouri’s'), 'a curly apostrophe must not truncate the target match right after the state name');

// Regression: "in a statement" is present in virtually any article quoting
// any spokesperson, regardless of subject — it was removed from
// INCIDENT_INDICATORS after it let a Krebs on Security piece about the
// ARREST of hackers (rich investigative detail about a months-old campaign,
// but not a freshly-dated incident) pass the lede-gate on that phrase alone.
const bareStatementResult = classify({
  title: 'Two men arrested in Australia over cybercrime group',
  contentText: 'Authorities said in a statement that the men were members of a prolific cybercrime and extortion group blamed for a supply chain attack spree in the United States.',
  link: 'u',
});
assert.strictEqual(bareStatementResult, null, 'a bare "in a statement" quote must not by itself satisfy the incident-language check');

// Regression: genuine AI-agent incidents are globally rare, so they must
// classify regardless of country. Found via a real Spain data protection
// agency (AEPD) disclosure — an autonomous AI agent using an undisclosed
// LLM breached an organization, with no US connection at all.
const nonUSAIResult = classify({
  title: 'Spain gets its first taste of AI-aided cyber attack',
  contentText: "Spain's data protection agency has reported the country's first-ever personal data breach caused by the actions of an autonomous AI agent. An individual deployed an AI agent that used a known large language model to carry out the attack on an organization. The agency did not name the LLM used to support the attack.",
  link: 'v',
});
assert.ok(nonUSAIResult && nonUSAIResult.category === 'incident' && nonUSAIResult.isAIRelated, 'a non-US AI-agent incident must classify, marked isAIRelated');
assert.strictEqual(nonUSAIResult.name, 'Unspecified AI Agent', 'an AI-executed incident with no named model should say so honestly, not guess');
assert.strictEqual(nonUSAIResult.creator, 'Unknown / Unattributed', 'creator must not fall back to an unrelated AI company name mentioned elsewhere');
assert.strictEqual(nonUSAIResult.deployedBy, 'An Individual', 'deployedBy should identify who used the agent, distinct from who created the model');
assert.strictEqual(nonUSAIResult.location, 'Spain', 'location should be identified from the article text');

// Regression: a human incident with no US connection must classify too
// (global coverage, no country filter) and carry the correct location.
const globalHumanResult2 = classify({
  title: 'Hackers breached a company in Germany',
  contentText: 'A ransomware gang confirmed a breach of the network and stole customer data.',
  link: 'w',
});
assert.ok(globalHumanResult2 && globalHumanResult2.category === 'incident' && !globalHumanResult2.isAIRelated, 'a non-US human incident must classify (global coverage), not AI-related');
assert.strictEqual(globalHumanResult2.location, 'Germany', 'location should be identified from the article text');

// Regression: the AI-agent "deployedBy" field distinguishes who USED the
// model from who CREATED it — found via the real Chinese-spies-Claude case,
// where Claude was made by Anthropic but deployed by a state-sponsored group
// Anthropic internally designated GTG-1002.
const deployerResult = classify({
  title: 'Chinese spies used Claude to break into critical orgs',
  contentText: 'Chinese spies told Claude to break into about 30 critical orgs. Some attacks succeeded, marking the first documented case of agentic AI obtaining access to targets. The state-sponsored campaign was tracked by Anthropic, which designated the group behind it as GTG-1002.',
  link: 'ai-deployer',
});
assert.ok(deployerResult && deployerResult.category === 'incident' && deployerResult.isAIRelated);
assert.strictEqual(deployerResult.creator, 'Anthropic', 'creator should be who made the model');
assert.strictEqual(deployerResult.deployedBy, 'GTG-1002', 'deployedBy should be the specific named group that used it, not the model creator');

// Regression: an article whose title itself signals a threat WARNING
// ("X warns") often cites one real case as supporting evidence, and that
// example can carry genuine incident language within the lede window —
// without title-based priority this misroutes as a live 'ai' incident
// instead of a 'warning'. Found via a real Google/Mandiant threat report
// ("Extortion crews have their eyes on high-value AI data, Google warns")
// whose lede cites a specific case Mandiant investigated.
const warningResult = classify({
  title: 'Extortion crews have their eyes on high-value AI data, Google warns',
  contentText: "Data theft and extortion crews are stealing companies' proprietary AI data and threatening to leak it in a supply chain attack, Google said. In one case that Google's Mandiant incident response team investigated, the crooks broke into a healthcare company and exfiltrated corporate data and drug research in the United States.",
  link: 'x',
});
assert.ok(warningResult && warningResult.category === 'warning', 'a title-signaled warning must classify as "warning", not be misrouted to a live incident by an embedded case example');
assert.strictEqual(warningResult.creator, 'Google', '"Google warns" should identify Google as the entity issuing the warning');
assert.notStrictEqual(warningResult.target, 'Extortion', 'a generic threat-category noun ("Extortion") must not be captured as the target');

// Regression: a plain synthetic warning with no embedded case example — the
// simplest path through findWarning() — should also classify correctly and
// fall back to "General Threat" rather than grabbing a stray headline word.
const genericWarningResult = classify({
  title: 'CISA warns hospitals face growing threat of ransomware attacks',
  contentText: 'The agency said hospitals in the United States could face disruptive ransomware attacks in the coming months as attackers increasingly target healthcare providers.',
  link: 'y',
});
assert.ok(genericWarningResult && genericWarningResult.category === 'warning', 'a plain threat warning with no confirmed incident should classify as "warning"');
assert.strictEqual(genericWarningResult.name, 'General Threat', 'a warning naming no specific actor should honestly say so');
assert.strictEqual(genericWarningResult.creator, 'CISA', '"CISA warns" should identify CISA as the issuer');

// Regression: guessWarningIssuer's regex allows "." inside the captured
// phrase (for abbreviations), which let a real headline's own "Warns." run
// on across the sentence boundary into the next sentence's capitalized word
// — observed live as creator "Google Warns. Google" instead of just "Google".
const sentenceBoundaryWarningResult = classify({
  title: 'Extortion crews target AI data, Google Warns.',
  contentText: 'Google warned that extortion crews are increasingly targeting proprietary AI data in a supply chain attack against companies in the United States.',
  link: 'z',
});
assert.ok(sentenceBoundaryWarningResult && sentenceBoundaryWarningResult.category === 'warning');
assert.strictEqual(sentenceBoundaryWarningResult.creator, 'Google', 'the warning issuer must not run on past the sentence boundary into "Google Warns. Google"');

// --- translate.js (pure/sync parts only — no real network calls in the
// test suite, the free tier's daily quota is too tight to spend here; a
// real translation is verified manually against the live API when adding a
// non-English feed) ---
const chunks450 = splitIntoChunks('word '.repeat(200).trim(), 450); // 1000 chars
assert.ok(chunks450.every((c) => c.length <= 450), 'every chunk must stay under the 500-char API limit');
assert.ok(chunks450.join(' ').length > 900, 'chunking must not drop text');
assert.ok(!chunks450.some((c) => c.startsWith(' ') || c.endsWith(' ')), 'chunks should be trimmed, not carry boundary whitespace');

// Regression: a naive fixed-size split can cut a word in half mid-sentence,
// which often translates to nonsense — splitIntoChunks must break on the
// nearest word boundary instead.
const boundaryText = `${'a'.repeat(440)} wholeword ${'b'.repeat(50)}`;
const wordAwareChunks = splitIntoChunks(boundaryText, 450);
assert.ok(!wordAwareChunks.some((c) => c.includes('wholew') && !c.includes('wholeword')), 'chunk boundary must not split a word in half');

// --- looksAttackRelated() ---
assert.strictEqual(looksAttackRelated('A local bakery opened a new storefront downtown'), false, 'unrelated text should not look attack-related');
assert.strictEqual(looksAttackRelated('The malware spread quickly across networks'), true, 'text with an attack-type keyword should look attack-related');
assert.strictEqual(looksAttackRelated('Hugging Face announced a new feature today'), true, 'text mentioning a known AI company should look attack-related');

// --- scheduler.extractOutboundLinks() ---
const { extractOutboundLinks } = require('./scraper/scheduler');
const fakeArticleHtml = `
  <p>Read more about our <a href="/newsletter">newsletter</a> and follow us on
  <a href="https://twitter.com/example">Twitter</a>.</p>
  <p>This is different from an earlier incident where
  <a href="/security/2026/01/01/some-unrelated-story/111">a storage vendor</a>
  fixed a bug, and separate from when
  <a href="/security/2026/02/02/hugging-face-was-hacked/222">OpenAI's rogue agents hacked Hugging Face</a>
  last year.</p>
`;
const links = extractOutboundLinks(fakeArticleHtml, 'https://www.theregister.com/security/2026/09/04/some-article/333', 2);
assert.strictEqual(links.length, 1, 'off-site links (Twitter) and shallow paths (/newsletter) should be filtered out');
assert.ok(links[0].includes('hugging-face-was-hacked'), 'the link whose anchor text mentions an AI company should be prioritized over an unrelated one');

// --- dedupe.isDuplicate() ---
const now = new Date().toISOString();
const existing = [{ name: 'LockBit', target: 'Acme Corp', attackType: 'Ransomware', timestamp: now, sourceUrl: 'x' }];
assert.strictEqual(isDuplicate({ name: 'LockBit', target: 'Acme Corp', attackType: 'Ransomware', timestamp: now, sourceUrl: 'x' }, existing), true, 'same source URL is a duplicate');
assert.strictEqual(isDuplicate({ name: 'LockBit', target: 'Acme Corp', attackType: 'Ransomware', timestamp: now, sourceUrl: 'y' }, existing), true, 'near-identical fields within days is a duplicate');
assert.strictEqual(isDuplicate({ name: 'Medusa', target: 'Totally Different Org', attackType: 'DDoS', timestamp: now, sourceUrl: 'z' }, existing), false, 'unrelated entry is not a duplicate');

// --- store: archive-everything-immediately, live cache capped at MAX_DISPLAY_WINDOW,
// sorted by real timestamp (not insertion order), display window clamped to [20, 200] ---
const tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hacktracker-test-'));
process.env.HACK_TRACKER_DATA_DIR = tmpDataDir;
delete require.cache[require.resolve('./store')];
const store = require('./store');
store.ensureDirs();

function makeEntry(i) {
  return {
    id: `id-${i}`,
    category: 'incident',
    isAIRelated: false,
    timestamp: new Date(2026, 0, 1, 0, 0, i).toISOString(),
    name: 'Test Actor',
    creator: null,
    target: `Target ${i}`,
    attackType: 'Ransomware',
    reason: 'Financial Gain',
    sourceUrl: `http://example.com/${i}`,
    sourceTitle: `Article ${i}`,
    detailFile: '',
  };
}

const TOTAL = 205;
// Insert out of chronological order to prove sorting is by timestamp, not insertion order.
const order = Array.from({ length: TOTAL }, (_, i) => i).sort(() => Math.random() - 0.5);
for (const i of order) store.addEntry('incident', makeEntry(i));

const live = store.loadLive('incident');
assert.strictEqual(live.length, 200, 'live cache should cap at MAX_DISPLAY_WINDOW (200) regardless of insertion order');
assert.strictEqual(live[0].id, `id-${TOTAL - 1}`, 'most recent entry (by timestamp) should be first');
for (let i = 1; i < live.length; i++) {
  assert.ok(new Date(live[i - 1].timestamp) >= new Date(live[i].timestamp), 'live cache must be sorted newest-first by timestamp');
}

const archives = store.listArchiveFiles('incident');
const archivedCount = archives.reduce((sum, f) => sum + f.count, 0);
assert.strictEqual(archivedCount, TOTAL, 'every entry should be archived immediately, not just overflow');

assert.strictEqual(store.setDisplayWindowSize(500), 200, 'display window should clamp to the 200 max');
assert.strictEqual(store.setDisplayWindowSize(5), 20, 'display window should clamp to the 20 min');
assert.strictEqual(store.setDisplayWindowSize(75), 75, 'in-range display window should be kept as-is');
assert.strictEqual(store.loadLiveWindowed('incident').length, 75, 'loadLiveWindowed should slice to the current display window setting');

// Regression: every entry is archived immediately AND kept in the live
// cache, so a stats function reading both and concatenating them would
// double-count every entry still in the live window. computeStats() must
// read from the archive only (which already contains everything).
const statsResult = store.computeStats();
assert.strictEqual(statsResult.totals.incident, TOTAL, `computeStats total must equal the real entry count (${TOTAL}), not double-counted from live+archive overlap`);
assert.strictEqual(statsResult.totals.aiRelated, 0, 'none of these test entries are AI-related');
assert.strictEqual(statsResult.topAttackTypes[0][0], 'Ransomware', 'top attack type should be identifiable');
assert.strictEqual(statsResult.topAttackTypes[0][1], TOTAL, 'attack type count must not be inflated by double-counting');
assert.ok(Array.isArray(statsResult.dailyTrend.incident) && statsResult.dailyTrend.incident.length === 14, 'daily trend should cover a 14-day window');

// Regression: ingestCandidate() silently no-ops if candidate.sourceUrl is
// already in seenUrls — this is correct for its own dedupe purpose, but a
// real bug shipped when scheduler.js's RSS loop pre-marked a URL as "seen"
// BEFORE attempting classification/ingestion, which meant every successful
// classify() result was silently dropped (confirmed live: zero RSS-derived
// entries ever reached the table, only the two database sources). Callers
// must only add to seenUrls AFTER giving up on ingestion, never before.
// detailFile.js also caches its own `require('../store')` reference from
// whenever it was first loaded (transitively, via the earlier
// extractOutboundLinks/scheduler import above, before HACK_TRACKER_DATA_DIR
// was set) — without clearing it too, ingestCandidate() below writes detail
// files into the REAL project's data/ folder instead of this test's tmp dir.
delete require.cache[require.resolve('./scraper/detailFile')];
delete require.cache[require.resolve('./scraper/scheduler')];
const { ingestCandidate } = require('./scraper/scheduler');
const freshCandidate = () => ({
  category: 'incident', isAIRelated: true, name: 'Test Model', creator: 'Test Co', deployedBy: 'Test Group', location: 'Testland', target: 'Test Org',
  attackType: 'Phishing', reason: 'Unknown / Not Specified', sourceUrl: 'http://example.com/regression-test',
  sourceTitle: 'Test', rawText: 'test', feedName: 'Test Feed', timestamp: new Date().toISOString(),
});

// Note: the 'incident' category already holds 200 entries from the sort/
// archive test above (same tmpDataDir, and human+ai now share one category)
// — so these checks look for the specific new entry by sourceUrl/timestamp
// rather than asserting an absolute live-array length.
const seenUrlsBefore = new Set(); // URL not yet marked — the correct calling pattern
ingestCandidate(freshCandidate(), seenUrlsBefore, null);
const liveAfterFresh = store.loadLive('incident');
// freshCandidate's timestamp is "now" (2026+), far newer than every makeEntry
// above (Jan 2026), so it must sort to the very front of the live cache.
assert.strictEqual(liveAfterFresh[0].sourceUrl, 'http://example.com/regression-test', 'ingestCandidate must actually add the entry when its URL was not pre-marked seen');

// Regression: ingestCandidate() builds the stored entry by explicitly
// listing fields to copy from the candidate — adding `location` and
// `deployedBy` to classify()'s output did nothing until this list was also
// updated, so both fields were silently dropped on every real entry
// (confirmed live: computeStats() topLocations/topDeployers came back empty
// despite 150+ real entries all having a location).
assert.strictEqual(liveAfterFresh[0].location, 'Testland', 'location must survive from candidate to stored entry');
assert.strictEqual(liveAfterFresh[0].deployedBy, 'Test Group', 'deployedBy must survive from candidate to stored entry');
assert.strictEqual(liveAfterFresh[0].isAIRelated, true, 'isAIRelated must survive from candidate to stored entry (the same silent-drop bug class)');

const seenUrlsPreMarked = new Set(['http://example.com/regression-test-2']); // simulates the bug
ingestCandidate({ ...freshCandidate(), sourceUrl: 'http://example.com/regression-test-2' }, seenUrlsPreMarked, null);
assert.ok(!store.loadLive('incident').some((e) => e.sourceUrl === 'http://example.com/regression-test-2'), 'pre-marking a URL as seen before calling ingestCandidate must silently skip it (documents the sharp edge)');

fs.rmSync(tmpDataDir, { recursive: true, force: true });

console.log('All checks passed.');
