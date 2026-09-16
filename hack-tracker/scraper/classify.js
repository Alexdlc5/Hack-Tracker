// Rule-based field extraction: no LLM, so this is keyword/regex matching
// against known lists. Good enough to sort real incidents into the tables;
// misses novel actor/target names it hasn't seen before.
// ponytail: keyword heuristics, upgrade path is swapping this file's matchers
// for an LLM extraction call if precision becomes a problem.

const ATTACK_TYPES = [
  { label: 'Ransomware', keywords: ['ransomware', 'ransom note', 'encrypted files', 'extortion group'] },
  { label: 'Phishing', keywords: ['phishing', 'spear-phishing', 'spearphishing', 'smishing', 'business email compromise'] },
  { label: 'Data Breach', keywords: ['data breach', 'security breach', 'network breach', 'was breached', 'suffered a breach', 'confirmed a breach', 'leaked data', 'exposed database', 'stolen data', 'data leak', 'leaked records', 'unauthorized access to'] },
  { label: 'DDoS', keywords: ['ddos', 'denial-of-service', 'denial of service'] },
  { label: 'Supply Chain Attack', keywords: ['supply chain attack', 'supply-chain attack', 'compromised update', 'malicious package', 'npm package', 'software supply chain', 'malicious model', 'backdoored model', 'poisoned model', 'trojanized model', 'malicious ai model'] },
  { label: 'Zero-Day Exploit', keywords: ['zero-day', 'zero day', '0-day', 'unpatched vulnerability'] },
  { label: 'Malware', keywords: ['malware', 'trojan', 'worm', 'backdoor', 'rootkit', 'spyware', 'infostealer', 'info-stealer'] },
  { label: 'Insider Threat', keywords: ['insider threat', 'rogue employee', 'malicious insider'] },
  { label: 'Credential Theft', keywords: ['credential stuffing', 'password dump', 'stolen credentials', 'compromised credentials', 'credentials were compromised', 'credentials were stolen', 'account takeover'] },
  { label: 'Nation-State / Espionage', keywords: ['nation-state', 'state-sponsored', 'cyberespionage', 'cyber espionage'] },
  { label: 'Autonomous Agent Misuse', keywords: ['went rogue', 'break out of the sandbox', 'break out of sandboxes', 'broke out of the sandbox', 'broke out of sandboxes', 'sandbox escape', 'acting outside its instructions'] },
];

const THREAT_ACTORS = [
  'LockBit', 'ALPHV', 'BlackCat', 'Cl0p', 'Clop', 'Scattered Spider', 'Lapsus$',
  'REvil', 'Conti', 'Black Basta', 'Akira', 'Medusa', 'RansomHub', 'BianLian',
  'Hunters International', 'Volt Typhoon', 'Salt Typhoon', 'APT28', 'Fancy Bear',
  'APT29', 'Cozy Bear', 'Lazarus Group', 'Sandworm', 'APT41', 'Midnight Blizzard',
  'Star Blizzard', 'Killnet', 'Anonymous Sudan', 'Qilin', 'DragonForce', 'SafePay',
  'INC Ransom', '8Base', 'NoEscape', 'Rhysida', 'Interlock',
  // GTG-1002: Anthropic's own designation for the Chinese state-sponsored
  // group behind the first documented large-scale AI-orchestrated espionage
  // campaign (used Claude Code to attack ~30 organizations). Real, named,
  // worth tracking as a deployer the same way ransomware gang names are.
  'GTG-1002',
  // Note: deliberately excludes common-English-word gang names (Play, Cactus,
  // Meow, Everest) — a bare word-boundary match on those would false-positive
  // on unrelated text ("Google Play", etc.) more often than it correctly attributes.
];

const AI_MODEL_PATTERNS = [
  { re: /chatgpt|gpt-?5|gpt-?4|gpt-?3\.5/i, model: 'GPT (OpenAI)', creator: 'OpenAI' },
  { re: /\bclaude\b/i, model: 'Claude', creator: 'Anthropic' },
  { re: /\bgemini\b|\bbard\b/i, model: 'Gemini', creator: 'Google' },
  { re: /\bllama\b/i, model: 'Llama', creator: 'Meta' },
  { re: /\bmistral\b/i, model: 'Mistral', creator: 'Mistral AI' },
  { re: /\bcopilot\b/i, model: 'Copilot', creator: 'Microsoft' },
  { re: /\bgrok\b/i, model: 'Grok', creator: 'xAI' },
  { re: /\bdeepseek\b/i, model: 'DeepSeek', creator: 'DeepSeek' },
];

const AI_INDICATOR_KEYWORDS = [
  'ai agent', 'ai-powered attack', 'autonomous agent', 'agentic ai',
  'ai-generated malware', 'ai-written malware', 'llm-powered', 'llm-generated',
  'ai worm', 'malicious ai model', 'jailbroken ai', 'used an ai model to',
  'ai chatbot was used to', 'ai autonomously',
];

// AI is the attack *vector* even without an autonomous agent driving it:
// a backdoored model that runs malicious code when loaded, or a poisoned
// dataset/package distributed through an ML hub.
const AI_SUPPLY_CHAIN_KEYWORDS = [
  'malicious model', 'backdoored model', 'poisoned model', 'trojanized model',
  'malicious ai model', 'pickle exploit', 'compromised model weights',
  'malicious pypi package', 'poisoned dataset', 'model hub', 'ai supply chain',
];

// Companies/platforms whose product IS an AI system — a breach of their
// infrastructure is treated as an AI-sector incident even when the attack
// method itself is conventional (stolen credentials, unpatched software).
const AI_COMPANIES = [
  { name: 'OpenAI', re: /\bopenai\b/i },
  { name: 'Anthropic', re: /\banthropic\b/i },
  { name: 'Hugging Face', re: /hugging\s?face/i },
  { name: 'Google DeepMind', re: /\bdeepmind\b/i },
  { name: 'Stability AI', re: /stability ai/i },
  { name: 'Midjourney', re: /midjourney/i },
  { name: 'Perplexity', re: /\bperplexity\b/i },
  { name: 'Cohere', re: /\bcohere\b/i },
  { name: 'Mistral AI', re: /mistral ai/i },
  { name: 'Character.AI', re: /character\.ai/i },
  { name: 'Runway', re: /\brunwayml\b|\brunway\b/i },
  { name: 'Scale AI', re: /scale ai/i },
  { name: 'Databricks', re: /databricks/i },
  { name: 'Replicate', re: /\breplicate\.com\b|\breplicate\b/i },
  { name: 'Weights & Biases', re: /weights\s*&\s*biases|\bwandb\b/i },
  { name: 'Inflection AI', re: /inflection ai/i },
  { name: 'xAI', re: /\bxai\b/i },
];

function matchAICompany(text) {
  for (const c of AI_COMPANIES) {
    if (c.re.test(text)) return c.name;
  }
  return null;
}

// An article can mention "ransomware" or "DDoS" while just explaining the
// concept or disclosing a theoretical vulnerability ("could allow an
// attacker to..."). Require language confirming an incident actually
// happened, so advisories/explainers/opinion pieces get skipped.
const INCIDENT_INDICATORS = [
  'attacked', 'was attacked', 'breached', 'was breached', 'hacked', 'was hacked',
  'compromised', 'was compromised', 'confirmed a', 'disclosed a', 'suffered a',
  'suffered an', 'hit by', 'targeted by', 'claimed responsibility', 'has been hit',
  'took credit', 'said it was', 'said the attack', 'said hackers', 'according to the company',
  'notified customers', 'notified victims', 'said in a filing',
  // Note: deliberately excludes a bare "in a statement" — virtually any news
  // article quoting any spokesperson about anything contains that phrase
  // (confirmed on two real false-positive-adjacent cases: a Black Axe
  // extradition story and a TeamPCP arrest/investigative piece), so on its
  // own it's too weak a signal that THIS article is reporting a live incident.
  // Longer-form incident/threat-intel reporting (e.g. a vendor's writeup of an
  // attack campaign) states things happened without ever using breach-notice
  // phrasing above — it reads more like "spies told Claude to break into X".
  'break into', 'broke into', 'break-in', 'break-ins', 'attacks succeeded',
  'successfully attacked', 'gained access to', 'obtained access to', 'infiltrated',
  'according to a report', 'according to the report', 'threat actor was able to',
  'used claude to', 'used chatgpt to', 'induce', 'told claude to', 'told the ai to',
  // Breach-notification-letter phrasing: "[company] is notifying 50,000
  // patients that..." / "attackers accessed files containing...". Distinct
  // from the "notified customers" phrasing above, which is past-tense.
  'is notifying', 'are notifying', 'attackers accessed', 'hackers accessed',
  // Ransomware-claim headline phrasing ("[group] claims attack on [victim]") —
  // as common in incident reporting as "claimed responsibility" above, just present-tense.
  'claims attack', 'claimed attack', 'claims responsibility', 'claims credit',
  // Regulator/agency disclosure phrasing ("Spain's data protection agency
  // has reported the country's first-ever breach caused by...") — a real
  // incident report that never uses breach-notice-letter phrasing above.
  'has reported the', 'reported the country', 'reported a breach', 'caused by the actions of',
];

// A prosecution/court-outcome recap (sentencing, extradition, plea, conviction)
// reports the resolution of a PAST case, not a live incident — even though it
// often quotes officials ("said in a statement") and describes what the group
// did using incident-like past tense ("a ransomware group that attacked more
// than 1,000 orgs"), both of which otherwise read as incident language above.
const LEGAL_OUTCOME_INDICATORS = [
  'sentenced to', 'was sentenced', 'pleaded guilty', 'pleads guilty', 'pled guilty',
  'was extradited', 'were extradited', 'convicted of', 'found guilty', 'indicted for',
];

// Marks a sentence as backstory ("X comes less than a week after Y
// happened") rather than a claim about the CURRENT article's own subject.
// Requires the "comes/come/came ... after" construction specifically (not
// just any "after" clause) — a real incident report can legitimately say
// "the breach was confirmed a week after a report said it happened" about
// its OWN subject, which must NOT be excluded from lede consideration.
const BACKSTORY_FRAMING_RE = /\b(?:comes?|came)\b.{0,60}?\b(?:day|days|week|weeks|month|months|hour|hours|year|years)\s+after\b/;
const BACKSTORY_FRAMING = ['following a', 'in the wake of', 'this follows'];
function isBackstoryFraming(sentence) {
  const s = sentence.toLowerCase();
  return BACKSTORY_FRAMING_RE.test(s) || BACKSTORY_FRAMING.some((k) => s.includes(k));
}

const REASON_TYPES = [
  { label: 'Financial Gain', keywords: ['ransom', 'extortion', 'financial gain', 'for profit'] },
  { label: 'Espionage', keywords: ['espionage', 'intelligence gathering', 'state-sponsored'] },
  { label: 'Hacktivism', keywords: ['hacktivis', 'political statement', 'in protest'] },
  { label: 'Data Theft', keywords: ['steal data', 'data theft', 'exfiltrat', 'was stolen', 'were stolen'] },
  { label: 'Disruption / Sabotage', keywords: ['disrupt', 'sabotage', 'took down', 'knocked offline'] },
];

const US_STATES = ['alabama', 'alaska', 'arizona', 'arkansas', 'california', 'colorado', 'connecticut', 'delaware', 'florida', 'georgia', 'hawaii', 'idaho', 'illinois', 'indiana', 'iowa', 'kansas', 'kentucky', 'louisiana', 'maine', 'maryland', 'massachusetts', 'michigan', 'minnesota', 'mississippi', 'missouri', 'montana', 'nebraska', 'nevada', 'new hampshire', 'new jersey', 'new mexico', 'new york', 'north carolina', 'north dakota', 'ohio', 'oklahoma', 'oregon', 'pennsylvania', 'rhode island', 'south carolina', 'south dakota', 'tennessee', 'texas', 'utah', 'vermont', 'virginia', 'washington', 'west virginia', 'wisconsin', 'wyoming'];
const US_KEYWORDS = ['united states', 'u.s.', 'usa', 'america', '.gov', 'washington, d.c', 'fbi', 'cisa', 'department of homeland security', ...US_STATES];

// Returns whichever category's keyword appears EARLIEST in the text, not
// whichever category happens to be first in the list above. A long article
// can mention a tangential/earlier incident for comparison later in the
// piece (e.g. "unlike last year's ransomware attack..."); news writing leads
// with the actual subject, so the earliest match is the reliable one.
function findKeywordMatch(text, list) {
  let best = null;
  for (const entry of list) {
    for (const kw of entry.keywords) {
      const idx = text.indexOf(kw);
      if (idx !== -1 && (!best || idx < best.index)) {
        best = { label: entry.label, keyword: kw, index: idx };
      }
    }
  }
  return best ? { label: best.label, keyword: best.keyword } : null;
}

function matchThreatActor(text) {
  for (const name of THREAT_ACTORS) {
    const re = new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
    if (re.test(text)) return name;
  }
  return null;
}

function matchAIModel(text) {
  for (const p of AI_MODEL_PATTERNS) {
    if (p.re.test(text)) return { model: p.model, creator: p.creator };
  }
  return null;
}

function isUSRelevant(text) {
  return US_KEYWORDS.some((k) => text.includes(k));
}

// Global coverage: which country/region an incident is actually about.
// Position-based earliest match (like findKeywordMatch above) — an article
// about one country routinely name-drops another in passing (e.g. the real
// Spain AI-attack article mentioned "foremost US AI houses" as background),
// so the first-mentioned country is the reliable signal, not just "any match".
const LOCATIONS = [
  { name: 'United States', keywords: US_KEYWORDS },
  { name: 'United Kingdom', keywords: ['united kingdom', 'u.k.', 'britain', 'england', 'scotland', 'wales'] },
  { name: 'Spain', keywords: ['spain', 'spanish'] },
  { name: 'Germany', keywords: ['germany', 'german'] },
  { name: 'France', keywords: ['france', 'french'] },
  { name: 'China', keywords: ['china', 'chinese'] },
  { name: 'Russia', keywords: ['russia', 'russian'] },
  { name: 'Iran', keywords: ['iran', 'iranian'] },
  { name: 'North Korea', keywords: ['north korea', 'north korean', 'dprk'] },
  { name: 'South Korea', keywords: ['south korea', 'south korean'] },
  { name: 'India', keywords: ['india', 'indian'] },
  { name: 'Australia', keywords: ['australia', 'australian'] },
  { name: 'Canada', keywords: ['canada', 'canadian'] },
  { name: 'Japan', keywords: ['japan', 'japanese'] },
  { name: 'Brazil', keywords: ['brazil', 'brazilian'] },
  { name: 'Ukraine', keywords: ['ukraine', 'ukrainian'] },
  { name: 'Israel', keywords: ['israel', 'israeli'] },
  { name: 'Netherlands', keywords: ['netherlands', 'dutch'] },
  { name: 'Italy', keywords: ['italy', 'italian'] },
  { name: 'Sweden', keywords: ['sweden', 'swedish'] },
  { name: 'Poland', keywords: ['poland', 'polish'] },
  { name: 'Mexico', keywords: ['mexico', 'mexican'] },
  { name: 'Switzerland', keywords: ['switzerland', 'swiss'] },
  { name: 'Belgium', keywords: ['belgium', 'belgian'] },
  { name: 'Singapore', keywords: ['singapore', 'singaporean'] },
  { name: 'New Zealand', keywords: ['new zealand'] },
  { name: 'South Africa', keywords: ['south africa', 'south african'] },
  { name: 'Vietnam', keywords: ['vietnam', 'vietnamese'] },
  { name: 'Taiwan', keywords: ['taiwan', 'taiwanese'] },
];

function guessLocation(text) {
  let best = null;
  for (const loc of LOCATIONS) {
    for (const kw of loc.keywords) {
      const idx = text.indexOf(kw);
      if (idx !== -1 && (!best || idx < best.index)) best = { name: loc.name, index: idx };
    }
  }
  return best ? best.name : 'Unspecified / Global';
}

// Common sentence-starters that match the "[A-Z]word" shape but aren't organization
// names — without this, "Over 500 Organizations Hit by..." extracts "Over" as the target.
const NON_ENTITY_WORDS = new Set(['the', 'a', 'an', 'this', 'that', 'these', 'those', 'over', 'two', 'three', 'four', 'five', 'new', 'some', 'many', 'several', 'it', 'they', 'he', 'she', 'many', 'more', 'most', 'another', 'other', 'according', 'latest', 'novel', 'how', 'why', 'what', 'top', 'best', 'inside', 'exclusive', 'hundreds', 'thousands', 'dozens', 'why', 'here', 'southeast', 'northeast', 'southwest', 'northwest',
  // Same "count leads the headline" shape as "Over 500 Organizations Hit
  // by..." above — "280,000 Impacted by Premier Medical Group..." extracts
  // "Impacted" since the number itself isn't a letter for the regex to match.
  'impacted', 'affected',
  // Generic tech/security acronyms, not organization names — "compromised
  // VPN" or "targeted API" reads exactly like "attack on Acme Corp" to the
  // regex above, and a 3+ letter acronym passes the length check. Found via
  // a real article where this made guessTarget stop at "VPN" instead of
  // continuing to the article's actual named victim ("attack on Stryker").
  'vpn', 'api', 'sql', 'dns', 'url', 'ssl', 'tls', 'ceo', 'cfo', 'cto', 'faq', 'saas',
  // Nation-state attacker demonyms — describe the ATTACKER's origin, not the
  // victim, but are capitalized at the start of exactly this kind of headline
  // ("Chinese spies used Claude to break into..."), so guessTarget grabs them.
  'chinese', 'russian', 'iranian', 'north', 'korean', 'american', 'british', 'israeli', 'ukrainian',
  // AI model/company names are the attacker's TOOL in these headlines
  // ("spies used Claude to break into X") — without this, target ends up
  // being the same name already captured as the attacker.
  'claude', 'gpt', 'chatgpt', 'gemini', 'llama', 'mistral', 'copilot', 'grok', 'deepseek', 'openai', 'anthropic',
  // Generic threat-category nouns, not organization names — "Extortion crews
  // have their eyes on..." extracts "Extortion" the same way "Over 500..."
  // extracted "Over" above. Same bug class, pre-empting the obvious repeats.
  'extortion', 'ransomware', 'malware', 'phishing', 'cyberattack', 'cyberattacks',
  'breach', 'breaches', 'hackers', 'attackers', 'threat', 'threats', 'warning',
  'exploit', 'exploits', 'vulnerability', 'vulnerabilities',
  // Day names are always capitalized ("disclosed the breach Thursday") and
  // routinely sit right next to a reporting verb like "warned" — same trap
  // as the other generic-word categories above.
  'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']);

function looksLikeEntity(phrase) {
  const firstWord = phrase.split(/\s+/)[0].toLowerCase();
  return phrase.length > 2 && !NON_ENTITY_WORDS.has(firstWord);
}

function splitSentences(text) {
  return text.split(/(?<=[.!?])\s+(?=[A-Z0-9"“])/).filter(Boolean);
}

// RSS feeds' content:encoded field is raw HTML, and inline markup routinely
// splits a keyword phrase mid-sentence — e.g. "were <a href=...>extradited
// to the United States</a>" breaks a literal "were extradited" substring
// match. Every classify() input is run through this first so keyword/regex
// matching sees plain text regardless of whether it came from a raw RSS item
// or already-stripped article text (fetchArticle already strips tags, so
// re-running this on that text is a harmless no-op).
function stripTags(html) {
  return String(html || '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&#39;|&rsquo;|&lsquo;/g, "'")
    .replace(/&quot;|&rdquo;|&ldquo;/g, '"')
    // Catch-all for remaining numeric entities (e.g. &#160;) — guessTarget's
    // regex allows "." and "&" mid-word, so a leftover "&#160;" right after a
    // company name gets swallowed into it (observed as "IDScan.&" in real output).
    .replace(/&#\d+;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

const LEDE_SENTENCE_COUNT = 3;

// Real incident reporting states "what happened" plainly in the headline/lede
// ("spies told Claude to break into X") — the specific attack-type
// categorization is often only spelled out later in the analysis. An
// announcement/advisory article never claims an incident happened in its
// lede even when it mentions attack-related words in passing further down
// (e.g. "$1B for cyber defenders" discussing ransomware trends in general).
// Gating on the lede catches real incidents while still rejecting that kind
// of false positive, without requiring every signal to be in one place.
function findIncident(fullText) {
  const sentences = splitSentences(fullText);
  const ledeSentences = sentences.slice(0, LEDE_SENTENCE_COUNT);
  const lede = ledeSentences.join(' ').toLowerCase();
  if (LEGAL_OUTCOME_INDICATORS.some((k) => lede.includes(k))) return null;

  // A product-announcement lede often opens with 1-2 sentences about the
  // announcement, then a "why now" sentence citing an unrelated PAST incident
  // for context ("The new tools come less than a week after OpenAI ...
  // infiltrated Hugging Face") — that backstory sentence can fall inside the
  // 3-sentence lede window and contains strong incident language despite
  // describing a different company's old news, not this article's subject.
  // Excluding just that sentence (not the whole lede) still lets a genuine
  // incident article mention an unrelated earlier attack for comparison.
  const qualifyingLede = ledeSentences
    .filter((s) => !isBackstoryFraming(s))
    .join(' ')
    .toLowerCase();
  const hasIncidentLanguage = INCIDENT_INDICATORS.some((k) => qualifyingLede.includes(k));
  if (!hasIncidentLanguage) return null;

  const attackTypeMatch = findKeywordMatch(fullText.toLowerCase(), ATTACK_TYPES);
  if (!attackTypeMatch) return null;

  return { attackTypeMatch };
}

// Distinct from INCIDENT_INDICATORS: this is forward-looking/hypothetical
// language ("Google warns...", "could face...") rather than a claim that
// something already happened. Feeds the third "Incident Warning" table —
// threat intelligence and risk reporting, not a confirmed live incident.
const WARNING_INDICATORS = [
  'warns', 'warned', 'warning of', 'at risk', 'could face', 'may face', 'predicts', 'forecasts',
  'expected to', 'growing threat', 'on the rise', 'increasingly targeting', 'have their eyes on',
  'urges organizations', 'advises', 'recommends organizations', 'flags a risk', 'raises concerns',
  'according to a warning', 'threat report', 'threat intelligence report', 'eyeing', 'could be used to',
  'sounding the alarm', 'cautioned', 'cautions',
];

// Same lede-gate structure as findIncident(), swapping in WARNING_INDICATORS
// — a warning article's lede says "X warns of Y risk", never claims Y
// actually happened, which is exactly what keeps this from double-counting
// as a real incident (findIncident() is tried first and takes priority).
function findWarning(fullText) {
  const sentences = splitSentences(fullText);
  const lede = sentences.slice(0, LEDE_SENTENCE_COUNT).join(' ').toLowerCase();
  if (!WARNING_INDICATORS.some((k) => lede.includes(k))) return null;

  const attackTypeMatch = findKeywordMatch(fullText.toLowerCase(), ATTACK_TYPES);
  if (!attackTypeMatch) return null;

  return { attackTypeMatch };
}

// Headline title-case styling capitalizes every word, including verbs
// ("Cisco Warns of Ongoing Exploitation") — the capital-word regexes below
// can't tell a verb from part of an entity name, so a candidate that runs
// into one of these common reporting verbs is truncated there instead of
// swallowing it as if it were part of the "target".
const HEADLINE_VERBS = new Set(['warns', 'warned', 'confirms', 'confirmed', 'discloses', 'disclosed', 'admits', 'admitted', 'claims', 'claimed', 'says', 'said', 'reports', 'reported', 'reveals', 'revealed', 'plugs', 'patches', 'patched', 'fixes', 'fixed']);
function trimAtHeadlineVerb(phrase) {
  const words = phrase.split(/\s+/);
  // Strip trailing punctuation before checking — a captured phrase crossing a
  // sentence boundary (allowed so abbreviations like "U.S." survive) can
  // carry a period on the verb itself ("Warns."), which otherwise silently
  // fails the exact-match lookup and lets the phrase run on past it
  // (observed as target/creator "Google Warns. Google" in real output).
  const idx = words.findIndex((w) => HEADLINE_VERBS.has(w.toLowerCase().replace(/[.,]+$/, '')));
  return idx > 0 ? words.slice(0, idx).join(' ') : phrase;
}

// Best-effort target extraction: look for "<verb> <Capitalized Phrase>" near
// common incident-report phrasing. Falls back to "See source article" — full
// named-entity recognition needs an LLM/NER model, out of scope without one.
// excludeWords keeps target from re-capturing a name already assigned
// elsewhere in this entry (e.g. the AI model, or a warning's issuing org).
function guessTarget(title, body, excludeWords = []) {
  const excluded = new Set(excludeWords.filter(Boolean).map((w) => w.toLowerCase()));
  const isExcluded = (phrase) => excluded.has(phrase.toLowerCase());
  const combined = `${title}. ${body}`;
  // The word char class allows "." (for abbreviations like "U.S." or "Corp.")
  // — the (?<!\.) before each extension's \s+ stops the match from continuing
  // past a sentence-ending period into the next sentence's capitalized first
  // word (observed as "IDScan. Krebs" swallowing a source's byline). Also
  // allows the curly apostrophe (’) real headlines use in possessives
  // ("Missouri’s Cedar County Memorial Hospital") — the straight ASCII
  // apostrophe alone truncated the match right before it, losing everything
  // after (observed as target "Missouri" instead of the hospital's name).
  const patterns = [
    /(?:attack(?:ed)? on|targeted|breach(?:ed)? at|hit|struck|compromised)\s+([A-Z][A-Za-z0-9&.,'’-]*(?:(?<!\.)\s+[A-Z][A-Za-z0-9&.,'’-]*){0,3})/g,
  ];
  for (const re of patterns) {
    for (const m of combined.matchAll(re)) {
      const candidate = trimAtHeadlineVerb(m[1].replace(/[.,]$/, '').trim());
      if (looksLikeEntity(candidate) && !isExcluded(candidate)) return candidate;
    }
  }
  // Allows lowercase connectors (of/the/and/for) so "Bank of America" and
  // "Department of Justice" survive intact instead of truncating at "of".
  const titleCapsMatches = title.matchAll(/([A-Z][a-zA-Z0-9&'’-]*(?:\s+(?:of|the|and|for)\s+[A-Z][a-zA-Z0-9&'’-]*|\s+[A-Z][a-zA-Z0-9&'’-]*){0,2})/g);
  for (const m of titleCapsMatches) {
    const candidate = trimAtHeadlineVerb(m[1].trim());
    if (looksLikeEntity(candidate) && !isExcluded(candidate)) return candidate;
  }
  return 'See source article';
}

// Who issued a warning ("Google warns", "CISA warned", "the report from X
// cautioned") — a warning article names a reporting org, not a victim, so
// this is a separate job from guessTarget's (which finds the at-risk party).
function guessWarningIssuer(title, body) {
  const combined = `${title}. ${body}`;
  // Same (?<!\.) guard as guessTarget: without it, a period inside the
  // captured phrase (allowed for abbreviations) lets the match run on past a
  // real sentence boundary into the next sentence's capitalized words
  // (observed as "Google Warns. Google" — the headline's own "Warns." got
  // captured, then continued into the next sentence's "Google").
  const m = combined.match(/([A-Z][A-Za-z0-9&.'’-]*(?:(?<!\.)\s+[A-Z][A-Za-z0-9&.'’-]*){0,3})\s+(?:warns|warned|cautions|cautioned|advises|advised)\b/);
  if (!m) return null;
  const candidate = trimAtHeadlineVerb(m[1].trim());
  return looksLikeEntity(candidate) ? candidate : null;
}

// Who actually USED the AI to attack — distinct from the model's own creator
// (Claude was made by Anthropic, but deployed by a Chinese state-sponsored
// group). Checks known named groups first, then generic nation-state/actor-
// type phrasing common in this kind of reporting, before giving up honestly.
const GENERIC_DEPLOYER_PATTERNS = [
  { re: /\b((?:chinese|russian|iranian|north korean|american|israeli|ukrainian)\s+(?:state-sponsored\s+)?(?:hackers|spies|group|actors|operatives|threat actors))\b/i },
  { re: /\ban individual\b/i, label: 'An Individual' },
  { re: /\b(?:a |an )?criminal (?:group|gang|crew)\b/i, label: 'Criminal Group' },
  { re: /\bextortion crew\b/i, label: 'Extortion Crew' },
  { re: /\bhacktivis(?:t|ts|m)\b/i, label: 'Hacktivist Group' },
];
function guessDeployer(text) {
  const actor = matchThreatActor(text);
  if (actor) return actor;
  for (const p of GENERIC_DEPLOYER_PATTERNS) {
    const m = text.match(p.re);
    if (m) return p.label || m[1].replace(/\b\w/g, (c) => c.toUpperCase());
  }
  return 'Unknown / Unattributed';
}

/**
 * @returns {object|null} classified fields, or null if the article should be
 *   skipped. Global coverage (no country filter) — every entry carries a
 *   `location` field instead, guessed from the article text. Two categories:
 *   - 'incident': a confirmed real incident — human-executed or AI-related
 *     (as attacker, vector, or target), distinguished by `isAIRelated` so
 *     both display in one table with AI-related rows marked/highlighted.
 *   - 'warning': threat-intelligence/risk reporting — nothing has happened
 *     yet, someone is warning it could.
 */
function classify({ title, contentText, link }) {
  title = stripTags(title);
  contentText = stripTags(contentText);
  const fullText = `${title}. ${contentText}`;
  const lowerFull = fullText.toLowerCase();

  // A warning/trend-report article ("X warns...") often cites one real case
  // as supporting evidence, and that example sentence can carry genuine
  // incident language ("Mandiant investigated... broke into a healthcare
  // company") within the lede window. The title is the strongest, least
  // ambiguous signal of what the article fundamentally IS — if the title
  // itself reads as a warning, check findWarning() before letting an
  // embedded example's incident language misroute this as a live incident.
  const titleLower = title.toLowerCase();
  const titleSignalsWarning = WARNING_INDICATORS.some((k) => titleLower.includes(k));

  const incident = !titleSignalsWarning && findIncident(fullText);
  if (incident) {
    const { attackTypeMatch } = incident;
    const reasonMatch = findKeywordMatch(lowerFull, REASON_TYPES);
    const aiModel = matchAIModel(lowerFull);
    const aiCompanyInLede = matchAICompany(splitSentences(fullText).slice(0, LEDE_SENTENCE_COUNT).join(' ').toLowerCase());
    const aiCompany = matchAICompany(lowerFull);
    const hasAIIndicator = AI_INDICATOR_KEYWORDS.some((k) => lowerFull.includes(k));
    const hasSupplyChainIndicator = AI_SUPPLY_CHAIN_KEYWORDS.some((k) => lowerFull.includes(k));

    // 1. An AI model/agent actively executed the attack — including an
    // undisclosed/unnamed one ("did not name the LLM used"), which is common
    // in real reporting. Deliberately does NOT fall back to aiCompany for
    // creator here: a company name mentioned anywhere in a long article is
    // often unrelated backstory (confirmed on a real case — an article about
    // an unnamed-LLM attack also referenced OpenAI's unrelated past incident
    // for context, which must not become this entry's "creator").
    if (hasAIIndicator) {
      return {
        category: 'incident',
        isAIRelated: true,
        name: aiModel ? aiModel.model : 'Unspecified AI Agent',
        creator: aiModel ? aiModel.creator : 'Unknown / Unattributed',
        deployedBy: guessDeployer(lowerFull),
        location: guessLocation(lowerFull),
        target: guessTarget(title, contentText, [aiModel && aiModel.model, aiModel && aiModel.creator]),
        attackType: attackTypeMatch.label,
        reason: reasonMatch ? reasonMatch.label : 'Unknown / Not Specified',
        matchedKeywords: { attackType: attackTypeMatch.keyword, reason: reasonMatch && reasonMatch.keyword },
      };
    }

    // 2. A malicious/backdoored model or ML package was the attack vector.
    if (hasSupplyChainIndicator) {
      const name = aiModel ? aiModel.model : 'Malicious / Backdoored AI Model';
      const creator = aiModel ? aiModel.creator : (aiCompany || 'Unknown / Unattributed');
      return {
        category: 'incident',
        isAIRelated: true,
        name,
        creator,
        deployedBy: guessDeployer(lowerFull),
        location: guessLocation(lowerFull),
        target: guessTarget(title, contentText, [name, creator]),
        attackType: attackTypeMatch.label,
        reason: reasonMatch ? reasonMatch.label : 'Unknown / Not Specified',
        matchedKeywords: { attackType: attackTypeMatch.keyword, reason: reasonMatch && reasonMatch.keyword },
      };
    }

    // 3. An AI company/platform itself was the target of the attack. Scoped
    // to the LEDE specifically (not aiCompany's whole-doc match) — if an AI
    // company is genuinely this article's subject, the lede says so; a
    // mention only in a later backstory/comparison paragraph is not the
    // same claim (confirmed on a real case where "OpenAI" appeared only in
    // an unrelated background reference three paragraphs down).
    if (aiCompanyInLede) {
      return {
        category: 'incident',
        isAIRelated: true,
        name: `${aiCompanyInLede} Platform`,
        creator: aiCompanyInLede,
        deployedBy: guessDeployer(lowerFull),
        location: guessLocation(lowerFull),
        target: aiCompanyInLede,
        attackType: attackTypeMatch.label,
        reason: reasonMatch ? reasonMatch.label : 'Unknown / Not Specified',
        matchedKeywords: { attackType: attackTypeMatch.keyword, reason: reasonMatch && reasonMatch.keyword },
      };
    }

    // 4. A conventional human-executed incident — global coverage, no
    // country filter (the app used to be USA-only; now every incident is
    // tracked and the Location column says where it happened).
    const actor = matchThreatActor(lowerFull);
    return {
      category: 'incident',
      isAIRelated: false,
      name: actor || 'Unknown / Unattributed',
      creator: null,
      location: guessLocation(lowerFull),
      target: guessTarget(title, contentText, [actor]),
      attackType: attackTypeMatch.label,
      reason: reasonMatch ? reasonMatch.label : 'Unknown / Not Specified',
      matchedKeywords: { attackType: attackTypeMatch.keyword, reason: reasonMatch && reasonMatch.keyword, actor },
    };
  }

  const warning = findWarning(fullText);
  if (warning) {
    const { attackTypeMatch } = warning;
    const reasonMatch = findKeywordMatch(lowerFull, REASON_TYPES);
    const aiModel = matchAIModel(lowerFull);
    const aiCompany = matchAICompany(lowerFull);
    const actor = matchThreatActor(lowerFull);
    const issuer = guessWarningIssuer(title, contentText);

    // "name" is whatever the warning is actually ABOUT (a named model, a
    // known threat actor); most warnings don't name one, and "General
    // Threat" is an honest label rather than grabbing a stray capitalized
    // word out of the headline the way the old target-extraction bug did.
    const name = aiModel ? aiModel.model : (actor || 'General Threat');
    const creator = issuer || aiCompany || 'Unknown';
    return {
      category: 'warning',
      isAIRelated: !!(aiModel || aiCompany),
      name,
      creator,
      location: guessLocation(lowerFull),
      target: guessTarget(title, contentText, [name, creator]),
      attackType: attackTypeMatch.label,
      reason: reasonMatch ? reasonMatch.label : 'Unknown / Not Specified',
      matchedKeywords: { attackType: attackTypeMatch.keyword, reason: reasonMatch && reasonMatch.keyword },
    };
  }

  return null;
}

// Loose, whole-document check for "worth following this article's outbound
// links to see if one leads to a real incident report" — deliberately looser
// than classify()'s own gates, since we're not deciding an incident happened
// here, just whether the topic is adjacent enough to be worth one extra fetch.
function looksAttackRelated(text) {
  const lower = stripTags(text).toLowerCase();
  return !!findKeywordMatch(lower, ATTACK_TYPES) || !!matchAICompany(lower) || !!matchAIModel(lower);
}

module.exports = { classify, isUSRelevant, guessLocation, looksAttackRelated };
