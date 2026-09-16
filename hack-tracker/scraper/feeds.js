// Public RSS feeds only — syndication feeds are published for reuse, so this
// avoids scraping HTML directly and stays on solid legal ground.
module.exports = [
  { name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/' },
  { name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews' },
  { name: 'Krebs on Security', url: 'https://krebsonsecurity.com/feed/' },
  { name: 'Dark Reading', url: 'https://www.darkreading.com/rss.xml' },
  { name: 'The Record', url: 'https://therecord.media/feed/' },
  { name: 'SecurityWeek', url: 'https://www.securityweek.com/feed/' },
  { name: 'Infosecurity Magazine', url: 'https://www.infosecurity-magazine.com/rss/news/' },
  { name: 'DataBreaches.net', url: 'https://databreaches.net/feed/' },
  { name: 'Ars Technica Security', url: 'https://arstechnica.com/tag/security/feed/' },
  { name: 'TechCrunch Security', url: 'https://techcrunch.com/category/security/feed/' },
  { name: 'The Register Security', url: 'https://www.theregister.com/security/headlines.atom' },
  { name: 'Malwarebytes Labs', url: 'https://www.malwarebytes.com/blog/feed/index.xml' },
  { name: 'CyberScoop', url: 'https://cyberscoop.com/feed/' },
  { name: 'Security Affairs', url: 'https://securityaffairs.com/feed' },
  { name: 'BankInfoSecurity', url: 'https://www.bankinfosecurity.com/rss-feeds' },
  { name: 'DataBreachToday', url: 'https://www.databreachtoday.com/rss-feeds' },
  { name: 'GovInfoSecurity', url: 'https://www.govinfosecurity.com/rss-feeds' },
  { name: 'Help Net Security', url: 'https://www.helpnetsecurity.com/feed/' },
  { name: 'CSO Online', url: 'https://www.csoonline.com/feed/' },
  { name: 'Graham Cluley', url: 'https://grahamcluley.com/feed/' },
  { name: 'IT Security Guru', url: 'https://www.itsecurityguru.org/feed/' },
  { name: 'ZDNet Security', url: 'https://www.zdnet.com/topic/security/rss.xml' },
  { name: 'The Stack', url: 'https://thestack.technology/feed/' },
  // Incident-response case-study writeups (real intrusions with full attack
  // chains, e.g. "Apache ActiveMQ Exploit Leads to LockBit Ransomware") — the
  // RSS excerpt is just a "Key Takeaways" teaser too short/boilerplate-heavy
  // to pass the lede gate, but the full article (fetched via the existing
  // retryWithFullArticle path) classifies correctly. Verified against classify().
  { name: 'The DFIR Report', url: 'https://thedfirreport.com/feed/' },
  // General international news outlets — noisier (most items aren't security
  // news) but real editorial coverage that does report major breaches, and
  // the only way to get non-trade-press national perspectives (UK here).
  { name: 'BBC Technology', url: 'https://feeds.bbci.co.uk/news/technology/rss.xml' },
  { name: 'The Guardian Technology', url: 'https://www.theguardian.com/technology/rss' },
  // Government/CERT advisory sources. NCSC UK and CERT-EU mirror CISA KEV's
  // role for their regions; StateScoop and CIS/MS-ISAC give US state-level
  // (not just federal) coverage — see the README note in cisaKev.js for why
  // vulnerability-bulletin-style advisories route to the Warning table.
  { name: 'NCSC UK', url: 'https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml' },
  { name: 'CERT-EU', url: 'https://cert.europa.eu/publications/security-advisories-rss' },
  { name: 'StateScoop', url: 'https://statescoop.com/feed/' },
  { name: 'CIS Advisories (MS-ISAC)', url: 'https://www.cisecurity.org/advisory/feed' },
  // Non-English sources — translated via scraper/translate.js before
  // classify() ever sees them (see the `lang` field). Kept to a small list:
  // the free translation tier's daily quota is tight (roughly enough for a
  // couple of articles/day), so this is a starting point, not broad coverage.
  { name: 'ZATAZ', url: 'https://www.zataz.com/feed/', lang: 'fr' },
  { name: 'Le Monde Informatique Sécurité', url: 'https://www.lemondeinformatique.fr/flux-rss/thematique/securite/rss.xml', lang: 'fr' },
  { name: 'Heise Security', url: 'https://www.heise.de/security/rss/news-atom.xml', lang: 'de' },
  // Note: CISA's own advisory feed is vulnerability bulletins ("product X has
  // a flaw"), not attack reports — including it produced false-positive
  // "incidents" out of routine CVE disclosures, so it's deliberately excluded
  // (CISA KEV, a different feed scoped to CONFIRMED active exploitation, is
  // used instead — see scraper/cisaKev.js).
];
