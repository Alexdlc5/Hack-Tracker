// Structured database (public, no key required): CISA's Known Exploited
// Vulnerabilities catalog. CISA only adds an entry when there's confirmed
// evidence of ACTIVE exploitation in the wild — stronger signal than a
// generic CVE disclosure, so it fits the "Incident Warning" table (an
// elevated/active risk, not a specific victim's confirmed incident).
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const LOOKBACK_MS = 7 * 24 * 60 * 60 * 1000; // 7 days — KEV updates near-daily

function inferAttackType(v) {
  return v.knownRansomwareCampaignUse === 'Known' ? 'Ransomware' : 'Zero-Day Exploit';
}

async function fetchRecentKEV() {
  const res = await fetch(KEV_URL, { headers: { 'User-Agent': 'hack-tracker-app' } });
  if (!res.ok) throw new Error(`CISA KEV returned ${res.status}`);
  const data = await res.json();
  const cutoff = Date.now() - LOOKBACK_MS;

  return (data.vulnerabilities || [])
    .filter((v) => new Date(v.dateAdded).getTime() >= cutoff)
    .map((v) => ({
      category: 'warning',
      isAIRelated: false,
      name: v.vulnerabilityName,
      creator: 'CISA',
      location: 'Unspecified / Global', // a product vulnerability, not tied to one country
      target: `${v.vendorProject} ${v.product}`,
      attackType: inferAttackType(v),
      reason: 'Unknown / Not Specified',
      timestamp: v.dateAdded,
      sourceUrl: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
      sourceTitle: `${v.cveID}: ${v.vulnerabilityName}`,
      rawText: `${v.shortDescription} ${v.requiredAction}`,
      feedName: 'CISA KEV',
    }));
}

module.exports = { fetchRecentKEV };
