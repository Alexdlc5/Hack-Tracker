const fs = require('fs');
const path = require('path');
const store = require('../store');

function categoryLabel(entry) {
  if (entry.category === 'warning') return 'Threat Warning (No Confirmed Incident)';
  return entry.isAIRelated ? 'AI-Related Incident' : 'Human-Executed Incident';
}

function writeDetailFile(entry, { rawText, feedName }) {
  const isAI = !!entry.isAIRelated;
  const isWarning = entry.category === 'warning';
  const subjectLabel = isAI ? 'MODEL' : isWarning ? 'THREAT / SUBJECT' : 'ATTACKER / GROUP';
  const creatorLabel = isAI ? 'MODEL CREATOR' : isWarning ? 'WARNING ISSUED BY' : null;
  const targetLabel = isWarning ? 'AT-RISK TARGET / SECTOR' : 'TARGET';

  const lines = [
    isWarning ? 'THREAT WARNING REPORT' : 'INCIDENT DETAIL REPORT',
    '=======================',
    `ID: ${entry.id}`,
    `Category: ${categoryLabel(entry)}`,
    isAI ? 'AI-RELATED: Yes (highlighted in the Incident table)' : null,
    `Detected/Reported: ${entry.timestamp}`,
    '',
    `${subjectLabel}: ${entry.name}`,
    creatorLabel ? `${creatorLabel}: ${entry.creator}` : null,
    isAI ? `DEPLOYED BY: ${entry.deployedBy || 'Unknown / Unattributed'}` : null,
    `LOCATION: ${entry.location || 'Unspecified / Global'}`,
    `${targetLabel}: ${entry.target}`,
    `${isWarning ? 'THREAT TYPE' : 'ATTACK TYPE'}: ${entry.attackType}`,
    `SUSPECTED MOTIVE: ${entry.reason}`,
    '',
    'SOURCE ARTICLE',
    '--------------',
    `Title: ${entry.sourceTitle}`,
    `Publisher: ${feedName}`,
    `URL: ${entry.sourceUrl}`,
    '',
    'RAW EXCERPT',
    '-----------',
    (rawText || '').trim() || '(no article body available from feed)',
    '',
    'ANALYST NOTES (auto-generated, rule-based extraction — not AI-written)',
    '------------------------------------------------------------------------',
    `- ${isWarning ? 'Threat type' : 'Attack type'} matched keyword: "${entry.matchedKeywords?.attackType || 'n/a'}"`,
    `- Motive matched keyword: "${entry.matchedKeywords?.reason || 'not identified'}"`,
    !isWarning && !isAI ? `- Attacker/group matched via known-actor lookup: ${entry.matchedKeywords?.actor || 'not identified — see raw excerpt'}` : null,
    '',
    isWarning
      ? 'This is a THREAT WARNING, not a confirmed incident — the source article discusses risk, prediction, or general threat intelligence rather than reporting a specific attack that has already happened.'
      : 'This report was generated automatically from open-source news reporting.',
    'It has not been verified by a human analyst or AI model. Cross-reference',
    'the source article above for full context.',
  ].filter((l) => l !== null);

  const file = path.join(store.detailsDir(entry.category), `${entry.id}.txt`);
  fs.writeFileSync(file, lines.join('\n'));
  return file;
}

module.exports = { writeDetailFile };
