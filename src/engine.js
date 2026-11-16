// Second Look — explainable scam-message checker. Pure functions, no network,
// no dependencies: the text a person pastes never leaves their device.

/** @typedef {{id:string, title:string, explain:string, weight:number, spans:[number,number][], category:string}} Finding */

const BRANDS = [
  { name: 'PayPal', words: ['paypal'], domains: ['paypal.com', 'paypal.me'] },
  { name: 'Amazon', words: ['amazon'], domains: ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazon.ca', 'amazon.de', 'amazon.com.au', 'amzn.to', 'amazon.jobs'] },
  { name: 'Apple', words: ['apple id', 'apple account', 'apple support', 'apple pay', 'icloud', 'itunes'], domains: ['apple.com', 'icloud.com'] },
  { name: 'Netflix', words: ['netflix'], domains: ['netflix.com'] },
  { name: 'Microsoft', words: ['microsoft', 'outlook', 'office 365', 'office365', 'onedrive'], domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'microsoftonline.com'] },
  { name: 'Google', words: ['google', 'gmail'], domains: ['google.com', 'gmail.com', 'youtube.com', 'goo.gl'] },
  { name: 'USPS', words: ['usps', 'postal service'], domains: ['usps.com'] },
  { name: 'FedEx', words: ['fedex'], domains: ['fedex.com'] },
  { name: 'DHL', words: ['dhl'], domains: ['dhl.com', 'dhl.de'] },
  { name: 'UPS', words: ['ups package', 'ups delivery', 'ups parcel', 'ups shipment'], domains: ['ups.com'] },
  { name: 'Royal Mail', words: ['royal mail'], domains: ['royalmail.com'] },
  { name: 'IRS', words: ['irs', 'internal revenue'], domains: ['irs.gov'] },
  { name: 'HMRC', words: ['hmrc'], domains: ['gov.uk'] },
  { name: 'Chase', words: ['chase bank', 'jpmorgan chase'], domains: ['chase.com'] },
  { name: 'Wells Fargo', words: ['wells fargo'], domains: ['wellsfargo.com'] },
  { name: 'Bank of America', words: ['bank of america'], domains: ['bankofamerica.com'] },
  { name: 'Instagram', words: ['instagram'], domains: ['instagram.com'] },
  { name: 'Facebook', words: ['facebook'], domains: ['facebook.com', 'fb.com', 'meta.com'] },
  { name: 'WhatsApp', words: ['whatsapp'], domains: ['whatsapp.com', 'wa.me'] },
  { name: 'Steam', words: ['steam account', 'steam wallet', 'steam support'], domains: ['steampowered.com', 'steamcommunity.com'] },
  { name: 'Coinbase', words: ['coinbase'], domains: ['coinbase.com'] },
];

const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'rb.gy', 'shorturl.at', 'ow.ly', 'buff.ly', 'rebrand.ly', 'tiny.cc', 's.id', 'qrco.de'];
const RISKY_TLDS = ['zip', 'mov', 'top', 'xyz', 'click', 'country', 'gq', 'tk', 'ml', 'cf', 'ga', 'work', 'support', 'rest', 'cam', 'icu', 'buzz', 'sbs', 'cfd'];
const TWO_LEVEL_SUFFIXES = ['co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'net.au', 'co.in', 'co.nz', 'co.jp', 'com.br', 'com.mx', 'co.za', 'com.sg'];

// Phrase rules: [regex, category]. Each category explains *why* the pattern matters.
const PHRASES = {
  urgency: {
    title: 'Pressure to act fast',
    explain: 'Scammers rush you so you act before you think. Real organisations rarely demand action within minutes or hours.',
    weight: 2,
    patterns: [
      /\b(?:urgent(?:ly)?|immediately|right away|act now|asap|final (?:notice|warning|reminder)|last chance)\b/gi,
      /\bwithin (?:the next )?\d{1,2} ?(?:hours?|hrs?|minutes?|mins?)\b/gi,
      /\b(?:expires?|ends?|closing) (?:today|tonight|soon)\b/gi,
      /\b(?:today|tonight) only\b/gi,
      /\b(?:call|reply|click|tap|respond|pay|verify|update|act) (?:us |me |here )?now\b/gi,
    ],
  },
  threat: {
    title: 'Threat of a penalty',
    explain: 'Messages that threaten suspension, fines, or arrest are designed to scare you. Check by contacting the organisation through its official app or website.',
    weight: 2,
    patterns: [
      /\b(?:account|card|access|service)s? (?:(?:has|have) been|will be|is|are) (?:suspended|locked|disabled|closed|terminated|restricted|frozen|blocked)\b/gi,
      /\b(?:suspended|locked|restricted|frozen) (?:account|card)\b/gi,
      /\b(?:legal action|arrest(?:ed)?|warrant|lawsuit|police|penalt(?:y|ies)|late fee)\b/gi,
      /\bunusual (?:sign-?in|login|activity)\b/gi,
      /\b(?:(?:has|have) been |is |are )(?:infected|hacked|compromised)\b/gi,
      /\bvirus(?:es)? (?:detected|found)\b/gi,
    ],
  },
  payment: {
    title: 'Asks you to send money',
    explain: 'Money sent by bank transfer, gift card, crypto or payment app is very hard to get back, which is why scammers ask for it this way. No real company or government takes payment in gift cards.',
    weight: 3,
    patterns: [
      /\b(?:gift ?cards?|itunes cards?|google play cards?|steam cards?|apple cards?)\b/gi,
      /\b(?:bitcoin|btc|crypto(?:currency)?|usdt|ethereum|wallet address)\b/gi,
      /\b(?:wire transfer|bank transfer|western union|moneygram|zelle|cash ?app|venmo)\b/gi,
      /\b(?:send|transfer|pay|lend) (?:me |us )?(?:£|\$|€|₹)\s?\d[\d,.]*/gi,
      /\b(?:pay|send|transfer) (?:a |the )?(?:small |one-?time )?(?:fee|deposit|processing fee|customs fee|redelivery fee)\b/gi,
    ],
  },
  credentials: {
    title: 'Asks for codes, passwords or account details',
    explain: 'Never share one-time codes, passwords, PINs or ID numbers. A real company will never ask for your verification code — sharing it hands over your account.',
    weight: 3,
    patterns: [
      // Mentioning a code is normal ("Your code is 123456 — don't share it"). Asking for one is the red flag.
      /\b(?:share|send|forward|tell|give|read|reply with|provide|confirm) (?:it |them )?(?:to )?(?:me |us )?(?:your |the |that |this )?(?:(?:verification|security|one-?time|login|whatsapp|6-digit) )?(?:codes?|passwords?|pins?|otp|login details|card (?:number|details)|bank details|ssn|social security number)\b/gi,
      /\b(?:what(?:'s| is) the code|code you (?:just )?(?:received|got))\b/gi,
      /\b(?:verify|confirm|update|validate) (?:your )?(?:account|identity|details|information|payment (?:details|method)|billing)\b/gi,
    ],
  },
  prize: {
    title: 'Too good to be true',
    explain: 'Surprise prizes, refunds or giveaways are a classic hook. If you did not enter, you did not win.',
    weight: 2,
    patterns: [
      /\b(?:you(?:'ve| have)? (?:won|been selected)|congratulations|claim your (?:prize|reward|gift|refund)|winner)\b/gi,
      /\b(?:free (?:iphone|gift|money|crypto)|cash prize|lottery|jackpot|inheritance)\b/gi,
      /\byou are (?:eligible|entitled) (?:for|to) (?:a )?(?:refund|rebate|compensation)\b/gi,
    ],
  },
  generic: {
    title: 'Generic greeting',
    explain: 'Companies you have an account with usually use your name. "Dear customer" suggests a message sent to thousands of people at once.',
    weight: 1,
    patterns: [/\bdear (?:customer|user|client|member|valued (?:customer|member|user)|account holder|sir\/madam|sir or madam)\b/gi],
  },
  delivery: {
    title: 'Fake delivery problem',
    explain: 'Fake "missed delivery" texts are one of the most common scams. Track parcels in the courier’s own app or by typing its website yourself.',
    weight: 2,
    patterns: [
      /\b(?:package|parcel|shipment|delivery) (?:is )?(?:on hold|could not be delivered|failed|pending|held|suspended|returned)\b/gi,
      /\b(?:incomplete|invalid|wrong|unconfirmed) (?:address|street address|delivery address)\b/gi,
      /\b(?:redelivery|reschedule (?:your )?delivery)\b/gi,
    ],
  },
  impersonation: {
    title: '"New number" or family emergency',
    explain: 'Scammers pretend to be a family member on a new number who urgently needs money. Call the person on the number you already have before doing anything.',
    weight: 3,
    patterns: [
      /\b(?:this is my new number|new number|lost my phone|broke my phone|phone (?:is )?broken)\b/gi,
      /\bhi (?:mum|mom|dad)\b/gi,
      /\b(?:i'?m in trouble|need (?:money|help) (?:urgently|now|fast))\b/gi,
    ],
  },
  secrecy: {
    title: 'Asks you to keep it secret',
    explain: 'Being told not to tell anyone — or not to contact your bank — is a strong sign of a scam. Talking to someone you trust is the best protection.',
    weight: 3,
    patterns: [/\b(?:don[’']?t|do not) (?:tell|inform|contact|call) (?:anyone|anybody|your bank|the bank|family|dad|mum|mom|your (?:dad|mum|mom|parents|partner|manager|boss))\b/gi, /\bkeep (?:this|it) (?:confidential|secret|between us)\b/gi],
  },
  remote: {
    title: 'Asks to control your device',
    explain: 'Requests to install remote-access apps let a stranger see and control your computer or phone. Real support teams do not cold-contact you to do this.',
    weight: 3,
    patterns: [/\b(?:anydesk|teamviewer|ultraviewer|quick ?support|remote (?:access|desktop|support))\b/gi],
  },
  job: {
    title: 'Easy-money job offer',
    explain: 'Unsolicited jobs paying a lot for simple tasks (liking videos, reviews, "tasks") usually end with you paying to withdraw "earnings".',
    weight: 2,
    stack: 3, // each distinct signal adds weight: one alone is weak, together they are the task-scam pattern
    // "work from home" alone is a normal job ad; these are the task-scam signatures
    patterns: [
      /\b(?:earn|make|get paid) (?:up to )?(?:\$|£|€|₹)\s?\d[\d,]*\+? (?:a|per|each|every) (?:day|hour|task)\b/gi,
      /\b(?:like|rate|review|subscribe to) (?:youtube |tiktok )?(?:videos|products|channels|hotels)\b/gi,
      /\bsimple (?:online )?tasks?\b/gi,
    ],
  },
};

// ---------- links ----------

const URL_RE = /\b((?:https?:\/\/)?(?:[a-z0-9¡-￿](?:[a-z0-9¡-￿-]{0,61}[a-z0-9¡-￿])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]+)(?::\d{2,5})?(?:\/[^\s<>"')\]]*)?|https?:\/\/\d{1,3}(?:\.\d{1,3}){3}(?::\d{2,5})?(?:\/[^\s<>"')\]]*)?)/gi;

/** Registrable domain (eTLD+1) for a hostname, using a small built-in suffix list. */
export const registrableDomain = (host) => {
  const h = host.toLowerCase().replace(/\.$/, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return h;
  const parts = h.split('.');
  if (parts.length <= 2) return h;
  const lastTwo = parts.slice(-2).join('.');
  if (TWO_LEVEL_SUFFIXES.includes(lastTwo)) return parts.slice(-3).join('.');
  return lastTwo;
};

const DIGIT_SWAPS = { 0: 'o', 1: 'l', 3: 'e', 4: 'a', 5: 's', 7: 't', 8: 'b' };
const normaliseLookalike = (s) =>
  s
    .toLowerCase()
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/[0134578]/g, (d) => DIGIT_SWAPS[d]);

export const editDistance = (a, b) => {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return dp[a.length][b.length];
};

const ALL_OFFICIAL = BRANDS.flatMap((b) => b.domains.map((d) => ({ brand: b.name, domain: d })));

/** Analyse one link. Returns issues as {title, explain, weight}. */
export const analyseLink = (raw, mentionedBrands) => {
  const issues = [];
  const withScheme = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
  let url;
  try {
    url = new URL(withScheme);
  } catch {
    return { raw, host: raw, domain: raw, issues };
  }
  const host = url.hostname.toLowerCase();
  const domain = registrableDomain(host);
  const label = domain.split('.')[0];
  const tld = domain.split('.').pop();
  const official = ALL_OFFICIAL.find((o) => o.domain === domain);

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    issues.push({ title: 'Link is a bare number address', explain: 'Real companies use names, not raw IP addresses, for their websites.', weight: 3 });
  }
  if (host.includes('xn--')) {
    issues.push({ title: 'Disguised characters in the address', explain: 'This address uses special characters that can look identical to normal letters.', weight: 3 });
  }
  if (url.username || /@/.test(raw.replace(/^https?:\/\//i, '').split('/')[0])) {
    issues.push({ title: 'Address contains “@”', explain: 'Everything before the "@" is ignored by your browser — the link really goes to what comes after it.', weight: 3 });
  }
  if (SHORTENERS.includes(domain) || SHORTENERS.includes(host)) {
    issues.push({ title: 'Shortened link hides the destination', explain: 'Link shorteners hide where you will end up. Don’t tap it; go to the company’s site yourself.', weight: 2 });
  }
  if (!official) {
    // brand name hidden in a subdomain or path: paypal.com.account-check.net
    // Compare whole tokens, so "redelivery" never matches "live".
    const prefix = host.slice(0, Math.max(0, host.length - domain.length));
    const outerTokens = (prefix + url.pathname).toLowerCase().split(/[.\-_/]+/).filter(Boolean);
    const brandLabel = (d) => d.split('.')[0];
    const hidden = BRANDS.find((b) => b.domains.some((d) => outerTokens.includes(brandLabel(d))));
    if (hidden) {
      issues.push({
        title: `“${hidden.name}” is only a disguise`,
        explain: `The real website here is ${domain}. “${hidden.name}” appears earlier in the address to make it look legitimate.`,
        weight: 3,
      });
    }
    // lookalike: paypa1.com, arnazon.com, netf1ix-help.com
    const labelTokens = label.split('-').filter(Boolean);
    const look = ALL_OFFICIAL.find((o) => {
      const ol = brandLabel(o.domain);
      if (ol.length < 3) return false;
      return labelTokens.some((t) => {
        if (t === ol) return true; // paypal-support.com
        const n = normaliseLookalike(t);
        if (n !== t && n === ol) return true; // paypa1, arnazon
        return ol.length >= 5 && editDistance(t, ol) === 1; // paypall, netflx
      });
    });
    if (look) {
      issues.push({
        title: `Look-alike of ${look.brand}`,
        explain: `“${domain}” is designed to look like ${look.domain}, but it is a different website.`,
        weight: 3,
      });
    }
    // message talks about a brand but links elsewhere
    const mismatch = mentionedBrands.find((b) => !b.domains.includes(domain));
    if (mismatch && !look && !hidden && !SHORTENERS.includes(domain)) {
      issues.push({
        title: `Link doesn’t go to ${mismatch.name}`,
        explain: `The message talks about ${mismatch.name}, but the link goes to ${domain}, which is not one of ${mismatch.name}’s websites.`,
        weight: 3,
      });
    }
    if (RISKY_TLDS.includes(tld)) {
      issues.push({ title: `Unusual ending “.${tld}”`, explain: `Addresses ending in “.${tld}” are cheap to register and often used for short-lived scam sites.`, weight: 1 });
    }
  }
  if (url.protocol === 'http:' && /^http:\/\//i.test(raw)) {
    issues.push({ title: 'Not a secure (https) link', explain: 'Pages that ask for logins should always start with https.', weight: 1 });
  }
  return { raw, host, domain, official: official?.brand ?? null, issues };
};

// ---------- main ----------

const mentionedBrandsIn = (text) => {
  const lower = text.toLowerCase();
  return BRANDS.filter((b) => b.words.some((w) => new RegExp(`\\b${w.replace(/ /g, '\\s+')}\\b`, 'i').test(lower)));
};

/**
 * @param {string} text
 * @returns {{score:number, level:'low'|'medium'|'high', findings:Finding[], links:ReturnType<typeof analyseLink>[], brands:string[], advice:string[]}}
 */
export const analyse = (text) => {
  const input = String(text ?? '').slice(0, 20000);
  const findings = [];
  for (const [category, rule] of Object.entries(PHRASES)) {
    const spans = [];
    let distinct = 0;
    for (const re of rule.patterns) {
      re.lastIndex = 0;
      const before = spans.length;
      for (const m of input.matchAll(re)) spans.push([m.index, m.index + m[0].length]);
      if (spans.length > before) distinct++;
    }
    if (!spans.length) continue;
    const weight = rule.stack ? rule.weight * Math.min(rule.stack, distinct) : rule.weight;
    findings.push({ id: category, category, title: rule.title, explain: rule.explain, weight, spans: mergeSpans(spans) });
  }

  const brands = mentionedBrandsIn(input);
  const links = [];
  for (const m of input.matchAll(URL_RE)) {
    const raw = m[1].replace(/[.,;:!?]+$/, '');
    // ignore things like "e.g." or file names without a known TLD shape
    if (!/\.[a-z]{2,}|xn--|\d{1,3}(\.\d{1,3}){3}/i.test(raw)) continue;
    if (/^[^/]*\.(?:png|jpe?g|pdf|docx?|txt)$/i.test(raw)) continue;
    const res = analyseLink(raw, brands);
    links.push({ ...res, span: [m.index, m.index + raw.length] });
  }
  for (const l of links) {
    for (const issue of l.issues) {
      findings.push({ id: `link:${l.domain}:${issue.title}`, category: 'link', title: issue.title, explain: issue.explain, weight: issue.weight, spans: [l.span] });
    }
  }

  // Compound signal: a pressure tactic AND a request for money/codes is the core scam shape.
  const has = (c) => findings.some((f) => f.category === c);
  const pressure = has('urgency') || has('threat') || has('impersonation') || has('secrecy');
  const ask = has('payment') || has('credentials') || has('remote') || links.some((l) => l.issues.length);
  let score = findings.reduce((s, f) => s + f.weight, 0);
  if (pressure && ask) score += 2;

  const level = score >= 6 ? 'high' : score >= 3 ? 'medium' : 'low';
  return { score, level, findings, links, brands: brands.map((b) => b.name), advice: adviceFor(findings, links, level) };
};

const mergeSpans = (spans) => {
  const s = spans.sort((a, b) => a[0] - b[0]);
  const out = [];
  for (const sp of s) {
    const last = out[out.length - 1];
    if (last && sp[0] <= last[1]) last[1] = Math.max(last[1], sp[1]);
    else out.push([...sp]);
  }
  return out;
};

const adviceFor = (findings, links, level) => {
  const has = (c) => findings.some((f) => f.category === c);
  const advice = [];
  if (links.some((l) => l.issues.length) || (links.length && level !== 'low'))
    advice.push('Don’t tap the link. If you think the message might be real, open the company’s app or type its website address yourself.');
  if (has('credentials')) advice.push('Never share a verification code, password or PIN — not even with someone claiming to be the company.');
  if (has('payment')) advice.push('Don’t send money, gift cards or crypto. Payments like these usually can’t be reversed.');
  if (has('impersonation')) advice.push('Call the person on the number you already have for them, or ask a question only they would know.');
  if (has('remote')) advice.push('Don’t install any app someone asks you to. If you already did, disconnect from the internet and get trusted help.');
  if (has('threat') || has('urgency')) advice.push('Slow down. Real problems can wait the few minutes it takes to check through an official channel.');
  if (has('secrecy')) advice.push('Talk to someone you trust before acting. Scammers ask for secrecy because talking to others stops scams.');
  if (level !== 'low') advice.push('Report it: forward scam texts to 7726 (US and UK carriers), and use the “Report phishing” option in your email app. Then delete it.');
  if (level === 'low')
    advice.push('No common warning signs found — but that doesn’t prove it’s safe. If the message asks you to do anything unexpected, check with the sender through a channel you already trust.');
  return advice;
};

export const _internals = { BRANDS, PHRASES };
