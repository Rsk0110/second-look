import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyse, analyseLink, registrableDomain } from '../src/engine.js';
import { EXAMPLES } from '../src/examples.js';

const titles = (r) => r.findings.map((f) => f.title);

test('every scam example is high risk, every legit example is low', () => {
  for (const ex of EXAMPLES) {
    const r = analyse(ex.text);
    if (ex.kind === 'scam') assert.equal(r.level, 'high', `${ex.id} → ${r.level} (${r.score}) ${titles(r)}`);
    else assert.equal(r.level, 'low', `${ex.id} → ${r.level} (${r.score}) ${titles(r)}`);
  }
});

test('registrable domain', () => {
  assert.equal(registrableDomain('www.amazon.co.uk'), 'amazon.co.uk');
  assert.equal(registrableDomain('paypal.com.secure-login.net'), 'secure-login.net');
  assert.equal(registrableDomain('a.b.c.example.com'), 'example.com');
});

test('link checks', () => {
  const pp = [{ name: 'PayPal', words: ['paypal'], domains: ['paypal.com', 'paypal.me'] }];
  assert.deepEqual(analyseLink('https://www.paypal.com/signin', pp).issues, []);
  assert.match(analyseLink('paypa1-support.com/login', pp).issues.map((i) => i.title).join(), /Look-alike of PayPal/);
  assert.match(analyseLink('https://paypal.com.account-check.net/x', pp).issues.map((i) => i.title).join(), /PayPal” is only a disguise/);
  assert.match(analyseLink('https://example-billing.net', pp).issues.map((i) => i.title).join(), /doesn’t go to PayPal/);
  assert.match(analyseLink('bit.ly/3xYz', []).issues.map((i) => i.title).join(), /Shortened/);
  assert.match(analyseLink('http://192.168.4.20/login', []).issues.map((i) => i.title).join(), /bare number/);
  assert.match(analyseLink('https://xn--pypal-4ve.com', []).issues.map((i) => i.title).join(), /Disguised characters/);
  assert.match(analyseLink('https://accounts.google.com@evil.example/', []).issues.map((i) => i.title).join(), /“@”/);
  assert.match(analyseLink('arnazon-orders.com', []).issues.map((i) => i.title).join(), /Look-alike of Amazon/);
});

test('highlights point at the right words', () => {
  const text = 'Send me the code now. Pay with gift cards.';
  const r = analyse(text);
  const pay = r.findings.find((f) => f.category === 'payment');
  assert.equal(text.slice(...pay.spans[0]), 'gift cards');
});

test('ordinary text has no findings', () => {
  for (const t of ['See you at 7 for dinner!', 'The meeting notes are in the shared doc.', 'Apple pie recipe: 3 apples, sugar, butter.', 'Thanks for the steam iron, mum']) {
    const r = analyse(t);
    assert.equal(r.findings.length, 0, `${t}: ${titles(r)}`);
  }
});

test('handles empty and huge input', () => {
  assert.equal(analyse('').level, 'low');
  assert.equal(analyse(null).level, 'low');
  const big = 'urgent '.repeat(10000);
  const t0 = Date.now();
  analyse(big);
  assert.ok(Date.now() - t0 < 1500);
});
