import { analyse } from './engine.js';
import { EXAMPLES } from './examples.js';

const $ = (sel, root = document) => root.querySelector(sel);
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') n.className = v;
    else if (k === 'style') n.style.cssText = v; // CSSOM, allowed by the strict CSP (style attributes are not)
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) n.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) n.append(kid.nodeType ? kid : String(kid));
  return n;
};

// ---------- navigation ----------
const views = ['check', 'practice', 'about'];
const show = (name) => {
  for (const v of views) $(`#view-${v}`).hidden = v !== name;
  for (const t of document.querySelectorAll('.tab')) {
    const on = t.dataset.view === name;
    t.classList.toggle('is-on', on);
    if (on) t.setAttribute('aria-current', 'page');
    else t.removeAttribute('aria-current');
  }
  if (name === 'practice' && !$('#quiz').childElementCount) renderQuiz();
  history.replaceState(null, '', name === 'check' ? location.pathname : `#${name}`);
};
for (const t of document.querySelectorAll('.tab')) t.addEventListener('click', () => show(t.dataset.view));

// ---------- result rendering ----------
const VERDICT = {
  high: { label: 'This looks like a scam', sub: 'Several warning signs that scams commonly use.', icon: '⚠' },
  medium: { label: 'Be careful', sub: 'Some warning signs. Check with the sender through a channel you already trust.', icon: '!' },
  low: { label: 'No common warning signs', sub: 'That doesn’t prove it’s safe — see the note below.', icon: '✓' },
};

/** Builds the message with <mark> elements for every finding span. */
const highlighted = (text, findings) => {
  const marks = [];
  findings.forEach((f, i) => f.spans.forEach(([a, b]) => marks.push({ a, b, i, link: f.category === 'link' })));
  marks.sort((x, y) => x.a - y.a || y.b - x.b);
  const out = el('div', { class: 'msg', tabindex: '0', 'aria-label': 'Your message with warning signs highlighted' });
  let pos = 0;
  for (const m of marks) {
    if (m.a < pos) continue; // overlapping: first one wins
    if (m.a > pos) out.append(text.slice(pos, m.a));
    out.append(el('mark', { class: m.link ? 'm link' : 'm', 'data-f': m.i }, text.slice(m.a, m.b)));
    pos = m.b;
  }
  out.append(text.slice(pos));
  return out;
};

const focusFinding = (i, on) => {
  for (const m of document.querySelectorAll(`mark[data-f="${i}"]`)) m.classList.toggle('lit', on);
  const card = document.querySelector(`.finding[data-f="${i}"]`);
  card?.classList.toggle('lit', on);
};

const renderResult = (text) => {
  const box = $('#result');
  box.replaceChildren();
  if (!text.trim()) {
    box.hidden = true;
    return;
  }
  const r = analyse(text);
  const v = VERDICT[r.level];
  // de-duplicate findings by title for the cards (several links can raise the same issue)
  const cards = [];
  r.findings.forEach((f, i) => {
    const existing = cards.find((c) => c.f.title === f.title);
    if (existing) existing.ids.push(i);
    else cards.push({ f, ids: [i] });
  });
  cards.sort((a, b) => b.f.weight - a.f.weight);

  box.append(
    el(
      'div',
      { class: `verdict ${r.level}`, role: 'status' },
      el('span', { class: 'verdict-icon', 'aria-hidden': 'true' }, v.icon),
      el('div', {}, el('h2', {}, v.label), el('p', {}, v.sub)),
      el('div', { class: 'meter', 'aria-label': `Warning level ${r.level}` }, el('span', { style: `--w:${Math.min(100, r.score * 8)}%` }))
    )
  );

  const left = el('div', { class: 'col' }, el('h3', {}, 'Your message'), highlighted(text, r.findings));
  if (r.links.length) {
    left.append(
      el('h3', {}, r.links.length === 1 ? 'Where this link really goes' : 'Where these links really go'),
      el(
        'ul',
        { class: 'links' },
        r.links.map((l) =>
          el(
            'li',
            { class: l.issues.length ? 'bad' : l.official ? 'ok' : '' },
            el('span', { class: 'dest' }, l.domain),
            el('span', { class: 'raw' }, l.raw),
            el('span', { class: 'tag' }, l.issues.length ? `${l.issues.length} warning${l.issues.length > 1 ? 's' : ''}` : l.official ? `Official ${l.official} site` : 'No warnings')
          )
        )
      )
    );
  }

  const right = el('div', { class: 'col' });
  if (cards.length) {
    right.append(
      el('h3', {}, `Warning signs (${cards.length})`),
      el(
        'ul',
        { class: 'findings' },
        cards.map(({ f, ids }) => {
          const li = el(
            'li',
            { class: `finding w${Math.min(3, f.weight)}`, 'data-f': ids[0], tabindex: '0' },
            el('strong', {}, f.title),
            el('p', {}, f.explain)
          );
          const on = () => ids.forEach((i) => focusFinding(i, true));
          const off = () => ids.forEach((i) => focusFinding(i, false));
          li.addEventListener('mouseenter', on);
          li.addEventListener('mouseleave', off);
          li.addEventListener('focus', on);
          li.addEventListener('blur', off);
          return li;
        })
      )
    );
  }
  right.append(el('h3', {}, 'What to do now'), el('ol', { class: 'advice' }, r.advice.map((a) => el('li', {}, a))));
  right.append(
    el(
      'p',
      { class: 'limits' },
      el('strong', {}, 'Good to know: '),
      'Second Look spots common tactics. It can’t open links or know every scam, so trust your instincts too. If you’ve already paid or shared details, contact your bank or provider now.'
    )
  );

  box.append(el('div', { class: 'grid' }, left, right));
  box.hidden = false;
  box.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
};

// marks → cards, too
document.addEventListener('mouseover', (e) => {
  const m = e.target.closest?.('mark[data-f]');
  if (m) focusFinding(m.dataset.f, true);
});
document.addEventListener('mouseout', (e) => {
  const m = e.target.closest?.('mark[data-f]');
  if (m) focusFinding(m.dataset.f, false);
});

$('#check-form').addEventListener('submit', (e) => {
  e.preventDefault();
  renderResult($('#msg').value);
});
$('#clear').addEventListener('click', () => {
  $('#msg').value = '';
  $('#result').hidden = true;
  $('#msg').focus();
});

const SAMPLE_IDS = ['parcel', 'bank-lock', 'mum', 'real-delivery'];
const SAMPLE_LABELS = { parcel: 'Parcel text', 'bank-lock': 'Account locked', mum: '“Hi mum”', 'real-delivery': 'A genuine email' };
$('#samples').append(
  ...SAMPLE_IDS.map((id) =>
    el(
      'button',
      {
        type: 'button',
        class: 'chip',
        onclick: () => {
          $('#msg').value = EXAMPLES.find((x) => x.id === id).text;
          renderResult($('#msg').value);
        },
      },
      SAMPLE_LABELS[id]
    )
  )
);

// ---------- practice ----------
let order = [];
let idx = 0;
let correct = 0;
const shuffle = (a) => {
  const b = a.slice();
  for (let i = b.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [b[i], b[j]] = [b[j], b[i]];
  }
  return b;
};

const renderQuiz = () => {
  const q = $('#quiz');
  if (!order.length) {
    order = shuffle(EXAMPLES);
    idx = 0;
    correct = 0;
  }
  q.replaceChildren();
  if (idx >= order.length) {
    q.append(
      el('h2', {}, `You got ${correct} of ${order.length}`),
      el('p', {}, correct === order.length ? 'Sharp eyes. You spotted every one.' : 'Every one you practise makes the real thing easier to spot.'),
      el('button', { class: 'btn primary', onclick: () => ((order = []), renderQuiz()) }, 'Practise again')
    );
    return;
  }
  const ex = order[idx];
  q.append(
    el('p', { class: 'progress' }, `Message ${idx + 1} of ${order.length} · ${correct} correct so far`),
    el('div', { class: 'phone' }, el('p', { class: 'from' }, ex.from), el('p', { class: 'bubble' }, ex.text)),
    el('p', { class: 'ask' }, 'Scam or genuine?')
  );
  const answer = (guess) => {
    const right = guess === ex.kind;
    if (right) correct++;
    const r = analyse(ex.text);
    q.querySelector('.choices').remove();
    q.append(
      el(
        'div',
        { class: `reveal ${right ? 'right' : 'wrong'}`, role: 'status' },
        el('h3', {}, right ? 'Correct!' : 'Not quite.', ' ', `This one is ${ex.kind === 'scam' ? 'a scam' : 'genuine'}.`),
        el('p', {}, ex.lesson),
        r.findings.length
          ? el('ul', { class: 'mini' }, [...new Set(r.findings.map((f) => f.title))].map((t) => el('li', {}, t)))
          : el('p', { class: 'small' }, 'Second Look found no warning signs here.'),
        el(
          'button',
          {
            class: 'btn primary',
            onclick: () => {
              idx++;
              renderQuiz();
              $('#quiz button')?.focus();
            },
          },
          idx + 1 < order.length ? 'Next message' : 'See my score'
        )
      )
    );
    q.querySelector('.reveal button').focus();
  };
  q.append(
    el(
      'div',
      { class: 'choices' },
      el('button', { class: 'btn danger', onclick: () => answer('scam') }, 'Scam'),
      el('button', { class: 'btn safe', onclick: () => answer('legit') }, 'Genuine')
    )
  );
};

// ---------- boot ----------
const fromHash = () => show(location.hash === '#practice' || location.hash === '#about' ? location.hash.slice(1) : 'check');
if (location.hash) fromHash();
addEventListener('hashchange', fromHash);
if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('sw.js').catch(() => {});
