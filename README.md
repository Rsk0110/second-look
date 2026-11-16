# Second Look

**A calm second opinion on a suspicious message, entirely on your device.**

Paste a text, email or DM you're unsure about. Second Look highlights the warning signs in place, explains each one in plain language, shows where every link *really* goes, and tells you what to do next.

## Who it helps

Anyone who gets a message that feels slightly off: a parcel text, an "account locked" email, a "Hi mum, new number" message. It's especially meant for people who don't think of themselves as technical, and for helping a parent or grandparent check something together.

## What it checks

| Warning sign | Example |
|---|---|
| Pressure to act fast | "within 24 hours", "final notice", "act now" |
| Threat of a penalty | "your account has been suspended", "legal action" |
| Asks you to send money | gift cards, crypto, bank transfer, "pay a small fee" |
| Asks for codes, passwords or account details | "send me the code", "verify your account" |
| "New number" or family emergency | "Hi mum, this is my new number" |
| Asks you to keep it secret | "don't tell anyone", "keep this confidential" |
| Asks to control your device | AnyDesk, TeamViewer |
| Fake delivery problem, too good to be true, easy-money jobs, generic greetings | |

**Links:** the real destination domain (`paypal.com.account-help.net` → `account-help.net`), look-alike spellings (`paypa1`, `arnazon`), links that don't match the brand the message claims to be from, disguised characters (punycode), shorteners, raw IP addresses and `@` tricks.

## Private by construction

- Runs entirely in the browser: no server, no accounts, no analytics.
- The page's Content Security Policy sets `connect-src 'none'` and `form-action 'none'`, so the browser itself refuses any attempt to send data.
- Works offline after the first visit (service worker).

## Honest limits

- It can't open links or check whether a website is dangerous right now.
- It recognises common tactics, not every scam. "No warning signs" is not a guarantee, and the app says so.
- It's guidance, not a replacement for your bank or provider.

## Run it

It's a static site with no build step.

```bash
python -m http.server 8000   # then open http://localhost:8000
npm test                     # engine tests (Node 20+)
```

## Built with

Plain HTML, CSS and JavaScript (ES modules). The detection engine is in `src/engine.js`, the synthetic practice messages in `src/examples.js`, and the tests in `test/`.

All example messages are invented. Phone numbers use reserved fictional ranges.

## AI disclosure

Built with Claude (Anthropic) as an AI coding assistant for design, code, tests and documentation.

## License

MIT
