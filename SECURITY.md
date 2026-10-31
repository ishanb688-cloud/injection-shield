# Security policy

Injection Shield is a research prototype, not a certified security product. Treat it as one layer of defense, never the only one.

## Reporting a problem

- **A way to bypass the shield:** please open a GitHub issue titled "Bypass:" with the page or message that gets through. Bypasses are expected (see `docs/THREAT_MODEL.md`), and good reports make the project better.
- **A vulnerability in the dashboard, API or extension:** use GitHub's private vulnerability reporting (Security tab, "Report a vulnerability") so the details are not public before a fix exists.

## What is and is not in this repository

- The only secret token in the project, `FAKE-TOKEN-7731-DEMO`, is fake and exists for demonstration.
- No API keys are stored here. `.env` is ignored by Git, and the hosted dashboard runs without any key.
- The dashboard never fetches web addresses on a visitor's behalf and stores nothing that visitors paste.
- The browser extension runs on the device and makes no network requests.

## Supported versions

Only the latest commit on `main` is supported.
