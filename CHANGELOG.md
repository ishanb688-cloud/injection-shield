# Changelog

## [0.2.0] - October 2026
### Added
- Scam Radar: a rule-based red-flag checker for bank-style messages, with an official-website check for look-alike links.
- Browser extension (experimental) that scans the current page on the device and can remove hidden text.
- Page descriptions and expected results for every demo page in the dashboard, with a visible "matches / differs" check.
- Automated test suite (pytest) and a GitHub Actions workflow.
- Logo and brand assets.
- Documentation: architecture, threat model and evaluation notes.

### Changed
- The "Inspect a page's source" box now loads the source of the page selected in the picker.
- Dashboard redesigned.

## [0.1.0] - October 2026
### Added
- Three-layer shield: hidden content detector, instruction language detector and output checker.
- Deliberately naive demo assistant and attack pages.
- Test runner with original and held-out sets, and a hosted dashboard that holds no API key.
