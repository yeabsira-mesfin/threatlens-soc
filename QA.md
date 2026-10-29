# ThreatLens SOC quality assurance

## Automated verification

Backend: cd backend && python -m pytest -q. Browser: cd frontend && npm run test:e2e.

The CI workflow runs browser tests using actual Chromium, captures desktop and mobile screenshots, and uploads traces/screenshots as GitHub Actions artifacts. Axe-core audits WCAG 2.0/2.1 A/AA serious and critical findings. The workflow also validates and builds the local Docker Compose images.

Covered end-to-end: Synthetic log parsing, role-restricted ingestion, deterministic alerts, analyst triage, false positives, IOC search, case notes, case reports, ATT&CK mappings and multi-port scan heuristics.

### Local containers

Copy docker.env.example to .env, replace placeholders, then run docker compose up --build. Visit http://127.0.0.1:8082.

### Browser regression command

cd frontend && npm run test:e2e

### Review before merge

- Confirm the latest GitHub Actions run is green, including browser tests, accessibility and Compose build.
- Review the Playwright HTML report and saved desktop/mobile screenshots for clipping and contrast.
- Test keyboard navigation and screen-reader announcements manually. Automated axe does not replace human accessibility testing.
- Exercise invalid inputs, role boundaries, duplicate records, capacity races, stale sessions, and network errors.
- Check the work from a clean clone and verify no tokens, real attendee data or payment cards are committed.
- Run a qualified security assessment before considering any production deployment.

## Boundaries and known limitations

Only owned synthetic data or explicitly authorized lab logs. No real-time cloud SIEM streaming, commercial threat-intelligence feeds, enterprise SSO, or production incident response claims. Local SQLite persistence.

**Status:** An actively developed review-branch portfolio demonstration, not production certified. Automated checks are evidence of specific tested behaviors only, not proof of comprehensive security or browser compatibility.
