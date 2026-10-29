# ThreatLens SOC

A defensive SOC analyst training platform with explainable detection rules, normalized synthetic telemetry, incident cases, and a responsive React + TypeScript dashboard.

The original GitHub repository was empty. A minimal README was used to initialize its default branch; all application code is proposed through this feature branch and draft pull request.

## Implemented

- FastAPI REST backend with SQLite persistence for repeatable, fully local demos
- Seeded analyst and viewer accounts with PBKDF2 salted password hashing and 2-hour signed tokens
- Role-based enforcement: analysts may ingest, triage and manage cases; viewers have read-only access
- JSON and CSV ingestion for authentication, endpoint, firewall and web events
- Deterministic detections: 5 login failures from 1 IP in 10 minutes, synthetic unusual-region login, encoded PowerShell, and a clearly labeled 5-distinct-denied-ports scan heuristic
- MITRE ATT&CK mappings: T1110, T1078 and T1059.001, each accompanied by an explicit detection rationale
- Alert queue, IOC search across local event fields, analyst notes, false-positive dispositions, investigation cases and Markdown report export
- Searchable event history and action audit records
- Reproducible synthetic dataset with 4 expected detection findings (brute force, labeled geo anomaly, encoded PowerShell, distinct denied ports) and benign records
- Detection unit tests and frontend TypeScript build in GitHub Actions

## Run locally

Requirements: Python 3.12+, Node.js 22+, npm.

1. From backend, create a Python virtual environment, install requirements with pip install -r requirements.txt.
2. Copy backend/.env.example to a local .env and export THREATLENS_SECRET as a random value of 32+ characters and THREATLENS_DEMO_PASSWORD as a demo password of 12+ characters. The environment variables must be exported to the backend process; the .env file is a template, not automatically loaded.
3. From backend run python seed.py to create the local database and synthetic telemetry.
4. From backend run uvicorn main:app --reload.
5. In a new terminal from frontend run npm install && npm run dev.
6. Open the Vite URL. Sign in as analyst or viewer using your demo password.

No external SIEM or threat intelligence subscription is needed. The local database is ignored by Git.

## API routes

- POST /api/auth/login
- GET /api/summary, GET /api/events, GET /api/alerts, GET /api/cases
- POST /api/ingest, POST /api/ingest/csv (analyst only)
- PATCH /api/alerts/:id, POST /api/cases, PATCH /api/cases/:id (analyst only)
- GET /api/cases/:id/report

## Validate

From backend run python -m pytest -q. From frontend run npm run build. CI executes both separately.

## Scope and limitations

The provided IPs come from documentation-only ranges. All attack indicators are synthetic. The system performs defensive analysis and does not execute attacks or contact external hosts.

SQLite was selected for a zero-infrastructure, repeatable local training application; replacing it with PostgreSQL is a future scaling task. This is not a production SIEM: no enterprise SSO, deployment, real-time log streaming, distributed queues, enrichment subscriptions, or ingestion quotas beyond per-file limits. Demo accounts must never be used with real log data.

## Portfolio description

Built a defensive mini-SIEM using Python, FastAPI, SQLite, React and TypeScript, featuring normalized log ingestion, deterministic authentication and endpoint detections, analyst triage, ATT&CK mapping and exportable investigation reports.

## IOC search and additional analyst workflows

Use the IOC Lookup page to search source IP, destination, process and summary fields. Detection rule `PORT_SCAN_HEURISTIC` maps 5 distinct denied destination ports from 1 source within 10 minutes to ATT&CK T1046 as a heuristic, not proof of compromise. Cases support status, analyst assignment and notes.

## Docker and browser QA

Copy `docker.env.example` to `.env` with local secrets, then run `docker compose up --build`. Open http://127.0.0.1:8082. All data stays in a local SQLite volume. CI checks detection rules, RBAC, actual Chromium SOC workflows, axe-core accessibility, Compose and container images. See [QA.md](QA.md).
