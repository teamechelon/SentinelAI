# SentinelAI

SentinelAI is an explainable behavioural threat-detection prototype for identity, device, privilege, and file-activity events. The initial architecture is a local modular monolith using Python, Streamlit, SQLite, and scikit-learn.

The repository contains a working local prototype with deterministic synthetic data, personal and department/role peer behaviour profiles, feature engineering, Isolation Forest anomaly ranking, explainable rules, hybrid risk scoring, SQLite persistence, simulations, tests, and a Streamlit SOC interface.

## Quick start

Requires Python 3.11 or newer.

```bash
python3.11 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/python scripts/initialize_demo.py --reseed
.venv/bin/streamlit run app.py
```

Run the complete test suite with:

```bash
.venv/bin/pytest
```

The database is created at `data/sentinel_ai.db`. It is local runtime state and is ignored by Git.

## Demo deployment database initialization

API deployments do not seed data by default. To initialize the existing deterministic SentinelAI dataset when—and only when—the configured database has no employees, set:

```bash
SENTINEL_BOOTSTRAP_DEMO_DATA=true
```

Startup is idempotent: an already-populated database is preserved, including Attack Lab runs and their linked events. The bootstrap calls the same `generate_dataset()` and detection pipeline used by local development; it does not insert MITRE mappings. MITRE stories and graph findings continue to be derived at request time from seeded events, detections, alerts, sequences, and graph relationships.

For Render, mount a persistent disk and set `SENTINEL_DATABASE_PATH` to a file on that mount (for example `/var/data/sentinel_ai.db`). Without a persistent disk, Render filesystem state is ephemeral and the empty database will be recreated and bootstrapped after a replacement instance starts. Keep `SENTINEL_BOOTSTRAP_DEMO_DATA` unset or `false` for non-demo production environments.

## Simulated containment

The response policy consumes the already-persisted production risk score. By default, a score at the configured maximum triggers an internal block and session revocation:

```bash
AUTO_CONTAINMENT_ENABLED=true
AUTO_CONTAINMENT_RISK_THRESHOLD=100
```

Current containment uses `SimulationContainmentAdapter`. It changes only SentinelAI's persisted demonstration state and append-only response audit history; it does not disable an enterprise account, revoke real identity-provider tokens, isolate endpoints, or call an external service. The adapter interface is the future integration boundary for an authenticated and authorized enterprise IAM provider.

## Repository layout

```text
.
├── artifacts/              # Generated model and evaluation artifacts (not source)
├── config/                 # Versioned model, rule, and scenario configuration
├── data/
│   ├── raw/                # Imported source data; ignored by Git
│   ├── processed/          # Rebuildable normalized/feature data; ignored by Git
│   └── synthetic/          # Small deterministic demo fixtures safe to version
├── docs/
│   ├── architecture/       # Architecture decisions and contracts
│   └── research/           # Evidence-backed technical research
├── scripts/                # Explicit developer and demo entry points
├── app.py                  # Streamlit entry point
├── pyproject.toml          # Package metadata and dependencies
├── src/sentinel_ai/
│   ├── domain/             # Typed events, alerts, evidence, enums, reason codes
│   ├── ingestion/          # Validation and normalization of incoming events
│   ├── storage/            # SQLite connections, migrations, and repositories
│   ├── features/           # Prior-only windows and feature extraction
│   ├── baselines/          # Personal, peer, and global behavior profiles
│   ├── models/             # Replaceable anomaly-detector interfaces/adapters
│   ├── detection/          # Rules, sequences, risk fusion, and explanations
│   ├── services/           # Application orchestration/use cases
│   ├── demo/               # Seeded scenarios and replay support
│   └── ui/                 # Streamlit rendering backed by services
└── tests/
    ├── unit/               # Pure scoring, feature, rule, and travel tests
    ├── integration/        # SQLite and service-boundary tests
    ├── scenarios/          # End-to-end deterministic attack stories
    └── fixtures/           # Shared test-only data
```

## Dependency boundaries

- `domain` contains shared types and must not import infrastructure or UI code.
- `ingestion`, `features`, `baselines`, `models`, and `detection` implement focused domain capabilities.
- `services` coordinates those capabilities and is the only layer the UI should call.
- `storage` owns SQLite details; SQL must not leak into models, detection logic, or Streamlit pages.
- `ui` renders persisted/service data and must not invent alerts or model scores.
- `demo` generates deterministic inputs, never alternate scoring behavior.

The research basis for this structure is in `docs/research/threat-detection-research.md`.

## Detection design

- Profiles are calculated from historical normal events only; current events are not added to their own baseline.
- One global Isolation Forest uses a fixed feature order, preprocessing pipeline, random seed, and empirical normal-history percentile.
- The percentile is a relative anomaly rank, not an attack probability.
- Deterministic rules return a contribution, observed value, expected value, and readable reason.
- The final 0–100 score is the capped sum of rule, AI, and contextual-correlation contributions.
- Responses are recommendations and simulations only; the application performs no destructive security action.
