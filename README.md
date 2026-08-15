# Minimal-IDS

A lightweight **Intrusion Detection System (IDS)** backend built with FastAPI for educational use, experimentation, and university project demonstrations.

## Features

- JWT-based authentication (`/login`, `/logout`, `/protected`)
- In-memory threat scoring engine with automatic score accumulation
- Threshold-based user blocking workflow
- Request-level intrusion checks for:
  - SQL Injection
  - XSS Injection
  - Command Injection
  - High request rate / abuse patterns
- Overseer (admin) API routes for monitoring users and threat events

> **Note:** This project intentionally uses in-memory state for simplicity and rapid demonstration.

## Project Structure

```text
Minimal-IDS/
├── detectors/                  # Intrusion detectors by layer
├── routers/                    # API routers (overseer/admin tools)
├── tests/                      # Unit tests
├── .github/workflows/tests.yml # CI test workflow
├── config.py                   # Config constants and threat definitions
├── main.py                     # FastAPI application entry point
├── scoring_engine.py           # Threat scoring and block state logic
└── state.py                    # In-memory runtime stores
```

## Tech Stack

- Python 3.11+
- FastAPI
- Uvicorn
- Pydantic
- PyJWT
- Pytest (for tests)

## Getting Started

### 1) Clone and enter the repository

```bash
git clone https://github.com/Him99224/Minimal-IDS.git
cd Minimal-IDS
```

### 2) Create and activate a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
```

### 3) Install dependencies

```bash
pip install -r requirements.txt
pip install pytest
```

### 4) Configure environment

```bash
cp .env.example .env
```

Update values as needed for your environment.

### 5) Run the application

```bash
uvicorn main:app --reload
```

The API will be available at:

- `http://127.0.0.1:8000`
- Swagger docs: `http://127.0.0.1:8000/docs`

## Threat Scoring Model

Threat points are defined in `config.py` and accumulated per user. Current thresholds:

- **0 to 30**: No action
- **31 to 60**: Flag for overseer review
- **61+**: Auto-block user (implemented in scoring engine)

Additionally, score decay is applied at **50% per full 24 hours** since the user's last event.

## Testing

Run unit tests with:

```bash
pytest -q
```

Current tests target:

- Threat recording and point accumulation
- Unknown threat validation
- Auto-block transitions
- Score decay behavior
- User summary ordering
- State reset utilities (`unblock_user`, `clear_user_threats`)

## CI/CD

GitHub Actions is configured in `.github/workflows/tests.yml` to:

- Trigger on pushes and pull requests
- Set up Python 3.11 and 3.12
- Install dependencies
- Execute test suite with `pytest`

## Environment Variables

A template is provided in `.env.example`. Example variables include:

- `SECRET_KEY`
- `ALGORITHM`
- `ACCESS_TOKEN_EXPIRE_MINUTES`
- `WINDOW_SECONDS`
- `REQUEST_LIMIT`


## Future Scope

Potential next improvements for this project include:

- Move from in-memory runtime state to a persistent datastore (e.g., PostgreSQL/Redis) for production durability.
- Add network-level packet capture integrations (e.g., with Scapy/Zeek) to correlate API abuse with transport/session anomalies.
- Introduce role-based access control and audit trails for overseer actions.
- Add adaptive risk scoring (per-user baselines, anomaly detection, and model-assisted scoring).
- Export observability metrics and traces (Prometheus/OpenTelemetry + Grafana dashboards).
- Support configurable response policies (alert-only, soft block, hard block, and temporary quarantine windows).
- Add containerized deployment templates (Docker Compose/Kubernetes) with horizontal scaling guidance.
- Expand test coverage with integration and load tests to validate detection quality under realistic traffic.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file.
