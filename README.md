# 🛡️ Minimal-IDS

A modular **Intrusion Detection System (IDS)** built with FastAPI that simulates **API-layer security mechanisms** such as request inspection, threat detection, behavioral scoring, and adaptive access control.

---

## 🚀 Overview

Minimal-IDS is a **backend security system prototype** designed to monitor incoming API requests, detect malicious patterns, and dynamically respond based on user behavior.

It demonstrates concepts used in real-world systems such as:

* Web Application Firewalls (WAF)
* API Gateways with security filters
* Zero-trust backend architectures

---

## ⚙️ Features

* 🔐 JWT-based authentication (`/login`, `/logout`, `/protected`)
* 🧠 Threat scoring engine with accumulation + decay
* 🚫 Automatic user blocking based on thresholds
* 🛡️ Multi-layer intrusion detection:

  * SQL Injection
  * XSS Injection
  * Command Injection
  * Brute Force Attacks
  * Session Hijacking
  * High request rate / abuse patterns
* 📡 Real-time monitoring via WebSockets
* 🧑‍💼 Overseer (admin) APIs for monitoring users and threats

---

## 🔄 Request Processing Flow

1. Incoming request intercepted via FastAPI middleware
2. Rate limiting and payload inspection applied
3. Session-level and payload-level detectors executed
4. Threat events recorded in the scoring engine
5. User score updated (with decay over time)
6. User flagged or blocked based on thresholds
7. Events streamed to dashboard in real-time

---

## 🔍 Detection Engine

The IDS uses a **multi-layer detection approach** combining session-level and payload-level analysis.

### 🧠 Session Layer

* **Brute Force Detection**
  Triggered after repeated failed login attempts

* **Session Hijacking Detection**
  Detects IP changes within an active session

### 📡 Transport / Payload Layer

* **SQL Injection**
  Regex-based signature matching (e.g., `' OR 1=1`, `UNION SELECT`)

* **XSS Injection**
  Detection of script tags and malicious HTML payloads

* **Command Injection**
  Shell operators and system command patterns (`;`, `&&`, `|`, `/bin/sh`)

* **Rate Abuse Detection**
  Sliding window request rate monitoring

📌 Payloads are URL-decoded before inspection to detect **obfuscated attacks**.

All detection modules are modular and located in the `detectors/` directory.

---

## ⚠️ Example Detection

```http
POST /login
Payload: {"username": "admin' OR 1=1 --"}
```

**System Behavior:**

* Detected: SQL Injection
* Threat Score: Increased
* Action: User flagged or blocked (based on threshold)

---

## 🧠 Threat Scoring Model

Threat points are defined in `config.py` and accumulated per user:

* **0–30** → No action
* **31–60** → Flag for review
* **61+** → Auto-block

📉 Score decay:

* 50% reduction every 24 hours since last activity

---

## 🏗️ System Perspective

This project simulates an **API-layer intrusion detection system**, focusing on:

* Real-time request interception
* Behavioral risk scoring
* Adaptive access control

It reflects design patterns used in:

* WAFs (Web Application Firewalls)
* API security gateways
* Zero-trust systems

---

## 🔑 Demo Accounts

The system includes predefined users for testing:

| Username | Password    | Role     |
| -------- | ----------- | -------- |
| alice    | password123 | user     |
| bob      | password123 | user     |
| admin    | adminpass   | overseer |

> Note: Credentials are hardcoded for demonstration purposes. See `main.py` for details.

---

## 📡 Real-Time Events (WebSocket)

Connect to the live event stream:

```
ws://127.0.0.1:8000/ws/events
```

Streams real-time threat events for monitoring dashboards.

---

## ⚙️ Middleware Behavior

* IDS checks are applied via middleware to incoming requests
* Certain routes are intentionally excluded:

  * `/api/` (dashboard APIs)
  * `/demo/` (simulation routes)
  * `/static`, `/docs`, `/ws/`

This ensures internal system operations and monitoring endpoints are not affected by intrusion checks.

---

## 🧱 Project Structure

```
Minimal-IDS/
├── detectors/                  # Session & payload-level detection logic
├── routers/                    # API routers (overseer/admin tools)
├── tests/                      # Unit tests
├── config.py                   # Threat definitions and constants
├── main.py                     # FastAPI app + middleware pipeline
├── scoring_engine.py           # Threat scoring and blocking logic
└── state.py                    # In-memory runtime state
```

---

## 🛠️ Tech Stack

* Python 3.11+
* FastAPI
* Uvicorn
* Pydantic
* PyJWT
* Pytest

---

## ▶️ Getting Started

```bash
git clone https://github.com/Him99224/Minimal-IDS.git
cd Minimal-IDS

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -r requirements.txt
cp .env.example .env

uvicorn main:app --reload
```

* API: http://127.0.0.1:8000
* Docs: http://127.0.0.1:8000/docs

---

## 🧪 Testing

```bash
pytest -q
```

Covers:

* Threat scoring and accumulation
* Auto-block transitions
* Score decay behavior
* State reset utilities

---

## ⚖️ Design Tradeoffs

* **In-memory state**
  Used for simplicity and fast prototyping; not suitable for distributed systems

* **IP-based fallback for unauthenticated users**
  May group multiple users behind the same NAT/proxy

* **Token blacklist cleanup**
  Performed opportunistically (no background worker) to keep implementation simple

* **Demo credentials & secrets**
  Hardcoded for demonstration; should be externalized in production systems

---

## 🚧 Design Evolution

This project started as a simple rule-based IDS prototype, but evolved into a **modular backend security system** with:

* Middleware-based request interception
* Layered detection architecture
* Behavioral scoring with decay
* Real-time monitoring and observability

---

## 🔮 Future Scope

* Persistent storage (PostgreSQL / Redis)
* ML-based anomaly detection
* Advanced rate limiting strategies
* Observability (Prometheus + Grafana)
* Containerized deployment (Docker / Kubernetes)

---

## 📄 License

MIT License
