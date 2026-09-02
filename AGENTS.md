# Agent Instructions for AntiPhishing_Project

## Project Overview
Single-file Flask app (`app.py`) that detects phishing URLs via **heuristic scoring + Random Forest ML model**. UI text and code comments are in **Bahasa Indonesia** — match that convention when editing.

## Key Commands
- **Run**: `python app.py` → Flask dev server on `localhost:5000` (debug mode, hardcoded)
- **Install deps**: `pip install -r requirements.txt`
- **Database**: `phishing_logs.db` auto-created on first run; schema auto-migrated via `migrate_db()`
- **ML model**: `phishing_model.pkl` auto-trained on first run if missing (synthetic dataset)
- **No tests, no lint, no typecheck, no CI.**

## Architecture (single file)
Everything lives in `app.py`:
- `resolve_url()` — unshortens URLs (20 shortener domains)
- `extract_features_and_score()` — 14-indicator heuristic scoring engine
- `extract_ml_features()` — 19 lexical/structural features for ML model
- `predict_ml()` — Random Forest classification (probability 0-1)
- `calculate_final_score()` — combines heuristic + ML: `0.5 * heuristic + 0.5 * ml_confidence * 100`
- `process_and_save_scan()` — orchestrates full scan + SQLite persistence
- WHOIS lookup (`get_domain_age()`) + SSL cert check (`check_ssl_cert()`) — both with 5s timeout

## Scoring System
- **Heuristic score** (0-100): 14 rule-based indicators (IP address, HTTPS, keywords, TLD, WHOIS age, SSL cert, etc.)
- **ML score** (0-100): Random Forest trained on 1200 synthetic samples (19 features)
- **Combined score**: 50/50 weighted average → thresholds: ≥60 = BAHAYA, ≥30 = WASPADA, <30 = AMAN

## Endpoints
| Route | Method | Notes |
|---|---|---|
| `/` | GET/POST | Main scan form (POST triggers scan) |
| `/scan` | GET/POST | GET redirects to `/`; POST triggers scan |
| `/feedback` | POST only | Updates `user_feedback` in DB, redirects to `/admin` |
| `/admin` | GET | Shows last 50 scan logs (with ML/heuristic breakdown) |
| `/api/scan` | POST | Legacy JSON API, accepts `{"url": "..."}` |
| `/api/v1/scan` | POST | REST API v1, returns `model_version`, `timestamp`, `error` fields |

## DB Schema (`scan_logs`)
`id`, `input_url`, `final_url`, `risk_score`, `status`, `reasons` (JSON), `user_feedback`, `client_ip`, `user_agent`, `ml_confidence` (REAL), `heuristic_score` (INT), `created_at`

## Gotchas
- **SSL verification disabled globally** (`urllib3.disable_warnings`) — required for URL unshortening
- **`.gitignore`** exists — ignores `*.db`, `*.pkl`, `.venv/`, `__pycache__/`
- **WHOIS lookup cached** (`_whois_cache`) to avoid repeated slow network calls; skipped for IP-address hostnames
- **ML model trained on synthetic data** — retrain by deleting `phishing_model.pkl`; accuracy ~100% on synthetic but real-world performance differs
- `reasons` stored as **JSON strings** in SQLite (via `json.dumps`)
- WHOIS and SSL checks have 5s timeouts — they silently fail on network issues
- API endpoints use `request.get_json(silent=True)` — a request with no JSON body returns `400` (not `415`)
- `/feedback` is **POST-only** and validates `scan_id` (must be int) before updating the DB

## Conventions
- Heuristic features go in `extract_features_and_score()`; ML features in `extract_ml_features()`
- New suspicious keywords → `SUSPICIOUS_KEYWORDS`; new TLDs → `SUSPICIOUS_TLDS`
- ML feature order is defined in `ML_FEATURE_NAMES` — must stay consistent between training and prediction
- Templates in `templates/`, static assets in `static/`
- Schema changes: update `init_db()` + add migration in `migrate_db()`
