# ThreatLens AI 🛡️

A Flask-based cybersecurity dashboard with zero external APIs and zero databases. All analysis runs locally using rule-based intelligence.

## Features
- **Password Strength Analyzer** — Entropy scoring, crack-time estimates, actionable suggestions
- **Phishing URL Scanner** — Detects suspicious keywords, IP addresses, shorteners, fake brands
- **Email Phishing Detector** — Identifies urgency, threats, credential requests, and suspicious links
- **Cyber Knowledge AI** — 12+ topics with intent matching (no cloud AI required)
- **Security Quiz** — Random questions to test awareness

## Quick Start
```bash
pip install -r requirements.txt
python app.py
```
Open `http://localhost:5000`

## Tech Stack
- Flask + Jinja2 + Werkzeug
- Pure CSS dark cyber theme (no Tailwind build step)
- 100% local — no OpenAI, no Gemini, no database

## Deployment

**Vercel (Serverless):**
- Uses `api/index.py` as entry point
- Static files served via `vercel.json` routes

**Render.com:**
- Build: `pip install -r requirements.txt`
- Start: `gunicorn app:app`

**Local Development:**
```bash
start_app.bat   # Windows
python app.py   # Any OS
