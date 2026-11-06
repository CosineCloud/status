# Status Dashboard

Flask status dashboard with tagged access, incident/message detail views, SSH alarm lifecycle and history, and configurable dial/progress metrics.

## Docker deployment

```bash
git clone https://github.com/CosineCloud/status.git
cd status
cp .env.example .env
```

Edit `.env` and set three different random values for `UPDATE_KEY`, `DASHBOARD_PIN`, and `FLASK_SECRET`. Generate a value with:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

```bash
docker compose up -d --build
```

Open `http://localhost:8000`. Admin: `/update`, using `UPDATE_KEY`. The initial dashboard key is `DASHBOARD_PIN`. Create additional keys and permissions under Access Keys.

SQLite data lives in the persistent `status-data` Docker volume. Rebuilding or recreating the container retains it; `docker compose down -v` deletes it. To migrate an existing installation, stop it and copy its `status_dash.sqlite` into the volume before the first start; keep the original backup. The database includes keys, SSH credentials, and configuration, so keep backups private.

Linux SSH metrics use the configured server credentials and a command that returns one number. RAM/CPU/temperature examples are available in the editor. Each metric has its own interval, range, units, colors, value visibility, and decimal precision. Failed samples retain the last successful value. Fresh readings show LIVE; stale readings show minutes/hours since the last successful sample.

Enable auto-fetch for SSH servers to reconcile active alarms and import recent readable system-journal warning/error events (last 24 hours, latest 100 per poll). Manual alarms move to History only through an explicit action. Forced Resolved alarms remain masked until the detected condition clears.

## Local development

Python 3.12 is recommended. Create `.env` as above, then:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

For an existing local installation, its `.env` retains the current keys. The legacy React frontend and `api.py` are not used by this Docker image.

## Source files

This repository contains only the Flask application and Docker runtime files:

- `main.py`
- `templates/dashboard.html`
- `templates/update.html`
- `requirements.txt`
- `Dockerfile`
- `docker-compose.yml`
- `.env.example`
- `.gitignore`
- `.dockerignore`
- `README.md`

Local databases, credentials, session cookies, tests, development notes, and the legacy React frontend are excluded.

Dashboard labels use stable random display IDs: three digits for monitors, messages, and incidents, and six digits for alarms. Database relationships continue using separate internal IDs. Popup backdrops blur the page. Choose **None** in a live metric's Display setting for raw multi-line SSH output without a dial or progress bar. The last successful output remains visible after failed checks.

Fresh metrics show an unfilled outlined LIVE badge. After the larger of one minute or the configured interval has elapsed, the label shows minutes or hours since the last successful sample. Numerical readings can be hidden or formatted to 0–6 decimal places.

## Useful commands

```bash
docker compose config --quiet
docker compose logs -f
docker compose up -d --build
docker compose down
```
