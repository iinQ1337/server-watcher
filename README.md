# Monitoring Service & Dashboard

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://www.python.org/) [![Node](https://img.shields.io/badge/Node-18%2B-339933?logo=node.js)](https://nodejs.org/) [![Docker](https://img.shields.io/badge/Docker-CLI-blue?logo=docker)](https://www.docker.com/)

Python daemon that continuously checks APIs, web pages, servers, networks, databases, queues, Docker, sensitive paths, and writes JSON snapshots to `output/`. A Next.js dashboard reads the snapshots and renders live panels.

## Table of Contents
- [Features](#features)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Runtime Output](#runtime-output)
- [Dashboard](#dashboard)
- [Supervisor](#supervisor)
- [Testing](#testing)
- [Project Structure](#project-structure)

## Features
- **Health Checks:** API endpoints, web pages, server resources, dependency versions (Python/Node), DNS/WHOIS, network (ports/TCP/SMTP/TLS), log analysis, sensitive paths, databases (MySQL/PostgreSQL), queues (Redis/RabbitMQ).
- **Streams for UI:** Docker containers/nodes/events, database summary & backups, task-manager snapshot (CPU/mem/top processes), queue reachability.
- **Process Supervisor:** Runs external commands with restart policy, captures stdout/stderr to JSON (and TXT if enabled).
- **Notifications:** Telegram/Discord with templates, tags, retries, per-event filtering.
- **Reports:** Combined `report_<timestamp>.json` and per-site reports.

## Checks in Detail
- **API (`checker/api_checker.py`):** HTTP methods, headers/auth (Bearer), timeouts, JSON validation with schema keys, response preview, optional full-response logging and saving to file.
- **Pages (`checker/page_checker.py`):** Status/redirect chains, title/meta snapshot, must_contain/must_not_contain, perf warnings (slow response), security hints (HSTS, HTTPS redirect, gzip), robots/sitemap probes.
- **Server (`checker/server_checker.py`):** CPU/memory/disk vs thresholds, per-mount disk health, uptime humanized, basic net counters.
- **Versions (`checker/version_checker.py`):** pip list vs PyPI (updates/major updates), Node deps via `npm ls` and registry checks, stats per ecosystem.
- **Logs (`checker/log_checker.py`):** Tail of configured files, count ERROR/WARNING/CRITICAL, collect last error lines, failed/missing files.
- **DNS (`checker/dns_checker.py`):** DNS records per type, WHOIS info, domain status (ok/expiring/expired), error capture.
- **Network (`checker/net_checker.py`):** Port reachability, TCP payload/expect matching, SMTP EHLO/STARTTLS/LOGIN/NOOP, TLS cert issuer/SAN/days_remaining with warn/expired flags.
- **Sensitive Paths (`checker/sensitive_paths_checker.py`):** Probe base_urls × known sensitive files/folders with treat_401/403_as_exposed flags, counts exposed/errors.
- **Databases (`checker/database_checker.py`):** MySQL (aiomysql) and Postgres (asyncpg) connect/version/test_query timings; unsupported types surfaced as errors.
- **Queues (`checker/queue_checker.py`):** Redis (aioredis) PING/info/DB size/queue length; RabbitMQ (aio_pika) passive queue declare and stats.

## Streams in Detail (Dashboard Data)
- **Docker Stream (`monitoring/docker_stream.py`):** Containers/nodes/events via Docker CLI, CPU/mem stats (with optional psutil enrich), summary counts, writes `output/docker_stream.json`.
- **Database Stream (`monitoring/database_stream.py`):** Periodic `check_databases`, alerts/backups loading, optional auto-backup (mysqldump/pg_dump) with history, writes `output/database_stream.json`.
- **Task Manager Stream (`monitoring/task_manager.py`):** CPU/mem history, per-core/load_avg, top processes (pid/user/cmd/cpu/mem), writes `output/task_manager_stream.json`.
- **Queue Stream (`monitoring/queue_stream.py`):** TCP reachability and Redis PING for configured queues/endpoints, writes `output/queue_stream.json`.

## Notifications (Telegram/Discord)
- Located in `utils/notifier.py`.
- Message rendering with simple `{{placeholder}}` templates, common tags, retries.
- Channel-level `notify_on` filtering per event type (e.g., api_failures, tls_expiry, server_alerts, system_error).
- HTTP helpers with debug/warn/error logging; safe no-op when disabled.

## Reports & Logging
- **Reports:** `output/report_<ts>.json` aggregates all enabled checks; per-site reports under `output/<hostname>/`. TXT reports optional via `output.text_format`.
- **Logging:** `utils/logger.py` sets rotating file and console handlers, captures warnings and unhandled exceptions. Log format/level/file set in `config.yaml`.
- **Per-module logs:** All check/stream modules use structured log messages for start/end/error stats; supervisor logs stdout/stderr to `_latest.json` (and `.log` when enabled).

## Architecture
- **Daemon:** `main.py` orchestrates checks and writes reports to `output/`.
- **Streams:** Background threads under `monitoring/` write dashboard JSON snapshots.
- **Supervisor:** `monitoring/supervisor.py` manages external processes and logs.
- **Dashboard:** Next.js app in `admin-dashboard/` consumes snapshots from `output/`.

## Getting Started
```bash
# Python env
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run daemon
python main.py
```

### Prerequisites
- Python 3.10+
- Docker CLI (for Docker stream)
- `mysqldump` / `pg_dump` if DB auto-backups enabled
- Node 18+ to run the dashboard (optional)

## Configuration
Main settings live in `config.yaml`.

### Logging & Output
```yaml
logging: { level: DEBUG, file: monitoring.log, console: true }
output:  { directory: output, json_format: true, text_format: false }
```

### Supervisor (single + multiple processes)
```yaml
supervisor:
  enabled: true
  log_directory: output/supervisor
  command:                     # single process
    executable: "python"
    args: ["app.py"]
    working_dir: "/path/to/app"
    env: { APP_ENV: "prod" }
  restart_policy:
    mode: "always"             # always | on-failure | never
    restart_delay_seconds: 5
    max_restarts_per_minute: 10
  processes:                   # optional list of additional processes
    - name: "supervised-task"
      enabled: true
      command: { executable: "node", args: ["server.js"], working_dir: "/path/to/server" }
      restart_policy: { mode: "always", restart_delay_seconds: 5 }
```

### Streams & Checks
- Streams: `dashboard.docker_stream`, `dashboard.databases_stream` (intervals, thresholds, backup options), `task_manager`, `queue_monitoring`.
- Checks: `api_monitoring`, `page_monitoring`, `server_monitoring`, `version_monitoring` (Python/Node), `log_monitoring`, `dns_monitoring`, `network_monitoring`, `sensitive_paths_monitoring`, `security_monitoring`.

### Notifications
```yaml
notifications:
  enabled: true
  common: { tags: ["prod"], retry_attempts: 2 }
  telegram: { enabled: true, bot_token: "...", chat_id: "..." }
  discord:  { enabled: false, webhook_url: "" }
```

## Runtime Output
- `output/report_<ts>.json` — combined results of all checks (+ `.txt` if enabled).
- Streams: `task_manager_stream.json`, `docker_stream.json`, `database_stream.json`, `queue_stream.json`.
- Backups: `output/db_backups/`, `output/database_backups_history.json`.
- Supervisor: `output/supervisor/<name>/*_latest.json` (stdout/stderr snapshots; `.log` if `text_format: true`).

## Dashboard
Next.js app reading JSON snapshots from `output/`.
```bash
cd admin-dashboard
npm install
npm run dev   # open http://localhost:3000
```
Panels: overview, Docker, databases, queues, supervisor, and settings. Uses relative path `../output` by default.

## Supervisor
- Lives in `monitoring/supervisor.py`.
- Captures stdout/stderr, writes periodic live snapshots while the process is running.
- Restart policies: `always`, `on-failure`, `never`; `restart_delay_seconds`; `max_restarts_per_minute` to prevent flapping.

## Testing
- See `TEST_PLAN.md` for detailed coverage per module (checks, streams, supervisor, notifications, error paths).
- Integration tests require real or disposable resources (Docker, DBs, queues); DNS/SMTP/TLS can use public hosts.

## Project Structure
- `main.py` — daemon entrypoint, monitoring loop, report writer.
- `checker/` — individual check modules (API, pages, server, versions, DNS, network, logs, sensitive paths, DBs, queues).
- `monitoring/` — background streams (Docker/DB/Task/Queue) and process supervisor.
- `utils/` — logger, config loader, notifier, file writers.
- `output/` — generated reports and snapshots (git-ignored).
- `admin-dashboard/` — Next.js dashboard consuming `output/`.
