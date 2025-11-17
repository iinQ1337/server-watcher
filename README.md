# Monitoring Service and Dashboard

Python monitoring daemon that collects infrastructure signals (Docker containers, databases, tasks, API/page checks), writes JSON snapshots to `output/`, and a Next.js dashboard that reads these snapshots for visualization.

## Features
- Docker stream: container/node stats and events → `output/docker_stream.json`.
- Database stream: connection checks, alerts/backups info, auto-backups via `mysqldump` / `pg_dump` → `output/database_stream.json` and `output/db_backups`.
- Task manager stream (see `monitoring/task_manager_stream.py`) and general monitoring loop producing `report_<timestamp>.json`.
- Queue stream: Redis/RabbitMQ TCP reachability and Redis PING → `output/queue_stream.json`.

## Requirements
- Python 3.10+ with dependencies from `requirements.txt` (`aiomysql`, `asyncpg`, `cryptography` for MySQL SHA auth, etc.).
- Docker CLI available for Docker stream.
- `mysqldump` or `pg_dump` in PATH for auto-backups.
- Redis/RabbitMQ accessible on configured hosts for queue checks (no extra client libs required).

## Configuration
Main settings live in `config.yaml`:
- Output: `output.directory`, formats.
- Streams: `dashboard.docker_stream`, `dashboard.databases_stream` (intervals, thresholds, backup options like `backup_autosave_enabled`, `backup_directory`, `backup_retention`, `backup_timeout_sec`).
- Queues: `queue_monitoring` (enabled, interval_sec, list of Redis/RabbitMQ endpoints).
- Database instances with credentials under `dashboard.databases_stream.instances`.
- API/page monitoring, security, server resources, etc.

## Running
```bash
python main.py
```
The service launches streams per `config.yaml` and enters the monitoring loop. Snapshots are written to `output/`.

## Auto-backups
When `backup_autosave_enabled` is true, `monitoring/db_backups.py` runs `mysqldump`/`pg_dump` for each database instance and stores files in `output/db_backups` (path configurable). History is recorded in `output/database_backups_history.json`.

## Dashboard
The Next.js app under `admin-dashboard/` reads JSON from `output/` (or via API routes) to render `/docker` and `/databases`. The settings page writes back to `config.yaml` through `/api/settings`.

## Logs
Runtime logs go to `monitoring.log` (and console if enabled). Check them for stream errors or backup failures.
