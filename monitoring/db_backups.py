#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List, Optional
import json
import time
from datetime import datetime, timezone
from pathlib import Path
import os

import subprocess

from utils.logger import log_debug, log_error


def load_backups(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Возвращает список бэкапов из секции dashboard.databases_stream.backups.
    """
    backups = list((config.get("dashboard") or {}).get("databases_stream", {}).get("backups") or [])
    if backups:
        log_debug(f"DB backups loaded: {len(backups)} record(s)")
    return backups


def record_backup_runs(
    instances: List[Dict[str, Any]],
    history_path: Path,
    *,
    interval_sec: float,
    backup_dir: Path,
    max_entries: int = 50,
    timeout_sec: int = 120,
) -> List[Dict[str, Any]]:
    """
    Выполняет реальный бэкап (mysqldump/pg_dump) для каждого инстанса и сохраняет историю в файле.
    Возвращает обновленный список бэкапов.
    """
    history_path.parent.mkdir(parents=True, exist_ok=True)
    backup_dir.mkdir(parents=True, exist_ok=True)
    try:
        history_raw = history_path.read_text(encoding="utf-8")
        history: List[Dict[str, Any]] = json.loads(history_raw)
    except Exception:
        history = []

    created: List[Dict[str, Any]] = []
    for inst in instances:
        entry = _perform_backup(inst, backup_dir, interval_sec, timeout_sec)
        created.append(entry)

    updated = created + history
    if len(updated) > max_entries:
        updated = updated[:max_entries]

    try:
        history_path.write_text(json.dumps(updated, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as exc:
        log_error(f"DB backups: failed to write history {history_path}: {exc}")
    return updated


def _perform_backup(
    inst: Dict[str, Any], backup_dir: Path, interval_sec: float, timeout_sec: int
) -> Dict[str, Any]:
    """
    Делает бэкап конкретного инстанса. Возвращает запись для UI/history.
    """
    db_type = (inst.get("type") or "mysql").lower()
    identifier = inst.get("id") or inst.get("name") or db_type
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{identifier}-{timestamp}.sql"
    target_path = backup_dir / filename
    schedule = f"Авто · каждые {int(interval_sec)} сек"

    started = time.perf_counter()
    status = "failed"
    error: Optional[str] = None

    cmd: List[str] = []
    env = None

    if db_type == "mysql":
        cmd = [
            "mysqldump",
            "-h",
            str(inst.get("host", "localhost")),
            "-P",
            str(inst.get("port", 3306)),
            "-u",
            str(inst.get("user", "")),
            "--protocol=tcp",
            str(inst.get("database", "")),
        ]
        env = {**os.environ, "MYSQL_PWD": str(inst.get("password", ""))}
    elif db_type in ("postgres", "postgresql"):
        cmd = [
            "pg_dump",
            "-h",
            str(inst.get("host", "localhost")),
            "-p",
            str(inst.get("port", 5432)),
            "-U",
            str(inst.get("user", "")),
            "-F",
            "p",
            "-f",
            str(target_path),
            str(inst.get("database", "")),
        ]
        env = {**os.environ, "PGPASSWORD": str(inst.get("password", ""))}
    else:
        error = f"Unsupported backup type: {db_type}"
        duration = max(1, int((time.perf_counter() - started) / 60))
        return {
            "id": f"auto-backup-{identifier}-{int(time.time())}",
            "target": inst.get("name") or identifier,
            "schedule": schedule,
            "status": status,
            "lastRun": datetime.now(tz=timezone.utc).isoformat(),
            "durationMinutes": duration,
            "error": error,
        }

    # Для mysqldump используем опцию записи в файл через stdout redirection
    try:
        if db_type == "mysql":
            with target_path.open("w", encoding="utf-8") as fout:
                subprocess.run(cmd, stdout=fout, stderr=subprocess.PIPE, text=True, check=True, timeout=timeout_sec, env=env)
        else:
            subprocess.run(cmd, stderr=subprocess.PIPE, text=True, check=True, timeout=timeout_sec, env=env)
        status = "success"
    except FileNotFoundError:
        error = f"{cmd[0]} not found"
    except subprocess.CalledProcessError as exc:
        error = (exc.stderr or "").strip() or str(exc)
    except subprocess.TimeoutExpired:
        error = f"{cmd[0]} timed out after {timeout_sec}s"
    except Exception as exc:
        error = str(exc)

    duration_minutes = max(1, int(round((time.perf_counter() - started) / 60, 0)))

    entry = {
        "id": f"auto-backup-{identifier}-{int(time.time())}",
        "target": inst.get("name") or identifier,
        "schedule": schedule,
        "status": status if not error else "failed",
        "lastRun": datetime.now(tz=timezone.utc).isoformat(),
        "durationMinutes": duration_minutes,
        "path": str(target_path),
    }
    if error:
        entry["error"] = error
    return entry
