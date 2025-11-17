#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import asyncio
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from checker.database_checker import check_databases
from monitoring.db_alerts import load_alerts
from monitoring.db_backups import load_backups, record_backup_runs
from utils.logger import log_error, log_info, log_debug

DatabasePayload = Dict[str, Any]


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _to_number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class DatabaseStream(threading.Thread):
    """
    Фоновый поток, который готовит данные для /databases
    """

    def __init__(
        self,
        output_dir: Path,
        *,
        interval_sec: float = 30.0,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(name="DatabaseStream", daemon=True)
        cfg = config or {}
        self.interval = max(5.0, float(interval_sec))
        self.instances_cfg = list(cfg.get("instances") or [])
        self.alerts_cfg = list(cfg.get("alerts") or [])
        self.backups_cfg = list(cfg.get("backups") or [])
        self.auto_backup_enabled = bool(cfg.get("backup_autosave_enabled", False))
        self.backup_dir = Path(cfg.get("backup_directory") or (output_dir / "db_backups"))
        self.backup_retention = int(cfg.get("backup_retention") or 50)
        self.backup_timeout = int(cfg.get("backup_timeout_sec") or 120)

        thresholds = cfg.get("thresholds") or {}
        self.replication_warn = int(thresholds.get("replication_lag_ms", 250))
        self.storage_warn = int(thresholds.get("storage_percent", 85))

        self.output_path = Path(output_dir) / "database_stream.json"
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._stop_event = threading.Event()

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> Optional["DatabaseStream"]:
        dashboard_cfg = (config.get("dashboard") or {}).get("databases_stream") or {}
        if not dashboard_cfg.get("enabled", False):
            return None

        output_dir = Path((config.get("output") or {}).get("directory", "output"))
        interval = float(dashboard_cfg.get("interval_sec", 30))
        return cls(output_dir=output_dir, interval_sec=interval, config=dashboard_cfg)

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        log_info(
            f"DatabaseStream запущен, обновление каждые {self.interval}s, файл {self.output_path}"
        )

        while not self._stop_event.is_set():
            started = time.perf_counter()
            try:
                payload = self._build_payload()
                log_debug(f"DatabaseStream payload: {payload}")
                self._write_snapshot(payload)
            except Exception as exc:
                log_error(f"DatabaseStream: ошибка формирования снимка: {exc}")
            finally:
                elapsed = time.perf_counter() - started
                wait_for = max(0.5, self.interval - elapsed)
                self._stop_event.wait(wait_for)

        log_info("DatabaseStream остановлен")

    # --- внутренние методы -------------------------------------------------

    def _build_payload(self) -> DatabasePayload:
        instances = self._collect_instances()
        alerts_raw = load_alerts({"dashboard": {"databases_stream": {"alerts": self.alerts_cfg}}})
        backups_raw = load_backups({"dashboard": {"databases_stream": {"backups": self.backups_cfg}}})
        alerts = [self._normalize_alert(raw, idx) for idx, raw in enumerate(alerts_raw)]

        backups_list: List[Dict[str, Any]] = backups_raw
        source_instances = self.instances_cfg or instances
        if self.auto_backup_enabled and source_instances:
            history_path = self.output_path.parent / "database_backups_history.json"
            backups_list = record_backup_runs(
                source_instances,
                history_path,
                interval_sec=self.interval,
                backup_dir=self.backup_dir,
                max_entries=self.backup_retention,
                timeout_sec=self.backup_timeout,
            )

        backups = [self._normalize_backup(raw, idx) for idx, raw in enumerate(backups_list)]

        summary = self._compute_summary(instances, alerts)

        return {
            "generatedAt": _utc_now_iso(),
            "summary": summary,
            "instances": instances,
            "backups": backups,
            "alerts": alerts,
        }

    def _collect_instances(self) -> List[Dict[str, Any]]:
        if not self.instances_cfg:
            return []

        try:
            raw_result = asyncio.run(check_databases({"databases": self.instances_cfg}))
            raw_databases = raw_result.get("databases") or []
            log_debug(f"DatabaseStream raw check result: {raw_result}")
        except Exception as exc:  # pragma: no cover - защита от сетевых ошибок
            log_error(f"DatabaseStream: не удалось выполнить проверки БД: {exc}")
            raw_databases = []

        instances: List[Dict[str, Any]] = []
        for idx, base_cfg in enumerate(self.instances_cfg):
            details = raw_databases[idx] if idx < len(raw_databases) else {}
            instances.append(self._normalize_instance(base_cfg, details, idx))
        return instances

    def _normalize_instance(
        self, raw: Dict[str, Any], check_result: Dict[str, Any], idx: int
    ) -> Dict[str, Any]:
        storage_total = _to_number(
            raw.get("storage_total_gb") or raw.get("storageTotalGb"), default=0.0
        )
        storage_used = _to_number(
            raw.get("storage_used_gb") or raw.get("storageUsedGb"), default=0.0
        )
        storage_percent = raw.get("storage_usage_percent") or raw.get(
            "storageUsagePercent"
        )
        if storage_percent is None and storage_total > 0:
            storage_percent = round((storage_used / storage_total) * 100, 2)

        replication_lag = _to_number(
            raw.get("replication_lag_ms") or raw.get("replicationLagMs") or check_result.get("test_query_time"), default=0.0
        )

        response_time = _to_number(check_result.get("response_time"))
        status = self._status_from_checks(check_result, replication_lag, response_time, storage_percent)

        db_engine = raw.get("engine") or raw.get("type") or "postgres"

        return {
            "id": raw.get("id") or raw.get("name") or f"db-{idx + 1}",
            "name": raw.get("name") or "Database",
            "engine": str(db_engine),
            "version": str(raw.get("version") or check_result.get("version") or "unknown"),
            "role": raw.get("role") or "primary",
            "region": raw.get("region") or "-",
            "status": status,
            "queriesPerSecond": int(_to_number(check_result.get("queries_per_second") or raw.get("queries_per_second") or raw.get("queriesPerSecond"), 0)),
            "connections": int(_to_number(check_result.get("connections") or raw.get("connections"), 0)),
            "replicationLagMs": int(replication_lag or response_time),
            "storageUsedGb": round(storage_used, 2),
            "storageTotalGb": round(storage_total, 2),
            "storageUsagePercent": int(_to_number(storage_percent, 0)),
            "latencyMsP95": int(_to_number(raw.get("latency_ms_p95") or raw.get("latencyMsP95") or response_time, 0)),
            "lastBackup": raw.get("last_backup") or raw.get("lastBackup") or check_result.get("last_backup") or "",
            "error": check_result.get("error"),
        }

    def _status_from_checks(
        self, check_result: Dict[str, Any], replication_lag: float, response_time: float, storage_percent: Any
    ) -> str:
        if not check_result.get("connected"):
            return "critical"
        try:
            storage_pct_num = float(storage_percent)
        except (TypeError, ValueError):
            storage_pct_num = 0.0

        if replication_lag >= self.replication_warn * 1.5 or storage_pct_num >= 95:
            return "critical"
        if replication_lag >= self.replication_warn or storage_pct_num >= self.storage_warn:
            return "degraded"
        if response_time and response_time >= self.replication_warn:
            return "degraded"
        return "healthy"

    def _compute_summary(
        self, instances: List[Dict[str, Any]], alerts: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        divisor = max(len(instances), 1)
        avg_lag = sum(_to_number(inst.get("replicationLagMs")) for inst in instances) / divisor
        storage_pressure = sum(
            _to_number(inst.get("storageUsagePercent")) for inst in instances
        ) / divisor

        healthy = sum(1 for inst in instances if inst.get("status") == "healthy")
        degraded = sum(
            1
            for inst in instances
            if inst.get("status") in {"degraded", "critical", "maintenance"}
        )

        critical_alerts = sum(1 for alert in alerts if alert.get("severity") == "critical")

        return {
            "totalClusters": len(instances),
            "healthyClusters": healthy,
            "degradedClusters": degraded,
            "avgReplicationLagMs": int(round(avg_lag)),
            "storagePressurePercent": int(round(storage_pressure)),
            "criticalAlerts": critical_alerts,
        }

    def _normalize_alert(self, raw: Dict[str, Any], idx: int) -> Dict[str, Any]:
        return {
            "id": raw.get("id") or f"alert-{idx + 1}",
            "cluster": raw.get("cluster") or raw.get("name") or "database",
            "severity": (raw.get("severity") or "info").lower(),
            "message": raw.get("message") or "",
            "createdAt": raw.get("createdAt") or raw.get("created_at") or _utc_now_iso(),
        }

    def _normalize_backup(self, raw: Dict[str, Any], idx: int) -> Dict[str, Any]:
        return {
            "id": raw.get("id") or f"backup-{idx + 1}",
            "target": raw.get("target") or raw.get("name") or "cluster",
            "schedule": raw.get("schedule") or "—",
            "status": (raw.get("status") or "running").lower(),
            "lastRun": raw.get("lastRun") or raw.get("last_run") or _utc_now_iso(),
            "durationMinutes": int(_to_number(raw.get("duration_minutes") or raw.get("durationMinutes"), 0)),
        }

    def _write_snapshot(self, snapshot: DatabasePayload) -> None:
        tmp_path = self.output_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp_path.replace(self.output_path)
