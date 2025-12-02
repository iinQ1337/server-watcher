#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import gzip
import hashlib
import json
import shutil
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import uuid4

from utils.logger import log_debug, log_error, log_info


@dataclass
class StorageLayerConfig:
    enabled: bool
    max_age_minutes: int = 1440
    max_rows_per_table: int = 100000
    flush_interval_sec: int = 60
    file_path: Optional[Path] = None
    file_rotation: str = "none"
    compress_archives: bool = False
    max_size_mb: int = 256
    json_flush_interval_sec: Optional[int] = None


class MonitoringStorage:
    """
    Менеджер горячего (in-memory SQLite) и холодного (on-disk SQLite) хранилищ
    для результатов проверок и стримов. Позволяет быстро читать срезы по времени,
    типу и источнику и периодически сбрасывает историю на диск.
    """

    def __init__(self, hot: StorageLayerConfig, cold: StorageLayerConfig) -> None:
        self.hot_cfg = hot
        self.cold_cfg = cold
        self._hot_conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._cold_conn: Optional[sqlite3.Connection] = None
        self._cold_path: Optional[Path] = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._flush_thread: Optional[threading.Thread] = None

        self._json_targets: Dict[str, Path] = {}
        self._last_json_written: Dict[str, float] = {}
        self._last_json_hash: Dict[str, str] = {}
        self._latest_payload: Dict[str, Dict[str, Any]] = {}

        json_interval = hot.json_flush_interval_sec or min(
            30, float(cold.flush_interval_sec or 60)
        )
        self._json_export_interval = max(5.0, float(json_interval))

        self._init_schema(self._hot_conn)

    # --- Публичные методы -------------------------------------------------

    @classmethod
    def from_config(cls, config: Dict[str, Any], base_dir: Path) -> "MonitoringStorage":
        storage_cfg = config.get("storage") or {}
        hot_cfg_raw = storage_cfg.get("hot") or {}
        cold_cfg_raw = storage_cfg.get("cold") or {}

        hot_cfg = StorageLayerConfig(
            enabled=bool(hot_cfg_raw.get("enabled", True)),
            max_age_minutes=int(hot_cfg_raw.get("max_age_minutes", 1440)),
            max_rows_per_table=int(hot_cfg_raw.get("max_rows_per_table", 100000)),
            json_flush_interval_sec=int(hot_cfg_raw.get("json_flush_interval_sec", 15)),
            flush_interval_sec=int(cold_cfg_raw.get("flush_interval_sec", 60)),
        )

        cold_path_raw = cold_cfg_raw.get("file_path") or (base_dir / "db" / "history.sqlite")
        cold_path = Path(cold_path_raw)
        if not cold_path.is_absolute():
            cold_path = (Path(".") / cold_path).resolve()

        cold_cfg = StorageLayerConfig(
            enabled=bool(cold_cfg_raw.get("enabled", True)),
            flush_interval_sec=int(cold_cfg_raw.get("flush_interval_sec", 60)),
            file_path=cold_path,
            file_rotation=str(cold_cfg_raw.get("file_rotation", "none")).lower(),
            compress_archives=bool(cold_cfg_raw.get("compress_archives", False)),
            max_size_mb=int(cold_cfg_raw.get("max_size_mb", 256)),
        )
        cold_cfg.json_flush_interval_sec = hot_cfg.json_flush_interval_sec

        instance = cls(hot_cfg, cold_cfg)
        if cold_cfg.enabled:
            instance._ensure_cold_connection()
        return instance

    def start(self) -> None:
        if self._flush_thread:
            return
        self._flush_thread = threading.Thread(
            target=self._flush_loop, name="StorageFlush", daemon=True
        )
        self._flush_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._flush_thread:
            self._flush_thread.join(timeout=5)
        try:
            self.flush(force_json=True)
        except Exception as exc:  # pragma: no cover - best-effort on shutdown
            log_error(f"Storage flush on stop failed: {exc}")

    def store_snapshot(
        self,
        category: str,
        source: str,
        payload: Dict[str, Any],
        *,
        json_path: Optional[Path] = None,
        force_json: bool = False,
    ) -> None:
        """
        Сохраняет срез в горячее хранилище и (опционально) регистрирует JSON-цель.
        """
        if not self.hot_cfg.enabled:
            if json_path:
                self._write_json(json_path, payload)
            return

        created_at = time.time()
        storage_key = f"{category}:{uuid4().hex}"
        payload_str = json.dumps(payload, ensure_ascii=False)

        with self._lock:
            self._hot_conn.execute(
                """
                INSERT OR REPLACE INTO records
                (storage_key, category, source, created_at, payload)
                VALUES (?, ?, ?, ?, ?)
                """,
                (storage_key, category, source, created_at, payload_str),
            )
            self._hot_conn.commit()
            self._latest_payload[category] = payload
            self._trim_hot(category)

        if json_path:
            target = Path(json_path)
            self._json_targets[category] = target
            should_force = force_json or (category not in self._last_json_written)
            self._maybe_export_json(category, target, payload, force=should_force)

    def flush(self, *, force_json: bool = False) -> None:
        """
        Переносит горячие данные в холодное хранилище и пишет JSON-цели.
        """
        self._flush_hot_to_cold()
        self._export_json_targets(force=force_json)

    def describe(self) -> Dict[str, Dict[str, str]]:
        """
        Возвращает описание слоев для печати в табличном виде.
        """
        cold_path = str(self._cold_path or self.cold_cfg.file_path or "")
        return {
            "hot": {
                "host": ":memory:",
                "port": "-",
                "user": "-",
                "password": "-",
                "name": "hot_cache",
                "path": ":memory:",
                "enabled": "yes" if self.hot_cfg.enabled else "no",
            },
            "cold": {
                "host": cold_path or "-",
                "port": "-",
                "user": "-",
                "password": "-",
                "name": Path(cold_path).stem or "history",
                "path": cold_path or "-",
                "enabled": "yes" if self.cold_cfg.enabled else "no",
            },
        }

    # --- Внутренняя логика ------------------------------------------------

    def _init_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                storage_key TEXT UNIQUE,
                category TEXT NOT NULL,
                source TEXT,
                created_at REAL NOT NULL,
                payload TEXT NOT NULL
            );
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_records_category_time ON records(category, created_at);"
        )
        conn.commit()

    def _trim_hot(self, category: str) -> None:
        cutoff = time.time() - (self.hot_cfg.max_age_minutes * 60)
        self._hot_conn.execute(
            "DELETE FROM records WHERE category = ? AND created_at < ?", (category, cutoff)
        )
        self._hot_conn.commit()

        count_row = self._hot_conn.execute(
            "SELECT COUNT(*) FROM records WHERE category = ?", (category,)
        ).fetchone()
        total = count_row[0] if count_row else 0
        if total > self.hot_cfg.max_rows_per_table:
            overflow = total - self.hot_cfg.max_rows_per_table
            self._hot_conn.execute(
                """
                DELETE FROM records WHERE id IN (
                    SELECT id FROM records
                    WHERE category = ?
                    ORDER BY created_at ASC
                    LIMIT ?
                )
                """,
                (category, overflow),
            )
            self._hot_conn.commit()

    def _ensure_cold_connection(self) -> Optional[sqlite3.Connection]:
        if not self.cold_cfg.enabled or not self.cold_cfg.file_path:
            return None

        desired_path = self._resolve_cold_path()
        if self._cold_conn and self._cold_path == desired_path:
            return self._cold_conn

        if self._cold_conn:
            try:
                self._cold_conn.close()
            except Exception:
                pass

        desired_path.parent.mkdir(parents=True, exist_ok=True)
        self._cold_path = desired_path
        self._cold_conn = sqlite3.connect(desired_path, check_same_thread=False)
        self._init_schema(self._cold_conn)
        log_info(f"Cold storage ready at {desired_path}")
        return self._cold_conn

    def _resolve_cold_path(self) -> Path:
        assert self.cold_cfg.file_path is not None
        base = self.cold_cfg.file_path
        now = datetime.now()

        if self.cold_cfg.file_rotation == "daily":
            suffix = now.strftime("%Y%m%d")
            rotated = base.with_name(f"{base.stem}-{suffix}{base.suffix}")
            return rotated
        if self.cold_cfg.file_rotation == "weekly":
            suffix = now.strftime("%Y%W")
            rotated = base.with_name(f"{base.stem}-w{suffix}{base.suffix}")
            return rotated
        if self.cold_cfg.file_rotation == "size_based":
            if base.exists():
                size_mb = base.stat().st_size / (1024 * 1024)
                if size_mb >= self.cold_cfg.max_size_mb:
                    ts = now.strftime("%Y%m%d-%H%M%S")
                    archived = base.with_name(f"{base.stem}-{ts}{base.suffix}")
                    if self._cold_conn and self._cold_path == base:
                        try:
                            self._cold_conn.close()
                        except Exception:
                            pass
                        self._cold_conn = None
                        self._cold_path = None
                    self._rotate_file(base, archived)
            return base
        return base

    def _rotate_file(self, current: Path, archived: Path) -> None:
        try:
            if self.cold_cfg.compress_archives:
                gz_path = archived.with_suffix(archived.suffix + ".gz")
                with current.open("rb") as src, gzip.open(gz_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                current.unlink(missing_ok=True)
                log_info(f"Cold storage rotated & compressed to {gz_path}")
            else:
                shutil.move(str(current), str(archived))
                log_info(f"Cold storage rotated to {archived}")
        except Exception as exc:  # pragma: no cover - best effort
            log_error(f"Failed to rotate cold storage file: {exc}")

    def _flush_hot_to_cold(self) -> None:
        if not self.cold_cfg.enabled:
            return
        conn = self._ensure_cold_connection()
        if conn is None:
            return

        with self._lock:
            rows = self._hot_conn.execute(
                "SELECT storage_key, category, source, created_at, payload FROM records"
            ).fetchall()

        if not rows:
            return

        try:
            conn.executemany(
                """
                INSERT OR IGNORE INTO records
                (storage_key, category, source, created_at, payload)
                VALUES (?, ?, ?, ?, ?)
                """,
                rows,
            )
            conn.commit()
            log_debug(f"Flushed {len(rows)} hot rows to cold storage")
        except Exception as exc:
            log_error(f"Failed to flush hot storage to cold DB: {exc}")

    def _export_json_targets(self, *, force: bool = False) -> None:
        for category, target in list(self._json_targets.items()):
            payload = self._latest_payload.get(category)
            if payload is None:
                payload = self._load_latest_payload(category)
                if payload is None:
                    continue
                self._latest_payload[category] = payload
            self._maybe_export_json(category, target, payload, force=force)

    def _maybe_export_json(
        self, category: str, target: Path, payload: Dict[str, Any], *, force: bool = False
    ) -> None:
        now = time.time()
        last_written = self._last_json_written.get(category, 0.0)
        if not force and (now - last_written) < self._json_export_interval:
            return

        payload_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        if not force and self._last_json_hash.get(category) == payload_hash:
            return

        self._write_json(target, payload)
        self._last_json_written[category] = now
        self._last_json_hash[category] = payload_hash

    def _write_json(self, target: Path, payload: Dict[str, Any]) -> None:
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(target)
        except Exception as exc:
            log_error(f"Failed to write JSON {target}: {exc}")

    def _load_latest_payload(self, category: str) -> Optional[Dict[str, Any]]:
        try:
            row = self._hot_conn.execute(
                "SELECT payload FROM records WHERE category = ? ORDER BY created_at DESC LIMIT 1",
                (category,),
            ).fetchone()
            if not row:
                return None
            return json.loads(row[0])
        except Exception as exc:
            log_error(f"Failed to load latest payload for {category}: {exc}")
            return None

    def _flush_loop(self) -> None:
        interval = max(5.0, float(self.cold_cfg.flush_interval_sec))
        while not self._stop_event.is_set():
            self._stop_event.wait(interval)
            if self._stop_event.is_set():
                break
            try:
                self.flush()
            except Exception as exc:  # pragma: no cover - не даем потоку умереть
                log_error(f"Storage flush loop error: {exc}")
