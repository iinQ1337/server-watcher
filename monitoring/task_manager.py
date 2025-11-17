#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@file monitoring/task_manager.py
@brief Поток, который формирует «реальный» срез загрузки системы для панели
@details Снимает метрики CPU/памяти, топ процессов и сохраняет их в JSON,
         чтобы Next.js мог отдавать данные в модальном окне «диспетчера задач».
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover - psutil обязателен для потока
    psutil = None  # type: ignore

from utils.logger import log_error, log_info

MetricHistory = Deque[Dict[str, Any]]


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


class TaskManagerStream(threading.Thread):
    """
    Фоновый поток, который обновляет JSON со срезом метрик
    """

    def __init__(
        self,
        output_dir: Path,
        interval_sec: float = 2.0,
        history_points: int = 90,
        top_processes: int = 8,
    ) -> None:
        super().__init__(name="TaskManagerStream", daemon=True)
        self.interval = max(0.5, float(interval_sec))
        self.history_points = max(10, int(history_points))
        self.top_processes = max(3, int(top_processes))
        self.output_path = Path(output_dir) / "task_manager_stream.json"
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._stop_event = threading.Event()
        self._cpu_history: MetricHistory = deque(maxlen=self.history_points)
        self._mem_history: MetricHistory = deque(maxlen=self.history_points)

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> Optional["TaskManagerStream"]:
        dashboard_cfg = (config.get("dashboard") or {}).get("task_manager") or {}
        enabled = dashboard_cfg.get("enabled", True)
        if not enabled:
            return None

        output_dir = Path((config.get("output") or {}).get("directory", "output"))
        interval = float(dashboard_cfg.get("interval_sec", 2.0))
        history_points = int(dashboard_cfg.get("history_points", 90))
        top_processes = int(dashboard_cfg.get("top_processes", 8))
        return cls(
            output_dir=output_dir,
            interval_sec=interval,
            history_points=history_points,
            top_processes=top_processes,
        )

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        if psutil is None:
            log_error("TaskManagerStream: требуется psutil, поток не запущен")
            return

        log_info(
            f"TaskManagerStream запущен, обновление каждые {self.interval}s, файл {self.output_path}"
        )
        # прогреваем счетчики, иначе первые значения будут 0
        try:
            psutil.cpu_percent(interval=None)
            psutil.cpu_percent(interval=None, percpu=True)
        except Exception as exc:  # pragma: no cover - платформа может не поддерживать
            log_error(f"TaskManagerStream: не удалось инициализировать счетчики CPU: {exc}")

        while not self._stop_event.is_set():
            started = time.perf_counter()
            try:
                snapshot = self._collect_snapshot()
                if snapshot:
                    self._write_snapshot(snapshot)
            except Exception as exc:  # pragma: no cover - защитимся от любых сбоев
                log_error(f"TaskManagerStream: ошибка сбора метрик: {exc}")
            finally:
                elapsed = time.perf_counter() - started
                wait_for = max(0.1, self.interval - elapsed)
                self._stop_event.wait(wait_for)

        log_info("TaskManagerStream остановлен")

    # --- внутренние методы -------------------------------------------------

    def _collect_snapshot(self) -> Optional[Dict[str, Any]]:
        if psutil is None:
            return None

        timestamp = _utc_now_iso()
        cpu_percent = psutil.cpu_percent(interval=None)
        per_core = psutil.cpu_percent(interval=None, percpu=True)
        mem = psutil.virtual_memory()

        self._cpu_history.append({"ts": timestamp, "value": cpu_percent})
        self._mem_history.append({"ts": timestamp, "value": mem.percent})

        load_avg: Optional[List[float]] = None
        try:
            load_avg = list(psutil.getloadavg())  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            load_avg = None

        processes = self._collect_processes()

        return {
            "timestamp": timestamp,
            "status": "ok",
            "cpu": {
                "percent": cpu_percent,
                "per_core": per_core,
                "load_avg": load_avg,
                "history": list(self._cpu_history),
            },
            "memory": {
                "percent": mem.percent,
                "total": mem.total,
                "used": mem.used,
                "available": mem.available,
                "history": list(self._mem_history),
            },
            "processes": processes,
        }

    def _collect_processes(self) -> List[Dict[str, Any]]:
        if psutil is None:
            return []

        processes: List[Dict[str, Any]] = []
        for proc in psutil.process_iter(
            attrs=["pid", "name", "username", "cpu_percent", "memory_percent", "cmdline"]
        ):
            try:
                info = proc.info
                cpu = info.get("cpu_percent")
                if cpu is None:
                    cpu = proc.cpu_percent(interval=None)
                mem_percent = info.get("memory_percent") or 0.0
                cmdline = info.get("cmdline") or []
                processes.append(
                    {
                        "pid": info.get("pid"),
                        "name": info.get("name") or "process",
                        "user": info.get("username"),
                        "cpu": round(float(cpu or 0.0), 2),
                        "memory": round(float(mem_percent), 2),
                        "command": " ".join(cmdline)[:160] or info.get("name") or "",
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as exc:  # pragma: no cover
                log_error(f"TaskManagerStream: ошибка обработки процесса {proc.pid}: {exc}")

        processes.sort(key=lambda item: (item["cpu"], item["memory"]), reverse=True)
        return processes[: self.top_processes]

    def _write_snapshot(self, snapshot: Dict[str, Any]) -> None:
        tmp_path = self.output_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp_path.replace(self.output_path)
