from __future__ import annotations

import json
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import log_debug, log_error, log_info
from monitoring.storage import MonitoringStorage

QueuePayload = Dict[str, Any]


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


class QueueStream(threading.Thread):
    def __init__(
        self,
        output_dir: Path,
        *,
        interval_sec: float = 60.0,
        config: Optional[Dict[str, Any]] = None,
        storage: Optional[MonitoringStorage] = None,
    ) -> None:
        super().__init__(name="QueueStream", daemon=True)
        cfg = config or {}
        self.interval = max(10.0, float(interval_sec))
        self.queues_cfg = list(cfg.get("queues") or [])
        self.output_path = Path(output_dir) / "queue_stream.json"
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._stop_event = threading.Event()
        self.storage = storage

    @classmethod
    def from_config(
        cls, config: Dict[str, Any], storage: Optional[MonitoringStorage] = None
    ) -> Optional["QueueStream"]:
        qcfg = (config.get("queue_monitoring") or {})
        if not qcfg.get("enabled"):
            return None
        output_dir = Path((config.get("output") or {}).get("directory", "output"))
        interval = float(qcfg.get("interval_sec", 60))
        return cls(output_dir=output_dir, interval_sec=interval, config=qcfg, storage=storage)

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        log_info(f"QueueStream запущен, обновление каждые {self.interval}s, файл {self.output_path}")
        while not self._stop_event.is_set():
            started = time.perf_counter()
            try:
                payload = self._build_payload()
                log_debug(f"QueueStream payload: {payload}")
                self._persist_snapshot(payload)
            except Exception as exc:
                log_error(f"QueueStream: ошибка формирования снимка: {exc}")
            finally:
                elapsed = time.perf_counter() - started
                wait_for = max(0.5, self.interval - elapsed)
                self._stop_event.wait(wait_for)
        log_info("QueueStream остановлен")

    def _build_payload(self) -> QueuePayload:
        queues = [self._check_queue(raw) for raw in self.queues_cfg]
        summary = {
            "total": len(queues),
            "up": sum(1 for q in queues if q.get("status") == "up"),
            "down": sum(1 for q in queues if q.get("status") == "down"),
        }
        return {
            "generatedAt": _utc_now_iso(),
            "summary": summary,
            "queues": queues,
        }

    def _check_queue(self, cfg: Dict[str, Any]) -> Dict[str, Any]:
        qtype = (cfg.get("type") or "redis").lower()
        host = cfg.get("host") or "localhost"
        port = int(cfg.get("port") or (6379 if qtype == "redis" else 5672))

        started = time.perf_counter()
        status = "down"
        message = ""
        latency_ms = 0.0

        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                sock.settimeout(5)
                if qtype == "redis":
                    sock.sendall(b"PING\r\n")
                    response = sock.recv(16)
                    if b"PONG" not in response:
                        message = f"Unexpected redis response: {response!r}"
                    else:
                        message = "PONG"
                status = "up" if not message else "down"
        except Exception as exc:
            message = str(exc)
            status = "down"
        finally:
            latency_ms = round((time.perf_counter() - started) * 1000, 2)

        return {
            "id": cfg.get("id") or f"queue-{host}:{port}",
            "name": cfg.get("name") or cfg.get("queue_name") or cfg.get("queues") or "queue",
            "type": qtype,
            "host": host,
            "port": port,
            "status": status,
            "latencyMs": latency_ms,
            "message": message,
            "updatedAt": _utc_now_iso(),
        }

    def _write_snapshot(self, snapshot: QueuePayload) -> None:
        tmp_path = self.output_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp_path.replace(self.output_path)

    def _persist_snapshot(self, snapshot: QueuePayload) -> None:
        if self.storage:
            self.storage.store_snapshot(
                category="queue_stream",
                source="QueueStream",
                payload=snapshot,
                json_path=self.output_path,
            )
            return
        self._write_snapshot(snapshot)
