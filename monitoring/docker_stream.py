#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover - psutil обязательна только для обогащения
    psutil = None  # type: ignore

from utils.logger import log_error, log_info, log_debug

DockerPayload = Dict[str, Any]


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _to_number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class DockerStream(threading.Thread):
    """
    Фоновый поток, который собирает показатели контейнеров и пишет в JSON
    """

    def __init__(
        self,
        output_dir: Path,
        *,
        interval_sec: float = 20.0,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(name="DockerStream", daemon=True)
        cfg = config or {}
        self.interval = max(5.0, float(interval_sec))
        self.use_cli = bool(cfg.get("use_cli", True))
        self.default_node = cfg.get("default_node") or platform.node() or "docker-node"
        self.containers_cfg = list(cfg.get("containers") or [])
        self.nodes_cfg = list(cfg.get("nodes") or [])
        self.events_cfg = list(cfg.get("events") or [])

        self.output_path = Path(output_dir) / "docker_stream.json"
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._stop_event = threading.Event()
        # временная метка, с которой собираем docker events
        self._events_since = datetime.now(tz=timezone.utc) - timedelta(seconds=300)

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> Optional["DockerStream"]:
        dashboard_cfg = (config.get("dashboard") or {}).get("docker_stream") or {}
        if not dashboard_cfg.get("enabled", False):
            return None

        output_dir = Path((config.get("output") or {}).get("directory", "output"))
        interval = float(dashboard_cfg.get("interval_sec", 20))
        return cls(output_dir=output_dir, interval_sec=interval, config=dashboard_cfg)

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        log_info(
            f"DockerStream запущен, обновление каждые {self.interval}s, файл {self.output_path}"
        )
        while not self._stop_event.is_set():
            started = time.perf_counter()
            try:
                payload = self._build_payload()
                log_debug(f"DockerStream payload: {payload}")
                self._write_snapshot(payload)
            except Exception as exc:
                log_error(f"DockerStream: ошибка формирования снимка: {exc}")
            finally:
                elapsed = time.perf_counter() - started
                wait_for = max(0.5, self.interval - elapsed)
                self._stop_event.wait(wait_for)
        log_info("DockerStream остановлен")

    # --- внутренние методы -------------------------------------------------

    def _build_payload(self) -> DockerPayload:
        containers = self._collect_containers()
        nodes = self._collect_nodes(containers)
        events = self._collect_events()
        summary = self._build_summary(containers, events)

        return {
            "generatedAt": _utc_now_iso(),
            "summary": summary,
            "containers": containers,
            "nodes": nodes,
            "events": events,
        }

    def _collect_containers(self) -> List[Dict[str, Any]]:
        cli_containers: List[Dict[str, Any]] = []
        if self.use_cli and self._docker_available():
            try:
                cli_containers = self._collect_containers_from_cli()
            except Exception as exc:
                log_error(f"DockerStream: не удалось собрать данные docker-cli: {exc}")

        if cli_containers:
            return cli_containers

        return [
            self._normalize_container(raw, idx) for idx, raw in enumerate(self.containers_cfg)
        ]

    def _collect_containers_from_cli(self) -> List[Dict[str, Any]]:
        ps_data = self._read_docker_json(
            ["docker", "ps", "--format", "{{json .}}"], timeout=10
        )
        stats_map = self._collect_stats_map()
        if stats_map:
            log_debug(f"DockerStream stats_map: {stats_map}")
        ids = [
            item.get("ID") or item.get("Id") or item.get("Container") or item.get("Names")
            for item in ps_data
        ]
        health_map = self._collect_health_map(ids)
        if health_map:
            log_debug(f"DockerStream health_map: {health_map}")

        containers: List[Dict[str, Any]] = []

        for item in ps_data:
            cid = item.get("ID") or item.get("Id") or item.get("Container")
            name = item.get("Names") or cid or "container"
            status_text = item.get("Status") or ""
            status_from_ps, health_from_ps = self._map_status(status_text)

            hinfo = health_map.get(cid or name) or {}
            state_status = hinfo.get("state")
            health_status = hinfo.get("health")
            restarts = hinfo.get("restarts", 0)

            status = self._status_from_health(state_status, health_status, status_from_ps)
            health = self._health_from_status(health_status, status_from_ps, health_from_ps)

            stats = stats_map.get(cid) or stats_map.get(name)
            mem_usage = stats["mem_usage"] if stats else 0.0
            mem_limit = stats["mem_limit"] if stats else 0.0
            cpu_percent = stats["cpu"] if stats else 0.0

            containers.append(
                {
                    "id": cid or name,
                    "name": name,
                    "image": item.get("Image") or "",
                    "status": status,
                    "health": health,
                    "node": self.default_node,
                    "uptime": item.get("RunningFor") or status_text,
                    "cpuPercent": cpu_percent,
                    "memoryUsageMb": mem_usage,
                    "memoryLimitMb": mem_limit,
                    "restarts": restarts,
                    "ports": item.get("Ports") or "",
                    "updatedAt": _utc_now_iso(),
                }
            )

        return containers

    def _collect_stats_map(self) -> Dict[str, Dict[str, float]]:
        if not self._docker_available():
            return {}

        stats_data = self._read_docker_json(
            ["docker", "stats", "--no-stream", "--format", "{{json .}}"], timeout=10
        )
        stats_map: Dict[str, Dict[str, float]] = {}

        for item in stats_data:
            key = item.get("ID") or item.get("Container") or item.get("Name")
            if not key:
                continue
            mem_usage, mem_limit = self._parse_memory(item.get("MemUsage"))
            stats_map[key] = {
                "cpu": self._parse_percent(item.get("CPUPerc")),
                "mem_usage": mem_usage,
                "mem_limit": mem_limit,
            }
        return stats_map

    def _collect_health_map(self, ids: List[Optional[str]]) -> Dict[str, Dict[str, Any]]:
        valid_ids = [i for i in ids if i]
        if not valid_ids or not self._docker_available():
            return {}

        health_map: Dict[str, Dict[str, Any]] = {}
        for cid in valid_ids:
            cmd = [
                "docker",
                "inspect",
                "--format",
                "{{json .ID}} {{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}} {{json .State.Status}} {{json .RestartCount}}",
                cid,
            ]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, check=True, timeout=5
                )
            except subprocess.CalledProcessError as exc:
                stderr = (exc.stderr or "").strip()
                log_debug(f"DockerStream: inspect failed for {cid}: {stderr}")
                continue
            except Exception as exc:
                log_debug(f"DockerStream: inspect error for {cid}: {exc}")
                continue

            line = (result.stdout or "").strip()
            if not line:
                continue
            try:
                parts = line.split(" ", 3)
                parsed_cid = json.loads(parts[0]) if len(parts) > 0 else None
                health = json.loads(parts[1]) if len(parts) > 1 else None
                state = json.loads(parts[2]) if len(parts) > 2 else None
                restarts = json.loads(parts[3]) if len(parts) > 3 else 0
                if parsed_cid:
                    entry = {
                        "health": health,
                        "state": state,
                        "restarts": restarts,
                    }
                    short_id = parsed_cid[:12]
                    # Сохраняем под полным и коротким ID, чтобы совпадать с docker ps
                    health_map[parsed_cid] = entry
                    health_map[short_id] = entry
            except Exception as exc:
                log_debug(f"DockerStream: failed to parse inspect output for {cid}: {exc}")
                continue
        return health_map

    def _collect_nodes(self, containers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if self.nodes_cfg:
            return [self._normalize_node(raw, idx) for idx, raw in enumerate(self.nodes_cfg)]

        # fallback: один локальный узел
        mem_used_gb = 0.0
        mem_total_gb = 0.0
        if psutil is not None:
            try:
                mem = psutil.virtual_memory()
                mem_used_gb = round(mem.used / (1024**3), 2)
                mem_total_gb = round(mem.total / (1024**3), 2)
            except Exception:
                pass

        try:
            cpu_usage = psutil.cpu_percent(interval=None) if psutil else 0.0
        except Exception:
            cpu_usage = 0.0

        return [
            {
                "id": "local",
                "name": self.default_node,
                "role": "manager",
                "status": "online",
                "dockerVersion": self._docker_version() or "-",
                "cpuUsage": round(cpu_usage, 2),
                "memoryUsageGb": mem_used_gb,
                "memoryCapacityGb": mem_total_gb,
                "runningContainers": sum(1 for c in containers if c.get("status") == "running"),
            }
        ]

    def _collect_events(self) -> List[Dict[str, Any]]:
        now = datetime.now(tz=timezone.utc)
        events: List[Dict[str, Any]] = []

        if self._docker_available():
            since_ts = self._events_since
            until_ts = now
            since_arg = since_ts.isoformat()
            until_arg = until_ts.isoformat()
            cmd = [
                "docker",
                "events",
                "--since",
                since_arg,
                "--until",
                until_arg,
                "--format",
                "{{json .}}",
            ]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, check=True, timeout=8
                )
                lines = (result.stdout or "").splitlines()
                for idx, line in enumerate(lines):
                    try:
                        raw = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    action = str(raw.get("Action") or "").lower()
                    raw_type = str(raw.get("Type") or "").lower()
                    attrs = raw.get("Actor", {}).get("Attributes") or {}
                    scope = attrs.get("name") or raw.get("id") or raw_type or self.default_node
                    ts = raw.get("TimeNano") or raw.get("Time")
                    timestamp = (
                        datetime.fromtimestamp(ts / 1e9, tz=timezone.utc).isoformat()
                        if isinstance(ts, (int, float))
                        else _utc_now_iso()
                    )
                    tone = "info"
                    if any(word in action for word in ("die", "kill", "oom", "health_status: unhealthy")):
                        tone = "error"
                    elif any(word in action for word in ("restart", "pause", "unpause", "disconnect")):
                        tone = "warning"

                    events.append(
                        {
                            "id": f"docker-{raw.get('ID') or raw.get('id') or idx}-{int(ts) if isinstance(ts, (int, float)) else idx}",
                            "scope": scope,
                            "type": tone,
                            "message": f"{raw_type} {action}".strip(),
                            "timestamp": timestamp,
                        }
                    )
            except subprocess.TimeoutExpired:
                log_debug("DockerStream: docker events timed out")
            except subprocess.CalledProcessError as exc:
                stderr = (exc.stderr or "").strip()
                log_debug(f"DockerStream: docker events failed: {stderr}")
            except Exception as exc:
                log_debug(f"DockerStream: docker events error: {exc}")

        if not events and self.events_cfg:
            events = [
                {
                    "id": raw.get("id") or f"event-{idx + 1}",
                    "scope": raw.get("scope") or self.default_node,
                    "type": (raw.get("type") or "info").lower(),
                    "message": raw.get("message") or "",
                    "timestamp": raw.get("timestamp") or _utc_now_iso(),
                }
                for idx, raw in enumerate(self.events_cfg)
            ]

        self._events_since = now
        if events:
            log_debug(f"DockerStream events: {events}")
        return events

    def _build_summary(
        self, containers: List[Dict[str, Any]], events: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        divisor = max(len(containers), 1)
        avg_cpu = sum(_to_number(item.get("cpuPercent")) for item in containers) / divisor
        running = sum(1 for item in containers if item.get("status") == "running")
        unhealthy = sum(1 for item in containers if item.get("health") != "passing")
        warning_count = sum(1 for event in events if event.get("type") != "info")

        return {
            "runningContainers": running,
            "unhealthyContainers": unhealthy,
            "warningCount": warning_count,
            "avgCpuUsage": int(round(avg_cpu)),
        }

    def _normalize_container(self, raw: Dict[str, Any], idx: int) -> Dict[str, Any]:
        status = (raw.get("status") or "running").lower()
        health = (raw.get("health") or "passing").lower()

        mem_limit = _to_number(raw.get("memory_limit_mb") or raw.get("memoryLimitMb"), 0)
        mem_usage = _to_number(raw.get("memory_usage_mb") or raw.get("memoryUsageMb"), 0)

        return {
            "id": raw.get("id") or raw.get("name") or f"container-{idx + 1}",
            "name": raw.get("name") or "container",
            "image": raw.get("image") or "",
            "status": status,
            "health": health,
            "node": raw.get("node") or self.default_node,
            "uptime": raw.get("uptime") or "",
            "cpuPercent": int(_to_number(raw.get("cpu_percent") or raw.get("cpuPercent"), 0)),
            "memoryUsageMb": int(mem_usage),
            "memoryLimitMb": int(mem_limit),
            "restarts": int(_to_number(raw.get("restarts"), 0)),
            "ports": raw.get("ports") or "",
            "updatedAt": raw.get("updatedAt") or raw.get("updated_at") or _utc_now_iso(),
        }

    def _normalize_node(self, raw: Dict[str, Any], idx: int) -> Dict[str, Any]:
        return {
            "id": raw.get("id") or raw.get("name") or f"node-{idx + 1}",
            "name": raw.get("name") or f"node-{idx + 1}",
            "role": (raw.get("role") or "worker").lower(),
            "status": (raw.get("status") or "online").lower(),
            "dockerVersion": raw.get("dockerVersion") or raw.get("docker_version") or "-",
            "cpuUsage": int(_to_number(raw.get("cpu_usage") or raw.get("cpuUsage"), 0)),
            "memoryUsageGb": round(_to_number(raw.get("memory_usage_gb") or raw.get("memoryUsageGb"), 0), 2),
            "memoryCapacityGb": round(_to_number(raw.get("memory_capacity_gb") or raw.get("memoryCapacityGb"), 0), 2),
            "runningContainers": int(_to_number(raw.get("running_containers") or raw.get("runningContainers"), 0)),
        }

    def _map_status(self, status: str) -> Tuple[str, str]:
        status_lower = status.lower()
        if "unhealthy" in status_lower or "dead" in status_lower:
            return ("failed", "failing")
        if "starting" in status_lower or "restart" in status_lower:
            return ("starting", "warning")
        if "exited" in status_lower or "stopped" in status_lower:
            return ("stopped", "passing")
        return ("running", "passing")

    def _status_from_health(
        self, state_status: Optional[str], health_status: Optional[str], fallback_status: str
    ) -> str:
        if state_status:
            if state_status == "running":
                if health_status and health_status == "unhealthy":
                    return "failed"
                return "running"
            if state_status in ("exited", "dead"):
                return "stopped"
            if state_status == "restarting":
                return "starting"
        if health_status:
            if health_status == "unhealthy":
                return "failed"
            if health_status == "starting":
                return "starting"
        return fallback_status

    def _health_from_status(
        self, health_status: Optional[str], status_from_ps: str, health_from_ps: str
    ) -> str:
        if health_status:
            if health_status == "unhealthy":
                return "failing"
            if health_status == "starting":
                return "warning"
            return "passing"
        return health_from_ps or ("passing" if status_from_ps == "running" else "warning")

    def _parse_percent(self, value: Any) -> float:
        if value is None:
            return 0.0
        try:
            text = str(value).replace("%", "").strip()
            return float(text)
        except (TypeError, ValueError):
            return 0.0

    def _parse_memory(self, value: Optional[str]) -> Tuple[float, float]:
        if not value:
            return (0.0, 0.0)
        try:
            parts = value.split("/")
            used = self._parse_size_str(parts[0].strip())
            limit = self._parse_size_str(parts[1].strip()) if len(parts) > 1 else 0.0
            return (used, limit)
        except Exception:
            return (0.0, 0.0)

    def _parse_size_str(self, text: str) -> float:
        units = {"b": 1 / (1024**2), "kib": 1 / 1024, "kb": 1 / 1024, "mb": 1.0, "mib": 1.048576, "gb": 1024.0, "gib": 1024 * 1.048576}
        clean = text.strip().lower().replace(" ", "")
        for suffix, multiplier in units.items():
            if clean.endswith(suffix):
                try:
                    number = float(clean[: -len(suffix)])
                    return round(number * multiplier, 2)
                except ValueError:
                    return 0.0
        try:
            return float(clean)
        except ValueError:
            return 0.0

    def _docker_available(self) -> bool:
        return shutil.which("docker") is not None

    def _docker_version(self) -> Optional[str]:
        if not self._docker_available():
            return None
        try:
            result = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True,
                text=True,
                check=True,
                timeout=8,
            )
            version = (result.stdout or "").strip()
            return version or None
        except Exception:
            return None

    def _read_docker_json(self, cmd: List[str], *, timeout: int = 10) -> List[Dict[str, Any]]:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            return []
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip()
            log_error(f"DockerStream: команда {' '.join(cmd)} завершилась с ошибкой: {stderr}")
            return []
        except subprocess.TimeoutExpired:
            log_error(f"DockerStream: команда {' '.join(cmd)} превысила timeout {timeout}s")
            return []

        lines = (result.stdout or "").splitlines()
        parsed: List[Dict[str, Any]] = []
        for line in lines:
            try:
                parsed.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return parsed

    def _write_snapshot(self, snapshot: DockerPayload) -> None:
        tmp_path = self.output_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp_path.replace(self.output_path)
