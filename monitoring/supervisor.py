#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@file monitoring/supervisor.py
@brief Мини-супервизор для фоновых скриптов/процессов
@details Запускает внешнюю команду в цикле, собирает stdout/stderr, пишет JSON и текстовые логи,
         применяет политику перезапуска (always/on-failure/never) с защитой от флаппинга.
"""

from __future__ import annotations

import contextlib
import copy
import json
import os
import socket
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

try:
    import grp  # type: ignore
    import pwd  # type: ignore
    import resource  # type: ignore
except ImportError:  # pragma: no cover - Windows/limited platforms
    grp = None  # type: ignore
    pwd = None  # type: ignore
    resource = None  # type: ignore

try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover - psutil опционален для расширенного мониторинга
    psutil = None  # type: ignore

from utils.logger import log_debug, log_error, log_info, log_warning


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _build_env(extra: Dict[str, Any]) -> Dict[str, str]:
    env: Dict[str, str] = dict(os.environ)
    for key, value in extra.items():
        if value is None:
            continue
        env[str(key)] = str(value)
    return env


def _normalize_restart_policy(raw: Any) -> Dict[str, Any]:
    """
    Приводит restart_policy к словарю. Допускается строка ('always'/'on-failure'/'never').
    """
    if raw is None:
        return {}
    if isinstance(raw, str):
        return {"mode": raw}
    if isinstance(raw, dict):
        return raw
    return {}


class SupervisorStateStore:
    """
    Потокобезопасное хранилище состояния супервизоров и их процессоров.
    Нужно для self-monitoring, watchdog и health-check API.
    """

    _lock = threading.RLock()
    _process_state: Dict[str, Dict[str, Any]] = {}
    _watchdog_state: Dict[str, Any] = {}

    @classmethod
    def heartbeat(cls, name: str, **fields: Any) -> None:
        with cls._lock:
            state = cls._process_state.setdefault(name, {"name": name})
            state.update(fields)
            state["last_heartbeat"] = time.time()

    @classmethod
    def set_run_result(
        cls,
        name: str,
        run_result: Dict[str, Any],
        restart_reason: Optional[str],
        restart_count: int,
    ) -> None:
        summary = {
            "name": name,
            "status": "running" if run_result.get("exit_code") is None else "exited",
            "pid": run_result.get("pid"),
            "started_at": run_result.get("started_at"),
            "ended_at": run_result.get("ended_at"),
            "duration_seconds": run_result.get("duration_seconds"),
            "exit_code": run_result.get("exit_code"),
            "error": run_result.get("error"),
            "restart_reason": restart_reason,
            "restart_count": restart_count,
            "resource_usage": run_result.get("resource_usage"),
            "last_activity_ts": run_result.get("last_activity_ts"),
        }
        with cls._lock:
            state = cls._process_state.setdefault(name, {"name": name})
            state.update(summary)
            state["last_heartbeat"] = time.time()

    @classmethod
    def last_heartbeat(cls, name: str) -> Optional[float]:
        with cls._lock:
            return (cls._process_state.get(name) or {}).get("last_heartbeat")

    @classmethod
    def get_process_state(cls, name: str) -> Optional[Dict[str, Any]]:
        with cls._lock:
            state = cls._process_state.get(name)
            return copy.deepcopy(state) if state else None

    @classmethod
    def snapshot(cls) -> Dict[str, Any]:
        with cls._lock:
            return {
                "timestamp": _utc_now_iso(),
                "processes": copy.deepcopy(list(cls._process_state.values())),
                "watchdog": copy.deepcopy(cls._watchdog_state),
            }

    @classmethod
    def set_watchdog_state(cls, **fields: Any) -> None:
        with cls._lock:
            cls._watchdog_state.update(fields)
            cls._watchdog_state["last_check_ts"] = time.time()

    @classmethod
    def clear(cls) -> None:
        with cls._lock:
            cls._process_state.clear()
            cls._watchdog_state.clear()


class SupervisedProcessSpec:
    """
    Обертка над конфигом процесса, чтобы watchdog мог пересоздать поток при падении.
    """

    def __init__(
        self,
        *,
        name: str,
        command_cfg: Dict[str, Any],
        restart_policy: Dict[str, Any],
        log_dir: Path,
        write_json: bool,
        write_text: bool,
    ) -> None:
        self.name = name
        self.command_cfg = command_cfg
        self.restart_policy = restart_policy
        self.log_dir = log_dir
        self.write_json = write_json
        self.write_text = write_text

    def spawn(self) -> "ProcessSupervisor":
        return ProcessSupervisor(
            name=self.name,
            command_cfg=self.command_cfg,
            restart_policy=self.restart_policy,
            log_dir=self.log_dir,
            write_json=self.write_json,
            write_text=self.write_text,
        )


class SupervisorHealthServer(threading.Thread):
    """
    Простой HTTP health-check API для супервизора.
    Возвращает JSON с состояниями процессов и watchdog.
    """

    def __init__(self, host: str, port: int) -> None:
        super().__init__(name="SupervisorHealthServer", daemon=True)
        self.host = host
        self.port = port
        self._server: Optional[ThreadingHTTPServer] = None
        self._stop_event = threading.Event()

    @classmethod
    def from_config(cls, sup_cfg: Dict[str, Any]) -> Optional["SupervisorHealthServer"]:
        health_cfg = (sup_cfg.get("healthcheck") or {})
        if not health_cfg.get("enabled"):
            return None
        host = health_cfg.get("host", "127.0.0.1")
        port = int(health_cfg.get("port", 8130))
        return cls(host=host, port=port)

    def stop(self) -> None:
        self._stop_event.set()
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    def run(self) -> None:
        def handler_factory():
            store = SupervisorStateStore

            class RequestHandler(BaseHTTPRequestHandler):
                def do_GET(self) -> None:  # type: ignore[override]
                    if self.path not in ("/health", "/healthz", "/supervisor", "/supervisor/health"):
                        self.send_response(404)
                        self.end_headers()
                        return
                    payload = store.snapshot()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"))

                def log_message(self, format: str, *args: Any) -> None:  # pragma: no cover - глушим шум
                    return

            return RequestHandler

        try:
            self._server = ThreadingHTTPServer((self.host, self.port), handler_factory())
            self._server.timeout = 1.0
        except Exception as exc:
            log_error(f"[supervisor] Health-check сервер не запустился ({self.host}:{self.port})", exc=exc)
            return

        log_info(f"[supervisor] health-check API запущен на http://{self.host}:{self.port}/health")
        while not self._stop_event.is_set():
            self._server.handle_request()

        log_info("[supervisor] health-check API остановлен")


class SupervisorWatchdog(threading.Thread):
    """
    Отдельный watchdog, который следит за потоками супервизора (self-monitoring + crash recovery).
    Перезапускает поток, если тот умер или не бился heartbeat.
    """

    def __init__(
        self,
        specs: List[SupervisedProcessSpec],
        threads: List["ProcessSupervisor"],
        *,
        check_interval_sec: float = 5.0,
        stale_threshold_sec: float = 45.0,
    ) -> None:
        super().__init__(name="SupervisorWatchdog", daemon=True)
        self._specs = {spec.name: spec for spec in specs}
        self._threads: Dict[str, ProcessSupervisor] = {t.process_name: t for t in threads}
        self._stop_event = threading.Event()
        self.check_interval_sec = max(1.0, float(check_interval_sec))
        self.stale_threshold_sec = max(self.check_interval_sec * 2, float(stale_threshold_sec))

    def stop(self) -> None:
        self._stop_event.set()
        for thread in list(self._threads.values()):
            with contextlib.suppress(Exception):
                thread.stop()
                thread.join(timeout=5)

    def run(self) -> None:
        SupervisorStateStore.set_watchdog_state(
            status="running",
            started_at=_utc_now_iso(),
            check_interval_sec=self.check_interval_sec,
            stale_threshold_sec=self.stale_threshold_sec,
        )
        while not self._stop_event.is_set():
            now = time.time()
            for name, spec in self._specs.items():
                thread = self._threads.get(name)
                heartbeat = SupervisorStateStore.last_heartbeat(name)
                alive = thread.is_alive() if thread else False
                stale = heartbeat is None or (now - heartbeat) > self.stale_threshold_sec
                stopped_by_user = bool(getattr(thread, "_stop_event", None) and getattr(thread, "_stop_event").is_set())

                if (not alive or stale) and not stopped_by_user and not self._stop_event.is_set():
                    reason = "supervisor_thread_dead" if not alive else "supervisor_heartbeat_stale"
                    state = SupervisorStateStore.get_process_state(name) or {}
                    log_warning(
                        f"[{name}] watchdog сработал: {reason}, перезапускаем поток; "
                        f"last_status={state.get('status')}, exit_code={state.get('exit_code')}, "
                        f"error={state.get('error')}, restart_reason={state.get('restart_reason')}, "
                        f"last_heartbeat_age={None if heartbeat is None else round(now - heartbeat, 2)}s"
                    )
                    if thread and thread.is_alive():
                        with contextlib.suppress(Exception):
                            thread.stop()
                        thread.join(timeout=5)
                    replacement = spec.spawn()
                    self._threads[name] = replacement
                    replacement.start()
                    SupervisorStateStore.heartbeat(name, status="restarted", restart_reason=reason)
            SupervisorStateStore.set_watchdog_state(status="running")
            if self._stop_event.wait(self.check_interval_sec):
                break

        SupervisorStateStore.set_watchdog_state(status="stopped", stopped_at=_utc_now_iso())


class ProcessSupervisor(threading.Thread):
    """
    Поток, который следит за одним процессом и умеет его перезапускать.
    """

    def __init__(
        self,
        *,
        name: str,
        command_cfg: Dict[str, Any],
        restart_policy: Optional[Dict[str, Any]] = None,
        log_dir: Optional[Path] = None,
        write_json: bool = True,
        write_text: bool = True,
    ) -> None:
        super().__init__(name=f"Supervisor-{name}", daemon=True)
        self.process_name = name or "supervised-task"
        self.command_cfg = command_cfg
        self.restart_policy = _normalize_restart_policy(restart_policy)
        base_log_dir = (log_dir or (Path("output") / "supervisor"))
        # фиксируем абсолютный путь, чтобы не зависеть от cwd запуска
        self.log_dir = (Path(base_log_dir).expanduser().resolve()) / self.process_name
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._stop_event = threading.Event()
        self._current_process: Optional[subprocess.Popen[str]] = None
        self._restart_window: Deque[float] = deque()
        self._write_json = write_json
        self._write_text = write_text
        self._restart_count = 0
        self._last_activity_ts = time.perf_counter()
        self._last_restart_reason: Optional[str] = None
        res_cfg = (self.command_cfg.get("resource_monitoring") or self.command_cfg.get("resources") or {})
        memory_leak_window = max(3, int(res_cfg.get("memory_leak_window", 5)))
        self._resource_cfg = {
            "enabled": res_cfg.get("enabled", True),
            "sample_interval_sec": max(0.5, float(res_cfg.get("sample_interval_sec", self.command_cfg.get("flush_interval_sec", 2.0)))),
            "max_memory_mb": res_cfg.get("max_memory_mb"),
            "max_cpu_percent": res_cfg.get("max_cpu_percent"),
            "memory_leak_restart_mb": res_cfg.get("memory_leak_restart_mb"),
            "memory_leak_window": memory_leak_window,
            "network_check_host": res_cfg.get("network_check_host", "8.8.8.8"),
            "network_check_port": int(res_cfg.get("network_check_port", 80)),
            "network_check_timeout_sec": float(res_cfg.get("network_check_timeout_sec", 2.0)),
        }
        self._memory_window: Deque[float] = deque(maxlen=memory_leak_window)
        self._last_resource_snapshot: Optional[Dict[str, Any]] = None
        self._restart_on_exit_zero = bool(self.restart_policy.get("restart_on_exit_0", False))
        self._hang_timeout_sec = float(self.restart_policy.get("hang_timeout_seconds", 0.0) or 0.0)
        self._hang_cpu_threshold = float(self.restart_policy.get("hang_cpu_percent_threshold", 2.0))
        self._restart_on_hang = self.restart_policy.get("restart_on_hang", True)
        self._run_as_user = self.command_cfg.get("user")
        self._run_as_group = self.command_cfg.get("group")
        self._resource_limits = self.command_cfg.get("resource_limits") or {}

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> List[threading.Thread]:
        """
        Разворачивает конфигурацию supervisor в список потоков.
        Поддерживает два варианта:
          supervisor:
            enabled: true
            command: {...}
            restart_policy: {...}
          supervisor:
            enabled: true
            processes:
              - name: "app"
                command: {...}
                restart_policy: {...}
        """
        sup_cfg = (config.get("supervisor") or {})
        if not sup_cfg.get("enabled"):
            return []

        output_dir = Path((config.get("output") or {}).get("directory", "output"))
        output_json = bool((config.get("output") or {}).get("json_format", True))
        output_text = bool((config.get("output") or {}).get("text_format", False))
        if not output_json and not output_text:
            log_warning("[supervisor] Оба формата логов отключены, для надёжности включаем JSON")
            output_json = True
        default_log_dir = Path(sup_cfg.get("log_directory") or (output_dir / "supervisor")).expanduser().resolve()

        processes = list(sup_cfg.get("processes") or [])
        if sup_cfg.get("command"):
            processes.append(
                {
                    "name": sup_cfg.get("name") or "supervised-task",
                    "command": sup_cfg.get("command"),
                    "restart_policy": sup_cfg.get("restart_policy", {}),
                    "log_directory": sup_cfg.get("log_directory"),
                    "enabled": True,
                }
            )

        specs: List[SupervisedProcessSpec] = []
        for raw in processes:
            if raw is None or raw.get("enabled") is False:
                continue
            cmd_cfg = raw.get("command") or {}
            if not cmd_cfg.get("executable"):
                log_warning("Supervisor процесс пропущен: не указан executable")
                continue
            restart_cfg = _normalize_restart_policy(raw.get("restart_policy"))
            log_dir = Path(raw.get("log_directory") or default_log_dir)
            name = raw.get("name") or cmd_cfg.get("id") or "supervised-task"
            specs.append(
                SupervisedProcessSpec(
                    name=name,
                    command_cfg=cmd_cfg,
                    restart_policy=restart_cfg,
                    log_dir=log_dir,
                    write_json=output_json,
                    write_text=output_text,
                )
            )
        threads: List[ProcessSupervisor] = [spec.spawn() for spec in specs]

        result: List[threading.Thread] = list(threads)
        watchdog_cfg = (sup_cfg.get("watchdog") or {})
        watchdog_enabled = watchdog_cfg.get("enabled", True)
        if watchdog_enabled and threads:
            result.append(
                SupervisorWatchdog(
                    specs,
                    threads,
                    check_interval_sec=watchdog_cfg.get("check_interval_sec", 5.0),
                    stale_threshold_sec=watchdog_cfg.get("stale_threshold_sec", 45.0),
                )
            )

        health_server = SupervisorHealthServer.from_config(sup_cfg)
        if health_server:
            result.append(health_server)

        return result

    # --- управление жизненным циклом ---------------------------------------

    def stop(self) -> None:
        self._stop_event.set()
        self._terminate_process()
        SupervisorStateStore.heartbeat(self.process_name, status="stopping")

    def run(self) -> None:
        log_info(
            f"[{self.process_name}] супервизор запущен, логи: {self.log_dir}"
        )
        SupervisorStateStore.heartbeat(self.process_name, status="starting", restart_count=self._restart_count)
        while not self._stop_event.is_set():
            try:
                run_result = self._run_once()
            except Exception as exc:  # pragma: no cover - защита на случай непойманных исключений
                log_error(f"[{self.process_name}] сбой супервизора", exc=exc)
                run_result = {
                    "name": self.process_name,
                    "started_at": _utc_now_iso(),
                    "ended_at": _utc_now_iso(),
                    "exit_code": None,
                    "error": str(exc),
                    "stdout": [],
                    "stderr": [],
                    "command": [],
                    "working_dir": None,
                    "forced_stop_reason": "supervisor_crash",
                }

            should_restart, reason = self._decide_restart(run_result)
            run_result["restart_reason"] = reason
            run_result["restart_count"] = self._restart_count
            self._last_restart_reason = reason
            self._write_logs(run_result)
            SupervisorStateStore.set_run_result(self.process_name, run_result, reason, self._restart_count)

            if not should_restart:
                break

            self._restart_count += 1
            delay = float(self.restart_policy.get("restart_delay_seconds", 5))
            log_info(f"[{self.process_name}] перезапуск через {delay} сек. (причина: {reason or 'policy'})")
            SupervisorStateStore.heartbeat(
                self.process_name, status="restarting", restart_count=self._restart_count, restart_reason=reason
            )
            if self._stop_event.wait(delay):
                break

        SupervisorStateStore.heartbeat(self.process_name, status="stopped", restart_count=self._restart_count)
        log_info(f"[{self.process_name}] супервизор остановлен")

    # --- внутренние методы -------------------------------------------------

    def _run_once(self) -> Dict[str, Any]:
        executable = self.command_cfg.get("executable")
        args = self.command_cfg.get("args", []) or []
        workdir = self.command_cfg.get("working_dir")
        extra_env = self.command_cfg.get("env", {}) or {}

        command = [executable] + list(args)
        env = _build_env(extra_env)

        started_at = _utc_now_iso()
        started_ts = time.perf_counter()
        stdout_lines: List[str] = []
        stderr_lines: List[str] = []
        error: Optional[str] = None
        exit_code: Optional[int] = None
        flush_interval = max(1.0, float(self.command_cfg.get("flush_interval_sec", 2.0)))
        last_flush = started_ts
        resource_interval = max(0.5, float(self._resource_cfg["sample_interval_sec"]))
        last_resource = started_ts
        forced_stop_reason: Optional[str] = None
        pid: Optional[int] = None
        self._last_activity_ts = time.perf_counter()
        self._memory_window.clear()

        log_info(
            f"[{self.process_name}] попытка запуска: {' '.join(command)} (cwd={workdir or os.getcwd()})"
        )

        preexec_fn = self._build_preexec_fn()

        try:
            self._current_process = subprocess.Popen(
                command,
                cwd=workdir,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                preexec_fn=preexec_fn,
            )
            pid = self._current_process.pid
            log_info(
                f"[{self.process_name}] процесс запущен pid={pid} cwd={workdir or os.getcwd()}"
            )
        except Exception as exc:  # pragma: no cover - защита от неверных конфигов
            error = str(exc)
            log_error(f"[{self.process_name}] не удалось запустить процесс", exc=exc)
            return {
                "name": self.process_name,
                "started_at": started_at,
                "ended_at": _utc_now_iso(),
                "exit_code": exit_code,
                "error": error,
                "stdout": stdout_lines,
                "stderr": stderr_lines,
                "command": command,
                "working_dir": workdir,
                "resource_usage": None,
                "forced_stop_reason": forced_stop_reason,
                "pid": pid,
                "last_activity_ts": self._last_activity_ts,
            }

        SupervisorStateStore.heartbeat(self.process_name, status="running", pid=pid, restart_count=self._restart_count)

        stdout_thread = threading.Thread(
            target=self._stream_reader, args=(self._current_process.stdout, stdout_lines, "stdout"), daemon=True
        )
        stderr_thread = threading.Thread(
            target=self._stream_reader, args=(self._current_process.stderr, stderr_lines, "stderr"), daemon=True
        )
        stdout_thread.start()
        stderr_thread.start()

        ps_proc = None
        if psutil is not None:
            try:
                ps_proc = psutil.Process(pid)
                ps_proc.cpu_percent(interval=None)  # прогреваем
            except Exception:
                ps_proc = None

        resource_usage: Optional[Dict[str, Any]] = None

        try:
            # ждем завершения процесса или запроса на остановку
            while self._current_process.poll() is None and not self._stop_event.is_set():
                now = time.perf_counter()

                # мониторинг ресурсов и интернет-доступа процесса
                if self._resource_cfg["enabled"] and (now - last_resource) >= resource_interval:
                    if ps_proc is not None:
                        resource_usage = self._collect_resource_usage(ps_proc)
                        if resource_usage:
                            self._last_resource_snapshot = resource_usage
                            mem = resource_usage.get("memory_mb")
                            if mem is not None:
                                self._memory_window.append(float(mem))
                            if (resource_usage.get("cpu_percent") or 0.0) > self._hang_cpu_threshold:
                                self._mark_activity()
                            # обнаружение зависаний по простоям
                            if (
                                self._restart_on_hang
                                and self._hang_timeout_sec > 0
                                and (now - self._last_activity_ts) > self._hang_timeout_sec
                                and (resource_usage.get("cpu_percent") or 0.0) < self._hang_cpu_threshold
                            ):
                                forced_stop_reason = (
                                    forced_stop_reason
                                    or f"hang_detected(>{self._hang_timeout_sec}s без активности)"
                                )
                                log_warning(f"[{self.process_name}] процесс завис, выключаем")
                                self._terminate_process(kill=True)
                                break

                            forced_stop_reason = forced_stop_reason or self._maybe_enforce_limits(resource_usage)
                            if forced_stop_reason:
                                log_warning(f"[{self.process_name}] {forced_stop_reason}, убиваем процесс")
                                self._terminate_process(kill=True)
                                break
                    SupervisorStateStore.heartbeat(
                        self.process_name,
                        status="running",
                        pid=pid,
                        restart_count=self._restart_count,
                        resource_usage=resource_usage,
                        last_activity_ts=self._last_activity_ts,
                    )
                    last_resource = now

                if now - last_flush >= flush_interval:
                    # лайв-снимок stdout/stderr, даже если процесс еще работает
                    self._write_logs(
                        {
                            "name": self.process_name,
                            "started_at": started_at,
                            "ended_at": None,
                            "duration_seconds": round(now - started_ts, 3),
                            "exit_code": None,
                            "error": error,
                            "stdout": stdout_lines,
                            "stderr": stderr_lines,
                            "command": command,
                            "working_dir": workdir,
                            "resource_usage": resource_usage or self._last_resource_snapshot,
                            "pid": pid,
                            "last_activity_ts": self._last_activity_ts,
                        }
                    )
                    last_flush = now
                time.sleep(0.1)

            if self._stop_event.is_set() and self._current_process.poll() is None:
                self._terminate_process()

            exit_code = self._current_process.wait()
            if exit_code != 0:
                error = error or f"Process exited with code {exit_code}"
        except Exception as exc:  # pragma: no cover - защитный блок
            error = str(exc)
            forced_stop_reason = forced_stop_reason or "supervisor_exception"
            log_error(f"[{self.process_name}] ошибка выполнения процесса", exc=exc)
            self._terminate_process(kill=True)
        finally:
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)
            self._current_process = None

        ended_at = _utc_now_iso()
        duration = round(time.perf_counter() - started_ts, 3)

        log_info(
            f"[{self.process_name}] завершен: exit_code={exit_code}, duration={duration}s"
        )

        return {
            "name": self.process_name,
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_seconds": duration,
            "exit_code": exit_code,
            "error": error,
            "stdout": stdout_lines,
            "stderr": stderr_lines,
            "command": command,
            "working_dir": workdir,
            "resource_usage": resource_usage or self._last_resource_snapshot,
            "forced_stop_reason": forced_stop_reason,
            "pid": pid,
            "last_activity_ts": self._last_activity_ts,
        }

    def _mark_activity(self) -> None:
        self._last_activity_ts = time.perf_counter()

    def _collect_resource_usage(self, proc: "psutil.Process") -> Optional[Dict[str, Any]]:
        try:
            cpu = proc.cpu_percent(interval=None)
            mem_info = proc.memory_info()
            mem_mb = round(mem_info.rss / (1024 * 1024), 2)
            connections = 0
            internet_connected = False
            with contextlib.suppress(Exception):
                conns = proc.connections(kind="inet")
                connections = len(conns)
                internet_connected = any(getattr(c, "status", "") == psutil.CONN_ESTABLISHED for c in conns)
            internet_connected = internet_connected or self._check_internet_connectivity()

            return {
                "cpu_percent": round(float(cpu or 0.0), 2),
                "memory_mb": mem_mb,
                "connections": connections,
                "internet_connected": internet_connected,
            }
        except Exception as exc:
            log_warning(f"[{self.process_name}] не удалось собрать метрики процесса: {exc}")
            return self._last_resource_snapshot

    def _check_internet_connectivity(self) -> bool:
        host = self._resource_cfg.get("network_check_host")
        timeout = float(self._resource_cfg.get("network_check_timeout_sec") or 2.0)
        port = int(self._resource_cfg.get("network_check_port") or 80)
        if not host:
            return False
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    def _maybe_enforce_limits(self, resource_usage: Dict[str, Any]) -> Optional[str]:
        mem_limit = self._resource_cfg.get("max_memory_mb")
        mem_leak_restart = self._resource_cfg.get("memory_leak_restart_mb")
        cpu_limit = self._resource_cfg.get("max_cpu_percent")

        mem_mb = resource_usage.get("memory_mb")
        cpu_percent = resource_usage.get("cpu_percent")

        if mem_limit and mem_mb and float(mem_mb) > float(mem_limit):
            return f"memory_limit_exceeded({mem_mb}MB>{mem_limit}MB)"

        if mem_leak_restart and len(self._memory_window) == self._memory_window.maxlen:
            growth = max(self._memory_window) - min(self._memory_window)
            if growth >= float(mem_leak_restart):
                return f"memory_leak_detected(+{growth:.1f}MB за {self._memory_window.maxlen} сэмплов)"

        if cpu_limit and cpu_percent and float(cpu_percent) > float(cpu_limit):
            return f"cpu_limit_exceeded({cpu_percent}%>{cpu_limit}%)"

        return None

    def _stream_reader(self, pipe, buffer: List[str], label: str) -> None:
        if pipe is None:
            return
        try:
            for line in pipe:
                if self._stop_event.is_set():
                    break
                cleaned = line.rstrip("\n")
                buffer.append(cleaned)
                self._mark_activity()
                log_debug(f"[{self.process_name}][{label}] {cleaned}")
        except Exception as exc:  # pragma: no cover - логирование стриминга
            log_warning(f"[{self.process_name}] stream reader error ({label}): {exc}")

    def _write_logs(self, run_result: Dict[str, Any]) -> None:
        ts = run_result.get("started_at") or _utc_now_iso()
        safe_ts = ts.replace(":", "-").replace("T", "_")
        base_name = f"{self.process_name}_{safe_ts}"
        run_result = dict(run_result)
        run_result.setdefault("restart_count", self._restart_count)
        run_result.setdefault("restart_reason", self._last_restart_reason)

        if self._write_json:
            json_path = self.log_dir / f"{base_name}.json"
            latest_path = self.log_dir / f"{self.process_name}_latest.json"
            try:
                json_payload = json.dumps(run_result, ensure_ascii=False, indent=2)
                json_path.write_text(json_payload, encoding="utf-8")
                latest_path.write_text(json_payload, encoding="utf-8")
                log_debug(f"[{self.process_name}] JSON лог записан: {json_path}")
            except Exception as exc:
                log_error(f"[{self.process_name}] не удалось записать JSON лог", exc=exc)

        if self._write_text:
            txt_path = self.log_dir / f"{base_name}.log"
            try:
                text_lines = [
                    f"name: {run_result.get('name')}",
                    f"started_at: {run_result.get('started_at')}",
                    f"ended_at: {run_result.get('ended_at')}",
                    f"duration_seconds: {run_result.get('duration_seconds')}",
                    f"exit_code: {run_result.get('exit_code')}",
                    f"restart_reason: {run_result.get('restart_reason')}",
                    f"forced_stop_reason: {run_result.get('forced_stop_reason')}",
                    f"restart_count: {run_result.get('restart_count')}",
                    f"error: {run_result.get('error')}",
                    f"resource_usage: {run_result.get('resource_usage')}",
                    "",
                    "[stdout]",
                    *run_result.get("stdout", []),
                    "",
                    "[stderr]",
                    *run_result.get("stderr", []),
                ]
                txt_path.write_text("\n".join(text_lines), encoding="utf-8")
            except Exception as exc:
                log_error(f"[{self.process_name}] не удалось записать текстовый лог", exc=exc)

    def _decide_restart(self, run_result: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        if self._stop_event.is_set():
            return False, None

        mode = (self.restart_policy.get("mode") or "always").lower()
        exit_code = run_result.get("exit_code")
        had_error = bool(run_result.get("error"))
        forced_reason = run_result.get("forced_stop_reason")

        if mode == "never":
            return False, None

        if forced_reason:
            reason = forced_reason
        elif exit_code == 0 and not had_error:
            if mode == "on-failure" and not self._restart_on_exit_zero:
                return False, None
            reason = "exit_code_0_restart" if (self._restart_on_exit_zero or mode == "always") else None
        elif exit_code is None and had_error:
            reason = "process_error"
        else:
            reason = f"exit_code_{exit_code}" if exit_code is not None else "policy_always"

        if not self._register_restart():
            log_error(
                f"[{self.process_name}] превышен лимит перезапусков в минуту, останавливаемся"
            )
            return False, "restart_limit_reached"

        return True, reason or "policy_restart"

    def _register_restart(self) -> bool:
        """
        Возвращает False, если превышен лимит max_restarts_per_minute.
        """
        max_restarts = self.restart_policy.get("max_restarts_per_minute")
        if not max_restarts:
            return True

        now = time.time()
        self._restart_window.append(now)
        while self._restart_window and now - self._restart_window[0] > 60:
            self._restart_window.popleft()

        return len(self._restart_window) <= int(max_restarts)

    def _terminate_process(self, kill: bool = False) -> None:
        proc = self._current_process
        if proc is None:
            return
        try:
            if proc.poll() is None:
                if kill:
                    proc.kill()
                else:
                    proc.terminate()
                proc.wait(timeout=5)
        except Exception:
            with contextlib.suppress(Exception):
                proc.kill()

    def _build_preexec_fn(self):
        """
        Возвращает preexec_fn для запуска под другим пользователем и с лимитами ресурсов.
        """
        user = self._run_as_user
        group = self._run_as_group
        limits = self._resource_limits
        if os.name == "nt" or not (user or group or limits):
            if user or group:
                log_warning(f"[{self.process_name}] смена пользователя не поддерживается на этой платформе")
            return None

        resolved_uid: Optional[int] = None
        resolved_gid: Optional[int] = None

        # заранее резолвим uid/gid, чтобы не падать внутри preexec_fn
        if group and grp is not None:
            try:
                resolved_gid = int(group) if str(group).isdigit() else grp.getgrnam(str(group)).gr_gid
            except Exception as exc:
                log_warning(f"[{self.process_name}] не удалось найти group={group}: {exc}")
                resolved_gid = None
        if user and pwd is not None:
            try:
                resolved_uid = int(user) if str(user).isdigit() else pwd.getpwnam(str(user)).pw_uid
            except Exception as exc:
                log_warning(f"[{self.process_name}] не удалось найти user={user}: {exc}")
                resolved_uid = None

        if resolved_uid is None and resolved_gid is None and not limits:
            return None

        def preexec():  # type: ignore[return-type]
            try:
                if resolved_gid is not None:
                    os.setgid(resolved_gid)
                if resolved_uid is not None:
                    os.setuid(resolved_uid)
                if resource is not None and limits:
                    mem_mb = limits.get("memory_mb") or limits.get("max_memory_mb")
                    if mem_mb:
                        byte_limit = int(float(mem_mb) * 1024 * 1024)
                        resource.setrlimit(resource.RLIMIT_AS, (byte_limit, byte_limit))
                    cpu_seconds = limits.get("cpu_seconds")
                    if cpu_seconds:
                        cpu_limit = int(cpu_seconds)
                        resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
            except Exception as exc:
                # В preexec мы уже находимся в дочернем процессе после fork.
                # Логирование через logging здесь может повиснуть из-за блокировок,
                # поэтому пишем напрямую в stderr и продолжаем без падения.
                try:
                    os.write(2, f"[{self.process_name}] preexec_fn пропущен: {exc}\\n".encode("utf-8", "ignore"))
                except Exception:
                    pass

        return preexec
