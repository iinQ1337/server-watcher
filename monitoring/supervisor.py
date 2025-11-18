#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@file monitoring/supervisor.py
@brief Мини-супервизор для фоновых скриптов/процессов
@details Запускает внешнюю команду в цикле, собирает stdout/stderr, пишет JSON и текстовые логи,
         применяет политику перезапуска (always/on-failure/never) с защитой от флаппинга.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

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
        self.restart_policy = restart_policy or {}
        base_log_dir = (log_dir or (Path("output") / "supervisor"))
        # фиксируем абсолютный путь, чтобы не зависеть от cwd запуска
        self.log_dir = (Path(base_log_dir).expanduser().resolve()) / self.process_name
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._stop_event = threading.Event()
        self._current_process: Optional[subprocess.Popen[str]] = None
        self._restart_window: Deque[float] = deque()
        self._write_json = write_json
        self._write_text = write_text

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> List["ProcessSupervisor"]:
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

        threads: List[ProcessSupervisor] = []
        for raw in processes:
            if raw is None or raw.get("enabled") is False:
                continue
            cmd_cfg = raw.get("command") or {}
            if not cmd_cfg.get("executable"):
                log_warning("Supervisor процесс пропущен: не указан executable")
                continue
            restart_cfg = raw.get("restart_policy") or {}
            log_dir = Path(raw.get("log_directory") or default_log_dir)
            name = raw.get("name") or cmd_cfg.get("id") or "supervised-task"
            threads.append(
                cls(
                    name=name,
                    command_cfg=cmd_cfg,
                    restart_policy=restart_cfg,
                    log_dir=log_dir,
                    write_json=output_json,
                    write_text=output_text,
                )
            )
        return threads

    # --- управление жизненным циклом ---------------------------------------

    def stop(self) -> None:
        self._stop_event.set()
        self._terminate_process()

    def run(self) -> None:
        log_info(
            f"[{self.process_name}] супервизор запущен, логи: {self.log_dir}"
        )
        while not self._stop_event.is_set():
            run_result = self._run_once()
            self._write_logs(run_result)

            if not self._should_restart(run_result):
                break

            delay = float(self.restart_policy.get("restart_delay_seconds", 5))
            log_info(f"[{self.process_name}] перезапуск через {delay} сек.")
            self._stop_event.wait(delay)

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

        log_info(
            f"[{self.process_name}] старт процесса: {' '.join(command)} (cwd={workdir or os.getcwd()})"
        )

        try:
            self._current_process = subprocess.Popen(
                command,
                cwd=workdir,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
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
            }

        stdout_thread = threading.Thread(
            target=self._stream_reader, args=(self._current_process.stdout, stdout_lines, "stdout"), daemon=True
        )
        stderr_thread = threading.Thread(
            target=self._stream_reader, args=(self._current_process.stderr, stderr_lines, "stderr"), daemon=True
        )
        stdout_thread.start()
        stderr_thread.start()

        try:
            # ждем завершения процесса или запроса на остановку
            while self._current_process.poll() is None and not self._stop_event.is_set():
                now = time.perf_counter()
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
        }

    def _stream_reader(self, pipe, buffer: List[str], label: str) -> None:
        if pipe is None:
            return
        try:
            for line in pipe:
                if self._stop_event.is_set():
                    break
                cleaned = line.rstrip("\n")
                buffer.append(cleaned)
                log_debug(f"[{self.process_name}][{label}] {cleaned}")
        except Exception as exc:  # pragma: no cover - логирование стриминга
            log_warning(f"[{self.process_name}] stream reader error ({label}): {exc}")

    def _write_logs(self, run_result: Dict[str, Any]) -> None:
        ts = run_result.get("started_at") or _utc_now_iso()
        safe_ts = ts.replace(":", "-").replace("T", "_")
        base_name = f"{self.process_name}_{safe_ts}"

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
                    f"error: {run_result.get('error')}",
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

    def _should_restart(self, run_result: Dict[str, Any]) -> bool:
        if self._stop_event.is_set():
            return False

        mode = (self.restart_policy.get("mode") or "always").lower()
        exit_code = run_result.get("exit_code")
        had_error = bool(run_result.get("error"))

        if mode == "never":
            return False
        if mode == "on-failure" and not had_error and exit_code == 0:
            return False

        if not self._register_restart():
            log_error(
                f"[{self.process_name}] превышен лимит перезапусков в минуту, останавливаемся"
            )
            return False

        return True

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
            try:
                proc.kill()
            except Exception:
                pass
