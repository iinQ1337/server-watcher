#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@file log_checker.py
@brief Модуль анализа системных логов
@details Анализирует указанные лог-файлы на наличие ошибок и критических сообщений
@author Monitoring Module
@date 2025-11-09
"""

import asyncio
import re
from pathlib import Path
from typing import Dict, Any, List

ERROR_PATTERNS = [
    re.compile(r"\bERROR\b", re.IGNORECASE),
    re.compile(r"\bCRITICAL\b", re.IGNORECASE),
    re.compile(r"\bFATAL\b", re.IGNORECASE),
    re.compile(r"\bEXCEPTION\b", re.IGNORECASE),
    re.compile(r"Traceback \(most recent call last\):"),
]

WARNING_PATTERNS = [
    re.compile(r"\bWARNING\b", re.IGNORECASE),
    re.compile(r"\bWARN\b", re.IGNORECASE),
]


def _tail_lines(path: Path, max_lines: int) -> List[str]:
    """
    @brief Возвращает последние max_lines строк файла
    @param path Путь к файлу
    @param max_lines Максимальное количество строк
    """
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        # Попытка в бинарном режиме как fallback
        with path.open("rb") as f:
            lines = f.readlines()
        lines = [l.decode("utf-8", "ignore") for l in lines]

    if len(lines) <= max_lines:
        return lines
    return lines[-max_lines:]


def _analyze_lines(lines: List[str]) -> Dict[str, Any]:
    errors = 0
    warnings = 0
    critical = 0
    last_error_messages: List[str] = []

    for line in lines:
        line_stripped = line.strip()
        if any(p.search(line_stripped) for p in ERROR_PATTERNS):
            errors += 1
            last_error_messages.append(line_stripped)
        if any(p.search(line_stripped) for p in WARNING_PATTERNS):
            warnings += 1
        if "CRITICAL" in line_stripped.upper() or "FATAL" in line_stripped.upper():
            critical += 1

    # Ограничиваем количество сохраняемых сообщений
    if len(last_error_messages) > 10:
        last_error_messages = last_error_messages[-10:]

    return {
        "errors": errors,
        "warnings": warnings,
        "critical": critical,
        "last_errors": last_error_messages,
    }


async def check_logs(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    @brief Анализирует указанные лог-файлы
    @param config Конфигурация мониторинга логов
    @return Словарь с результатами
    """
    log_files = config.get("log_files", [])
    max_lines = int(config.get("max_lines_per_file", 1000))

    result: Dict[str, Any] = {
        "total_files": len(log_files),
        "processed_files": 0,
        "failed_files": 0,
        "files": [],
    }

    loop = asyncio.get_running_loop()

    async def process_file(path_str: str) -> Dict[str, Any]:
        path = Path(path_str)
        file_res: Dict[str, Any] = {
            "path": str(path),
            "exists": path.exists(),
            "error": None,
            "total_lines": None,
            "analyzed_lines": None,
            "errors": 0,
            "warnings": 0,
            "critical": 0,
            "last_errors": [],
        }

        if not path.exists():
            file_res["error"] = "File not found"
            return file_res
        if not path.is_file():
            file_res["error"] = "Not a regular file"
            return file_res

        try:
            # выполняем блокирующее чтение в пуле потоков
            lines = await loop.run_in_executor(None, _tail_lines, path, max_lines)
            file_res["analyzed_lines"] = len(lines)

            # Примерно оцениваем общее количество строк
            try:
                with path.open("r", encoding="utf-8", errors="ignore") as f:
                    file_res["total_lines"] = sum(1 for _ in f)
            except Exception:
                pass

            stats = _analyze_lines(lines)
            file_res.update(stats)
        except Exception as e:
            file_res["error"] = str(e)

        return file_res

    tasks = [process_file(str(p)) for p in log_files]
    files_res = await asyncio.gather(*tasks, return_exceptions=True)

    for item in files_res:
        if isinstance(item, Exception):
            result["failed_files"] += 1
            result["files"].append({"error": str(item)})
        else:
            result["files"].append(item)
            if item.get("error"):
                result["failed_files"] += 1
            else:
                result["processed_files"] += 1

    return result
