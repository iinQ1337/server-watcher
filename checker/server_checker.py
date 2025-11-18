#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@file server_checker.py
@brief Модуль проверки состояния сервера
@details Проверяет загрузку CPU, память, диски, аптайм и сетевую активность
@author Monitoring Module
@date 2025-11-09
"""

import asyncio
import platform
import time
from datetime import datetime
from typing import Dict, Any, Optional

try:
    import psutil
except ImportError:  # type: ignore
    psutil = None  # type: ignore

from utils.logger import log_error, log_info, log_warning

def _get_uptime() -> Optional[float]:
    """
    @brief Возвращает аптайм в секундах, если доступно
    """
    if psutil is None:
        return None
    try:
        boot_time = psutil.boot_time()
        return time.time() - boot_time
    except Exception:
        return None


async def check_server_status(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    @brief Проверяет состояние сервера
    @param config Конфигурация мониторинга сервера
    @return Словарь с результатами проверки
    """
    result: Dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "hostname": platform.node(),
        "platform": platform.platform(),
        "overall_status": "unknown",
        "cpu": {},
        "memory": {},
        "disk": {},
        "uptime": {},
        "network": {},
        "error": None,
    }

    log_info("[Server] Старт проверки состояния сервера")

    if psutil is None:
        result["error"] = "psutil not installed. Install with: pip install psutil"
        result["overall_status"] = "error"
        log_error("[Server] psutil is not installed")
        return result

    thresholds = config.get("thresholds", {})
    cpu_threshold = thresholds.get("cpu_percent", 90)
    mem_threshold = thresholds.get("memory_percent", 90)
    disk_threshold = thresholds.get("disk_percent", 90)

    overall_level = 0  # 0-ok,1-warning,2-critical

    try:
        if config.get("check_cpu", True):
            cpu_percent = psutil.cpu_percent(interval=1.0)
            load_avg = None
            try:
                load_avg = psutil.getloadavg()  # type: ignore[attr-defined]
            except Exception:
                pass

            level = 0
            if cpu_percent >= cpu_threshold:
                level = 2
            elif cpu_percent >= cpu_threshold * 0.8:
                level = 1
            overall_level = max(overall_level, level)

            result["cpu"] = {
                "percent": cpu_percent,
                "load_avg": load_avg,
                "threshold": cpu_threshold,
                "status": "critical" if level == 2 else "warning" if level == 1 else "ok",
            }

        if config.get("check_memory", True):
            vm = psutil.virtual_memory()
            level = 0
            if vm.percent >= mem_threshold:
                level = 2
            elif vm.percent >= mem_threshold * 0.8:
                level = 1
            overall_level = max(overall_level, level)

            result["memory"] = {
                "total": vm.total,
                "used": vm.used,
                "available": vm.available,
                "percent": vm.percent,
                "threshold": mem_threshold,
                "status": "critical" if level == 2 else "warning" if level == 1 else "ok",
            }

        if config.get("check_disk", True):
            disks_info: Dict[str, Any] = {}
            paths = config.get("paths", ["/"])
            worst_level = 0

            for path in paths:
                try:
                    usage = psutil.disk_usage(path)
                    level = 0
                    if usage.percent >= disk_threshold:
                        level = 2
                    elif usage.percent >= disk_threshold * 0.8:
                        level = 1
                    worst_level = max(worst_level, level)

                    disks_info[path] = {
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "percent": usage.percent,
                        "threshold": disk_threshold,
                        "status": "critical" if level == 2 else "warning" if level == 1 else "ok",
                    }
                except Exception as e:
                    disks_info[path] = {"error": str(e), "status": "error"}

            overall_level = max(overall_level, worst_level)
            result["disk"] = disks_info

        if config.get("check_uptime", True):
            uptime_sec = _get_uptime()
            result["uptime"] = {
                "seconds": uptime_sec,
                "human": None,
            }
            if uptime_sec is not None:
                days = int(uptime_sec // 86400)
                hours = int((uptime_sec % 86400) // 3600)
                minutes = int((uptime_sec % 3600) // 60)
                result["uptime"]["human"] = f"{days}d {hours}h {minutes}m"

        if config.get("check_network", True):
            try:
                net_io = psutil.net_io_counters()
                result["network"] = {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv,
                }
            except Exception:
                # Не критично
                pass

    except Exception as e:
        result["error"] = f"Server check failed: {e}"
        result["overall_status"] = "error"
        log_error("[Server] Ошибка проверки сервера", exc=e)
        return result

    if overall_level == 0:
        result["overall_status"] = "ok"
    elif overall_level == 1:
        result["overall_status"] = "warning"
    else:
        result["overall_status"] = "critical"

    log_info(
        f"[Server] Завершено: status={result['overall_status']}, "
        f"cpu={result.get('cpu', {}).get('percent')}, "
        f"mem={result.get('memory', {}).get('percent')}"
    )
    if result["overall_status"] != "ok":
        log_warning(f"[Server] Обнаружены проблемы: {result['overall_status']}")

    return result
