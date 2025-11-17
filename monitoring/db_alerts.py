#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Dict, List

from utils.logger import log_debug


def load_alerts(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Возвращает список алертов из секции dashboard.databases_stream.alerts.
    """
    alerts = list((config.get("dashboard") or {}).get("databases_stream", {}).get("alerts") or [])
    if alerts:
        log_debug(f"DB alerts loaded: {len(alerts)} record(s)")
    return alerts
