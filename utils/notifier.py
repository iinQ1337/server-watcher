#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@file notifier.py
@brief Модуль отправки уведомлений (Telegram / Discord)
@details Оборачивает отправку в Telegram-бота и Discord webhook, применяя фильтры
         по типам событий, шаблоны сообщений и общие настройки (теги, ретраи и т.д.). 
"""

from typing import Any, Dict, Optional, List
import asyncio
from datetime import datetime

import aiohttp

from utils.logger import log_info, log_warning, log_error, log_debug


# ================== НИЗКОУРОВНЕВЫЕ HTTP-ХЕЛПЕРЫ ==================


async def _post_json(url: str, json_payload: Dict[str, Any], timeout: float = 5.0) -> bool:
    try:
        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=timeout_obj) as session:
            async with session.post(url, json=json_payload) as resp:
                text = await resp.text()
                if 200 <= resp.status < 300:
                    log_debug(f"[notifier] POST JSON {url} OK {resp.status}: {text[:200]}")
                    return True
                log_warning(f"[notifier] POST JSON {url} failed {resp.status}: {text[:200]}")
                return False
    except Exception as e:
        log_error(f"[notifier] POST JSON {url} exception: {e}")
        return False


async def _post_form(url: str, data: Dict[str, Any], timeout: float = 5.0) -> bool:
    try:
        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=timeout_obj) as session:
            async with session.post(url, data=data) as resp:
                text = await resp.text()
                if 200 <= resp.status < 300:
                    log_debug(f"[notifier] POST FORM {url} OK {resp.status}: {text[:200]}")
                    return True
                log_warning(f"[notifier] POST FORM {url} failed {resp.status}: {text[:200]}")
                return False
    except Exception as e:
        log_error(f"[notifier] POST FORM {url} exception: {e}")
        return False


# ================== РЕНДЕРИНГ ШАБЛОНОВ ==================


def _render_template(template: str, context: Dict[str, Any]) -> str:
    """
    Простейший рендер: {{key}} → value из context.
    Никаких внешних шаблонизаторов.
    """
    result = template
    for key, value in context.items():
        placeholder = "{{" + key + "}}"
        result = result.replace(placeholder, str(value))
    return result


def _channel_allows_event(channel_cfg: Dict[str, Any], event_type: str) -> bool:
    """
    Проверяет, разрешено ли событие по notify_on.
    Если список пустой или отсутствует – считаем, что всё разрешено.
    """
    allowed = channel_cfg.get("notify_on")
    if not allowed:
        return True
    return event_type in allowed


def _build_context(
    event_type: str,
    message: Optional[str],
    host: Optional[str],
    details: Optional[str],
    timestamp: Optional[str],
) -> Dict[str, Any]:
    ts = timestamp or datetime.utcnow().isoformat()
    d = details if details is not None else (message or "")
    ctx = {
        "event_type": event_type,
        "host": host or "-",
        "details": d,
        "timestamp": ts,
    }
    return ctx


# ================== КАНАЛЫ: TELEGRAM / DISCORD ==================


async def _send_telegram_message(cfg: Dict[str, Any], text: str) -> bool:
    if not cfg.get("enabled", False):
        return False

    token = cfg.get("bot_token") or ""
    chat_id = cfg.get("chat_id") or ""
    if not token or not chat_id:
        log_warning("[notifier] Telegram enabled, but bot_token/chat_id missing")
        return False

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": cfg.get("parse_mode", "Markdown"),
        "disable_web_page_preview": True,
    }
    timeout = float(cfg.get("timeout_sec", 5))
    ok = await _post_form(url, payload, timeout=timeout)
    if ok:
        log_info("[notifier] Telegram message sent")
    return ok


async def _send_discord_message(cfg: Dict[str, Any], text: str) -> bool:
    if not cfg.get("enabled", False):
        return False

    webhook_url = cfg.get("webhook_url") or ""
    if not webhook_url:
        log_warning("[notifier] Discord enabled, but webhook_url missing")
        return False

    payload: Dict[str, Any] = {"content": text}
    if cfg.get("username"):
        payload["username"] = cfg["username"]
    if cfg.get("avatar_url"):
        payload["avatar_url"] = cfg["avatar_url"]

    timeout = float(cfg.get("timeout_sec", 5))
    ok = await _post_json(webhook_url, payload, timeout=timeout)
    if ok:
        log_info("[notifier] Discord message sent")
    return ok


# ================== ВЫСОКОУРОВНЕВАЯ ФУНКЦИЯ УВЕДОМЛЕНИЙ ==================


async def send_notification(
    notifications_cfg: Dict[str, Any],
    message: Optional[str] = None,
    event_type: str = "generic",
    host: Optional[str] = None,
    details: Optional[str] = None,
    timestamp: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> None:
    """
    @brief Отправляет уведомление в Telegram/Discord согласно конфигу.
    @param notifications_cfg  секция `notifications` из config.yaml
    @param message            необязательный "сырой" текст (если нет шаблона)
    @param event_type         тип события: api_failures, tls_expiry, sensitive_exposed, server_alerts, system_error, ...
    @param host               опционально: хост/сервис, к которому относится событие
    @param details            детали события
    @param timestamp          время; если None — текущий UTC
    @param tags               дополнительные теги; объединятся с notifications.common.tags
    """
    if not notifications_cfg or not notifications_cfg.get("enabled", False):
        log_debug("[notifier] Notifications disabled globally")
        return

    common = notifications_cfg.get("common", {}) or {}
    global_tags: List[str] = common.get("tags", []) or []
    extra_tags: List[str] = tags or []
    all_tags: List[str] = list(dict.fromkeys(global_tags + extra_tags))  # уникальные

    include_tags = bool(common.get("include_tags", True))
    retry_attempts = int(common.get("retry_attempts", 1))

    # Формируем контекст для шаблона
    ctx = _build_context(event_type, message, host, details, timestamp)
    ctx["tags"] = ", ".join(all_tags) if all_tags else ""

    tg_cfg = notifications_cfg.get("telegram", {}) or {}
    dc_cfg = notifications_cfg.get("discord", {}) or {}

    async def send_to_channel(
        channel_name: str,
        channel_cfg: Dict[str, Any],
        raw_sender,
    ):
        if not channel_cfg.get("enabled", False):
            log_debug(f"[notifier] {channel_name} disabled")
            return

        if not _channel_allows_event(channel_cfg, event_type):
            log_debug(f"[notifier] {channel_name} ignores event_type={event_type}")
            return

        template = channel_cfg.get("message_template")
        extra_instr = channel_cfg.get("extra_instructions")

        # Основной текст
        if template:
            text = _render_template(template, ctx)
        else:
            base_text = message or f"{event_type}: {ctx.get('details', '')}"
            # добавим теги префиксом, если включены
            if include_tags and all_tags:
                base_text = f"[{', '.join(all_tags)}] {base_text}"
            text = base_text

        # Если есть шаблон и теги включены, но {{tags}} нет в шаблоне — добавим префиксом
        if template and include_tags and all_tags and "{{tags}}" not in template:
            text = f"[{', '.join(all_tags)}] {text}"

        # Extra instructions (например: "добавить @devops...")
        if extra_instr:
            text = f"{text}\n{extra_instr}"

        # Ретраи
        last_ok = False
        for attempt in range(1, max(1, retry_attempts) + 1):
            ok = await raw_sender(channel_cfg, text)
            if ok:
                last_ok = True
                break
            log_warning(f"[notifier] {channel_name} send attempt {attempt} failed")
            await asyncio.sleep(0.5)
        if not last_ok:
            log_error(f"[notifier] {channel_name} failed after {retry_attempts} attempts")

    tasks = [
        send_to_channel("Telegram", tg_cfg, _send_telegram_message),
        send_to_channel("Discord", dc_cfg, _send_discord_message),
    ]

    await asyncio.gather(*tasks, return_exceptions=True)


