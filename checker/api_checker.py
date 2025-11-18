#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@file api_checker.py
@brief Проверка API endpoints (GET/POST/PUT/DELETE/HEAD, Bearer, JSON/schema)
"""

import json
import asyncio
import time
from typing import Dict, Any, List

import aiohttp

from utils.logger import log_debug, log_error, log_info, log_large_debug, log_warning


async def check_single_endpoint(
    session: aiohttp.ClientSession,
    endpoint: Dict[str, Any],
    default_timeout: float,
) -> Dict[str, Any]:
    url = endpoint.get("url")
    method = endpoint.get("method", "GET").upper()
    headers = dict(endpoint.get("headers", {}) or {})
    timeout = endpoint.get("timeout", default_timeout)
    expected_status = endpoint.get("expected_status", 200)
    validate_json = endpoint.get("validate_json", False)
    json_schema = endpoint.get("json_schema", {})
    body = endpoint.get("body")
    verify_ssl = endpoint.get("verify_ssl", True)

    data = endpoint.get("data")         # form-data / x-www-form-urlencoded
    params = endpoint.get("params")     # query string (?a=1&b=2)

    # Bearer token support
    auth_cfg = endpoint.get("auth") or {}
    bearer_token = (
        endpoint.get("bearer_token")
        or auth_cfg.get("bearer_token")
        or (auth_cfg.get("token") if auth_cfg.get("type") == "bearer" else None)
    )
    if bearer_token:
        if not any(h.lower() == "authorization" for h in headers.keys()):
            headers["Authorization"] = f"Bearer {bearer_token}"
            log_debug(f"[API checker] Added Bearer token for {url}")
        else:
            log_warning(f"[API checker] Authorization already set for {url}, keep as-is")

    preview_chars = int(endpoint.get("preview_chars", 200))
    log_full_response = bool(endpoint.get("log_full_response", False))
    save_response_to = endpoint.get("save_response_to")

    result: Dict[str, Any] = {
        "url": url,
        "method": method,
        "status": None,
        "response_time": None,
        "success": False,
        "error": None,
    }

    start_time = time.time()

    try:
        timeout_obj = aiohttp.ClientTimeout(total=timeout)

        json_payload = None
        data_payload = None
        if body is not None:
            json_payload = body
        elif data is not None:
            data_payload = data

        async with session.request(
            method=method, url=url, headers=headers,
            json=json_payload, data=data_payload, params=params,
            timeout=timeout_obj, ssl=verify_ssl
        ) as response:
            response_time = (time.time() - start_time) * 1000
            result["response_time"] = round(response_time, 2)
            result["status"] = response.status

            if response.status == expected_status:
                result["success"] = True
            else:
                result["error"] = f"Unexpected status: {response.status} (expected {expected_status})"

            is_head = method == "HEAD"

            if validate_json and result["success"] and not is_head:
                raw_text = await response.text()
                try:
                    response_json = json.loads(raw_text)
                except json.JSONDecodeError as e:
                    result["success"] = False
                    result["error"] = f"Invalid JSON response: {e}"
                    return result

                try:
                    preview = json.dumps(response_json, ensure_ascii=False)[:preview_chars]
                except Exception:
                    preview = str(response_json)[:preview_chars]
                result["response_preview"] = preview

                if log_full_response:
                    try:
                        full_str = json.dumps(response_json, ensure_ascii=False, indent=2)
                    except Exception:
                        full_str = str(response_json)
                    log_large_debug(f"[API full response] {url}\n{full_str}")

                if save_response_to:
                    from pathlib import Path
                    p = Path(save_response_to)
                    p.parent.mkdir(parents=True, exist_ok=True)
                    with p.open("w", encoding="utf-8") as f:
                        json.dump(response_json, f, ensure_ascii=False, indent=2)

                if json_schema:
                    for key in json_schema.get("required_keys", []):
                        if key not in response_json:
                            result["success"] = False
                            result["error"] = f"Missing required key: {key}"
                            break
            else:
                if preview_chars > 0 and result["success"] and not is_head:
                    try:
                        txt = await response.text()
                        result["response_preview"] = txt[:preview_chars]
                    except Exception:
                        pass

    except asyncio.TimeoutError:
        result["error"] = f"Timeout after {timeout}s"
        result["response_time"] = round(timeout * 1000, 2)
        log_warning(f"[API checker] Timeout {method} {url} after {timeout}s")
    except aiohttp.ClientError as e:
        result["error"] = f"Connection error: {str(e)}"
        log_warning(f"[API checker] Connection error {method} {url}: {e}")
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"
        log_warning(f"[API checker] Unexpected error {method} {url}: {e}")

    return result


async def check_api_endpoints(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    @brief Проверяет все API endpoints, указанные в конфигурации
    @param config Конфигурация (api_monitoring)
    @return Сводка результатов
    """
    endpoints: List[Dict[str, Any]] = config.get("endpoints", [])
    if not endpoints:
        return {"total": 0, "successful": 0, "failed": 0, "results": []}

    # Таймаут и параллелизм: endpoint.timeout → api_monitoring.request_timeout_sec → polling.request_timeout_sec → 10
    # concurrency_limit: api_monitoring.concurrency_limit → polling.concurrency_limit → 10
    polling_cfg = (config.get("__root__", {}) or {}).get("polling", {})  # на случай, если ты прокинешь root внутрь
    # fallback: если "__root__" не передан, ниже мы возьмём from defaults
    # Без "__root__": просто попробуем вычитать из глобального блока позже, через разумные дефолты.

    # Прямо из api_monitoring
    default_timeout = float(config.get("request_timeout_sec", None)
                            or polling_cfg.get("request_timeout_sec", 10)
                            or 10)

    concurrency_limit = int(config.get("concurrency_limit", None)
                            or polling_cfg.get("concurrency_limit", 10)
                            or 10)

    log_info(
        f"[API] Начинаем проверки {len(endpoints)} endpoint(ов), timeout={default_timeout}s, concurrency={concurrency_limit}"
    )

    connector = aiohttp.TCPConnector(
        limit=concurrency_limit,
        limit_per_host=concurrency_limit,
    )
    session_timeout = aiohttp.ClientTimeout(total=default_timeout * 2)

    sem = asyncio.Semaphore(concurrency_limit)

    async with aiohttp.ClientSession(
        connector=connector,
        timeout=session_timeout,
    ) as session:

        async def limited_check(ep: Dict[str, Any]):
            async with sem:
                return await check_single_endpoint(session, ep, default_timeout)

        tasks = [limited_check(ep) for ep in endpoints]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    processed_results: List[Dict[str, Any]] = []
    successful = 0
    failed = 0

    for i, result in enumerate(results):
        if isinstance(result, Exception):
            log_error(f"[API] Exception при проверке {endpoints[i].get('url', 'unknown')}", exc=result)  # type: ignore[arg-type]
            processed_results.append({
                "url": endpoints[i].get("url", "unknown"),
                "error": str(result),
                "success": False,
            })
            failed += 1
            continue

        processed_results.append(result)
        if result.get("success"):
            successful += 1
        else:
            log_warning(f"[API] Ошибка {result.get('method')} {result.get('url')}: {result.get('error')}")
            failed += 1

    times = [r.get("response_time", 0) for r in processed_results if r.get("response_time") is not None]
    avg_time = round(sum(times) / len(times), 2) if times else 0.0

    summary = {
        "total": len(endpoints),
        "successful": successful,
        "failed": failed,
        "avg_response_time": avg_time,
        "results": processed_results,
    }
    log_info(
        f"[API] Завершены проверки: total={summary['total']}, ok={summary['successful']}, failed={summary['failed']}, avg={summary['avg_response_time']} ms"
    )
    return summary
