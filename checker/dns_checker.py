#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@file dns_checker.py
@brief Модуль проверки DNS записей и WHOIS
@details Проверяет базовые DNS записи (A, AAAA, MX, TXT и т.д.) и информацию WHOIS по доменам
@author Monitoring Module
@date 2025-11-09
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List

from utils.logger import log_error, log_info, log_warning

try:
    import dns.resolver as dns_resolver  # type: ignore
except ImportError:  # type: ignore
    dns_resolver = None  # type: ignore

try:
    import whois  # type: ignore
except ImportError:  # type: ignore
    whois = None  # type: ignore


async def _resolve_records(domain: str, record_types: List[str]) -> Dict[str, Any]:
    """
    @brief Получает DNS записи для домена
    """
    records: Dict[str, Any] = {}
    if dns_resolver is None:
        return {"error": "dnspython not installed. Install with: pip install dnspython"}

    resolver = dns_resolver.Resolver()  # type: ignore[attr-defined]

    for rtype in record_types:
        try:
            answers = await asyncio.get_running_loop().run_in_executor(
                None, resolver.resolve, domain, rtype
            )
            values = []
            for ans in answers:
                values.append(ans.to_text())
            records[rtype] = values
        except Exception as e:
            records[rtype] = {"error": str(e)}

    return records


async def _fetch_whois(domain: str, enabled: bool) -> Dict[str, Any]:
    """
    @brief Получает WHOIS информацию о домене
    """
    if not enabled:
        return {}
    if whois is None:
        return {"error": "python-whois not installed. Install with: pip install python-whois"}

    def _do_whois(name: str):
        return whois.whois(name)  # type: ignore[call-arg]

    try:
        data = await asyncio.get_running_loop().run_in_executor(None, _do_whois, domain)
    except Exception as e:
        return {"error": str(e)}

    result: Dict[str, Any] = {}
    try:
        registrar = getattr(data, "registrar", None) or data.get("registrar")
        creation_date = getattr(data, "creation_date", None) or data.get("creation_date")
        expiration_date = getattr(data, "expiration_date", None) or data.get("expiration_date")
        name_servers = getattr(data, "name_servers", None) or data.get("name_servers")

        from datetime import datetime as _dt

        def _date_to_iso(value):
            if isinstance(value, list):
                if value:
                    value = value[0]
                else:
                    return None
            if isinstance(value, _dt):
                return value.isoformat()
            return str(value) if value is not None else None

        result["registrar"] = registrar
        result["creation_date"] = _date_to_iso(creation_date)
        result["expiration_date"] = _date_to_iso(expiration_date)
        result["name_servers"] = list(name_servers) if name_servers else None

    except Exception:
        # В случае неожиданных структур просто сериализуем словарь как есть
        try:
            result["raw"] = dict(data)
        except Exception:
            result["raw"] = str(data)

    return result


async def _check_single_domain(domain: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    @brief Проверяет один домен
    """
    record_types = config.get("record_types", ["A", "AAAA", "MX", "TXT"])
    check_whois_flag = config.get("check_whois", True)

    res: Dict[str, Any] = {
        "domain": domain,
        "dns": {},
        "whois": {},
        "status": "unknown",
        "error": None,
    }

    log_info(f"[DNS] Проверяем домен {domain}")

    try:
        res["dns"] = await _resolve_records(domain, record_types)
        res["whois"] = await _fetch_whois(domain, check_whois_flag)

        # Определяем статус домена по дате истечения
        status = "ok"
        whois_data = res.get("whois") or {}
        exp_str = whois_data.get("expiration_date")
        if isinstance(exp_str, str):
            try:
                exp_dt = datetime.fromisoformat(exp_str)
                now = datetime.utcnow()
                if exp_dt < now:
                    status = "expired"
                elif exp_dt - now < timedelta(days=30):
                    status = "expiring_soon"
            except Exception:
                pass
        res["status"] = status
    except Exception as e:
        res["error"] = str(e)
        res["status"] = "error"
        log_error(f"[DNS] Ошибка при проверке домена {domain}", exc=e)

    return res


async def check_dns(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    @brief Выполняет DNS и WHOIS проверки для списка доменов
    @param config Конфигурация мониторинга DNS
    @return Словарь с результатами
    """
    domains = config.get("domains", [])
    if not domains:
        return {
            "total_domains": 0,
            "results": [],
            "errors": 0,
        }

    log_info(f"[DNS] Старт проверки {len(domains)} доменов")

    tasks = [_check_single_domain(d, config) for d in domains]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    processed: List[Dict[str, Any]] = []
    errors = 0

    for i, item in enumerate(results):
        if isinstance(item, Exception):
            processed.append(
                {
                    "domain": domains[i],
                    "error": str(item),
                    "status": "error",
                }
            )
            errors += 1
            log_error(f"[DNS] Исключение при проверке домена {domains[i]}", exc=item)  # type: ignore[arg-type]
        else:
            processed.append(item)
            if item.get("status") == "error":
                errors += 1
                log_warning(f"[DNS] Ошибка в результате для {item.get('domain')}: {item.get('error')}")

    summary = {
        "total_domains": len(domains),
        "errors": errors,
        "results": processed,
    }
    log_info(f"[DNS] Завершено: total={summary['total_domains']}, errors={summary['errors']}")

    return summary
