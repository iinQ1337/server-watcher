#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@file net_checker.py
@brief Сетевые проверки: открытые порты, TCP, SMTP, TLS сертификаты
@details Асинхронно проверяет доступность портов, выполняет TCP-пробы,
         проверяет SMTP-серверы (EHLO/STARTTLS/LOGIN/NOOP) и собирает
         информацию о TLS-сертификатах (issuer/subject/SAN/срок).
@author Monitoring Module
@date 2025-11-10
"""

import asyncio
import socket
import ssl
import smtplib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ===== ВСПОМОГАТЕЛЬНЫЕ УТИЛИТЫ =====

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _dt_from_cert_str(value: str) -> Optional[datetime]:
    """
    Парсит notBefore/notAfter из ssl.getpeercert() в datetime (UTC).
    Формат обычно: 'May  1 12:00:00 2026 GMT'
    """
    try:
        # Учитываем двойной пробел для дня <10
        dt = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


async def _tcp_connect(
    host: str,
    port: int,
    timeout: float = 3.0,
    use_tls: bool = False,
    server_hostname: Optional[str] = None,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    ssl_ctx = None
    if use_tls:
        ssl_ctx = ssl.create_default_context()
    return await asyncio.wait_for(
        asyncio.open_connection(
            host=host,
            port=port,
            ssl=ssl_ctx,
            server_hostname=server_hostname if use_tls else None,
        ),
        timeout=timeout,
    )


async def _check_port(host: str, port: int, timeout: float) -> Dict[str, Any]:
    start = _utcnow()
    result: Dict[str, Any] = {"host": host, "port": port, "open": False}
    try:
        reader, writer = await _tcp_connect(host, port, timeout=timeout)
        # успешное соединение — порт открыт
        result["open"] = True
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except Exception as e:
        result["error"] = str(e)
    finally:
        elapsed = (_utcnow() - start).total_seconds() * 1000.0
        result["latency_ms"] = round(elapsed, 1)
    return result


async def _tcp_probe(
    host: str,
    port: int,
    timeout: float,
    payload: Optional[bytes],
    expect_contains: Optional[bytes],
    use_tls: bool,
) -> Dict[str, Any]:
    start = _utcnow()
    res: Dict[str, Any] = {
        "host": host,
        "port": port,
        "use_tls": use_tls,
        "success": False,
        "response_preview": None,
    }
    try:
        reader, writer = await _tcp_connect(
            host, port, timeout=timeout, use_tls=use_tls, server_hostname=host
        )

        if payload:
            writer.write(payload)
            await writer.drain()

        # читаем немного ответа (до 8 КБ или до таймаута)
        try:
            data = await asyncio.wait_for(reader.read(8192), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""

        if data:
            preview = data[:1024]
            try:
                res["response_preview"] = preview.decode("utf-8", errors="replace")
            except Exception:
                res["response_preview"] = repr(preview)

        if expect_contains is None:
            res["success"] = True
        else:
            res["success"] = data and (expect_contains in data)

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    except Exception as e:
        res["error"] = str(e)
    finally:
        res["latency_ms"] = round(((_utcnow() - start).total_seconds() * 1000.0), 1)
    return res


def _smtp_probe_sync(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Синхронная SMTP-проба на smtplib (вызовется через asyncio.to_thread).
    Поддерживает: TLS/STARTTLS, EHLO, LOGIN (если user/pass), NOOP.
    """
    host: str = params["host"]
    port: int = params.get("port", 25)
    timeout: float = params.get("timeout", 5.0)
    use_ssl: bool = params.get("tls", False)
    starttls: bool = params.get("starttls", False)
    username: Optional[str] = params.get("username")
    password: Optional[str] = params.get("password")
    helo_host: Optional[str] = params.get("helo_host")

    res: Dict[str, Any] = {
        "host": host,
        "port": port,
        "tls": use_ssl,
        "starttls": starttls,
        "connected": False,
        "ehlo_ok": False,
        "starttls_ok": False,
        "auth_ok": False,
        "noop_ok": False,
        "features": [],
        "banner": None,
        "error": None,
    }

    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(host=host, port=port, timeout=timeout)
        else:
            server = smtplib.SMTP(host=host, port=port, timeout=timeout)

        try:
            code, banner = server.connect(host=host, port=port)
        except (TypeError, smtplib.SMTPServerDisconnected):
            # некоторые реализации уже подключены в конструкторе
            code, banner = (220, b"")

        res["connected"] = code == 220
        res["banner"] = banner.decode("utf-8", errors="replace") if isinstance(banner, (bytes, bytearray)) else str(banner)

        # EHLO
        ehlo_domain = helo_host or "localhost"
        code, msg = server.ehlo(ehlo_domain)
        res["ehlo_ok"] = 200 <= code < 300
        if hasattr(server, "esmtp_features"):
            res["features"] = sorted(list(server.esmtp_features.keys()))

        # STARTTLS (если требуется и поддерживается)
        if starttls:
            if "starttls" in getattr(server, "esmtp_features", {}):
                import ssl as _ssl
                ctx = _ssl.create_default_context()
                code, msg = server.starttls(context=ctx)
                res["starttls_ok"] = 200 <= code < 300
                # после STARTTLS — повторный EHLO
                code, msg = server.ehlo(ehlo_domain)
                # обновим features
                if hasattr(server, "esmtp_features"):
                    res["features"] = sorted(list(server.esmtp_features.keys()))
            else:
                res["starttls_ok"] = False

        # AUTH (если заданы логин/пароль)
        if username and password:
            try:
                server.login(username, password)
                res["auth_ok"] = True
            except Exception as e:
                res["auth_ok"] = False
                res["auth_error"] = str(e)

        # NOOP
        try:
            code, msg = server.noop()
            res["noop_ok"] = 200 <= code < 300
        except Exception:
            res["noop_ok"] = False

        try:
            server.quit()
        except Exception:
            try:
                server.close()
            except Exception:
                pass

    except Exception as e:
        res["error"] = str(e)

    return res


async def _smtp_probe(params: Dict[str, Any]) -> Dict[str, Any]:
    # выполняем синхронную логику в отдельном потоке
    start = _utcnow()
    res = await asyncio.to_thread(_smtp_probe_sync, params)
    res["latency_ms"] = round(((_utcnow() - start).total_seconds() * 1000.0), 1)
    # success-условие: подключились и EHLO ок (и если просили starttls — он ок)
    success = res.get("connected") and res.get("ehlo_ok")
    if params.get("starttls"):
        success = success and res.get("starttls_ok")
    res["success"] = bool(success)
    return res


async def _fetch_certificate(
    host: str,
    port: int,
    timeout: float,
) -> Dict[str, Any]:
    start = _utcnow()
    res: Dict[str, Any] = {
        "host": host,
        "port": port,
        "error": None,
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "expired": None,
        "san": [],
    }

    try:
        ctx = ssl.create_default_context()
        # Проверяем цепочку (CERT_REQUIRED по умолчанию),
        # но не валим проверку из-за несоответствия hostname.
        ctx.check_hostname = False

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            # Пустой словарь — считаем это проблемой сертификата
            res["error"] = "Empty certificate info (verify_mode=CERT_REQUIRED)"
            return res

        # subject/issuer
        def _name_tuple_to_str(t):
            try:
                return ", ".join(["{}={}".format(k, v) for k, v in t])
            except Exception:
                return str(t)

        if cert.get("subject"):
            res["subject"] = " / ".join(
                _name_tuple_to_str(t) for t in cert["subject"]
            )
        if cert.get("issuer"):
            res["issuer"] = " / ".join(
                _name_tuple_to_str(t) for t in cert["issuer"]
            )

        # SAN
        san = cert.get("subjectAltName") or []
        res["san"] = [val for (kind, val) in san if kind.lower() in ("dns", "ip")]

        # Даты
        nb = cert.get("notBefore")
        na = cert.get("notAfter")
        res["not_before"] = nb
        res["not_after"] = na

        dt_nb = _dt_from_cert_str(nb) if nb else None
        dt_na = _dt_from_cert_str(na) if na else None

        if dt_na:
            days_left = (dt_na - _utcnow()).days
            res["days_remaining"] = days_left
            res["expired"] = days_left < 0

    except ssl.SSLCertVerificationError as e:
        # Проблема с цепочкой/доверенностью сертификата
        res["error"] = f"certificate verification failed: {e}"
    except Exception as e:
        res["error"] = str(e)
    finally:
        res["latency_ms"] = round(((_utcnow() - start).total_seconds() * 1000.0), 1)

    return res


# ===== ОСНОВНАЯ ТОЧКА ВХОДА =====

async def check_network(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    @brief Запускает сетевые проверки по конфигу network_monitoring
    Ожидаемый формат:
      {
        "enabled": true,
        "ports": [
          {"host": "example.com", "ports": [80, 443], "timeout_ms": 1500},
          {"host": "1.2.3.4", "ports": [22, 25]}
        ],
        "tcp_checks": [
          {
            "host": "example.com", "port": 443, "use_tls": true,
            "send": "HEAD / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n",
            "expect_contains": "HTTP/1.", "timeout_ms": 3000
          }
        ],
        "smtp": [
          {"host": "smtp.example.com", "port": 587, "starttls": true, "username": "", "password": "", "timeout_ms": 5000}
        ],
        "certificates": [
          {"host": "example.com", "port": 443, "warn_days": 30, "timeout_ms": 3000}
        ]
      }
    """
    result: Dict[str, Any] = {
        "enabled": config.get("enabled", False),
        "overall_status": "disabled",
        "ports": {
            "total_targets": 0, "open": 0, "closed_or_timeout": 0, "results": []
        },
        "tcp": {
            "total_checks": 0, "successful": 0, "failed": 0, "results": []
        },
        "smtp": {
            "total_servers": 0, "successful": 0, "failed": 0, "results": []
        },
        "certificates": {
            "total_hosts": 0, "ok": 0, "warn": 0, "expired": 0, "results": []
        },
    }

    if not result["enabled"]:
        return result

    result["overall_status"] = "ok"

    # ---- Порты (open/closed)
    ports_cfg: List[Dict[str, Any]] = config.get("ports", [])
    port_tasks: List[asyncio.Task] = []
    for item in ports_cfg:
        host = item["host"]
        timeout = (item.get("timeout_ms", 1500) / 1000.0)
        for p in item.get("ports", []):
            port_tasks.append(asyncio.create_task(_check_port(host, int(p), timeout)))
    if port_tasks:
        port_results = await asyncio.gather(*port_tasks)
        result["ports"]["results"] = port_results
        result["ports"]["total_targets"] = len(port_results)
        for r in port_results:
            if r.get("open"):
                result["ports"]["open"] += 1
            else:
                result["ports"]["closed_or_timeout"] += 1
                if result["overall_status"] == "ok":
                    result["overall_status"] = "warning"

    # ---- TCP-проверки (payload/expect)
    tcp_cfg: List[Dict[str, Any]] = config.get("tcp_checks", [])
    tcp_tasks: List[asyncio.Task] = []
    for tc in tcp_cfg:
        host = tc["host"]
        port = int(tc["port"])
        timeout = (tc.get("timeout_ms", 3000) / 1000.0)
        use_tls = bool(tc.get("use_tls", False))
        send = tc.get("send")
        expect = tc.get("expect_contains")
        payload = send.encode("utf-8") if isinstance(send, str) else (send or None)
        expect_bytes = expect.encode("utf-8") if isinstance(expect, str) else (expect or None)
        tcp_tasks.append(asyncio.create_task(
            _tcp_probe(host, port, timeout, payload, expect_bytes, use_tls)
        ))

    if tcp_tasks:
        tcp_results = await asyncio.gather(*tcp_tasks)
        result["tcp"]["results"] = tcp_results
        result["tcp"]["total_checks"] = len(tcp_results)
        for r in tcp_results:
            if r.get("success"):
                result["tcp"]["successful"] += 1
            else:
                result["tcp"]["failed"] += 1
                result["overall_status"] = "warning"

    # ---- SMTP
    smtp_cfg: List[Dict[str, Any]] = config.get("smtp", [])
    smtp_tasks: List[asyncio.Task] = []
    for s in smtp_cfg:
        params = {
            "host": s["host"],
            "port": int(s.get("port", 25)),
            "timeout": float(s.get("timeout_ms", 5000) / 1000.0),
            "tls": bool(s.get("tls", False)),          # SMTPS (465)
            "starttls": bool(s.get("starttls", False)),# STARTTLS (обычно 587)
            "username": s.get("username"),
            "password": s.get("password"),
            "helo_host": s.get("helo_host"),
        }
        smtp_tasks.append(asyncio.create_task(_smtp_probe(params)))

    if smtp_tasks:
        smtp_results = await asyncio.gather(*smtp_tasks)
        result["smtp"]["results"] = smtp_results
        result["smtp"]["total_servers"] = len(smtp_results)
        for r in smtp_results:
            if r.get("success"):
                result["smtp"]["successful"] += 1
            else:
                result["smtp"]["failed"] += 1
                result["overall_status"] = "warning"

    # ---- Сертификаты
    cert_cfg: List[Dict[str, Any]] = config.get("certificates", [])
    cert_tasks: List[asyncio.Task] = []
    for c in cert_cfg:
        host = c["host"]
        port = int(c.get("port", 443))
        timeout = float(c.get("timeout_ms", 3000) / 1000.0)
        cert_tasks.append(asyncio.create_task(_fetch_certificate(host, port, timeout)))

    if cert_tasks:
        cert_results = await asyncio.gather(*cert_tasks)
        result["certificates"]["results"] = cert_results
        result["certificates"]["total_hosts"] = len(cert_results)
        warn_threshold = int(config.get("warn_days", 30))
        for r in cert_results:
            if r.get("error"):
                result["certificates"]["warn"] += 1
                result["overall_status"] = "warning"
                continue
            days = r.get("days_remaining")
            if days is None:
                result["certificates"]["warn"] += 1
                result["overall_status"] = "warning"
            elif days < 0:
                result["certificates"]["expired"] += 1
                result["overall_status"] = "critical"
            elif days <= warn_threshold:
                result["certificates"]["warn"] += 1
                if result["overall_status"] == "ok":
                    result["overall_status"] = "warning"
            else:
                result["certificates"]["ok"] += 1

    return result
