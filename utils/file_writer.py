#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@file file_writer.py
@brief Модуль функций сохранения отчетов
@details Сохраняет результаты мониторинга в формате JSON и человекочитаемом .txt отчете.
         Дополнительно формирует per-site отчеты в отдельных папках output/<site>/.
"""

import json
from pathlib import Path
from typing import Dict, Any, Union, List, Iterable, Tuple
from urllib.parse import urlparse


PathLike = Union[str, Path]


def write_json_report(data: Dict[str, Any], file_path: PathLike) -> None:
    """
    @brief Сохраняет отчет мониторинга в JSON формате
    @param data Словарь с результатами мониторинга
    @param file_path Путь к JSON-файлу
    @throws OSError При ошибках записи файла
    """
    path = Path(file_path)
    if path.parent:
        path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        json.dump(
            data,
            f,
            ensure_ascii=False,
            indent=2,
        )


def write_text_report(data: Dict[str, Any], file_path: PathLike) -> None:
    """
    @brief Сохраняет человекочитаемый текстовый отчет
    @param data Словарь с результатами мониторинга
    @param file_path Путь к .txt файлу
    @throws OSError При ошибках записи файла
    """
    path = Path(file_path)
    if path.parent:
        path.parent.mkdir(parents=True, exist_ok=True)

    lines: List[str] = []

    # Заголовок
    lines.append("ОТЧЕТ МОНИТОРИНГА ВЕБ-СИСТЕМ")
    lines.append("=" * 40)
    lines.append(f"Время запуска: {data.get('timestamp', '-')}")
    lines.append("")

    checks: Dict[str, Any] = data.get("checks", {})

    # Список выполненных проверок
    if checks:
        lines.append("Выполненные проверки:")
        for name in checks.keys():
            lines.append(f"  - {name}")
        lines.append("")

    # Детальные секции
    if "api" in checks:
        _format_api_section(checks["api"], lines)

    if "pages" in checks:
        _format_pages_section(checks["pages"], lines)

    if "server" in checks:
        _format_server_section(checks["server"], lines)

    if "versions" in checks:
        _format_versions_section(checks["versions"], lines)
        node_section = checks["versions"].get("node")
        if node_section:
            _format_node_section(node_section, lines)

    if "logs" in checks:
        _format_logs_section(checks["logs"], lines)

    if "dns" in checks:
        _format_dns_section(checks["dns"], lines)

    if "network" in checks:
        _format_network_section(checks["network"], lines)

    # Запись в файл
    text = "\n".join(lines) + "\n"
    with path.open("w", encoding="utf-8") as f:
        f.write(text)


def write_site_reports(
    data: Dict[str, Any],
    output_dir: PathLike,
    date_suffix: str,
    *,
    write_json: bool = True,
    write_text: bool = False,
) -> List[Tuple[str, Path]]:
    """
    @brief Сохраняет отчеты по каждому сайту в отдельные директории
    @param data Результаты мониторинга
    @param output_dir Базовая директория output
    @param date_suffix Строка, которая добавляется к имени файла (обычно timestamp)
    @param write_json Создавать JSON файлы
    @param write_text Создавать текстовые файлы
    @return Список пар (site_name, путь до JSON файла) для дальнейшего использования
    """
    site_reports = _split_results_by_site(data)
    if not site_reports:
        return []

    written: List[Tuple[str, Path]] = []
    base_dir = Path(output_dir)

    for site, payload in site_reports.items():
        sanitized = _sanitize_site_name(site)
        site_dir = base_dir / sanitized
        site_dir.mkdir(parents=True, exist_ok=True)

        primary_path: Path | None = None
        file_suffix = f"report_site-{date_suffix}"
        if write_json:
            json_path = site_dir / f"{file_suffix}.json"
            write_json_report(payload, json_path)
            primary_path = json_path

        if write_text:
            txt_path = site_dir / f"{file_suffix}.txt"
            write_text_report(payload, txt_path)
            if primary_path is None:
                primary_path = txt_path

        if primary_path is not None:
            written.append((site, primary_path))

    return written


# ===== ВСПОМОГАТЕЛЬНЫЕ ФОРМАТТЕРЫ СЕКЦИЙ =====

def _separator(title: str) -> str:
    return f"\n{title}\n" + "-" * len(title)


def _format_api_section(section: Dict[str, Any], lines: List[str]) -> None:
    lines.append(_separator("Проверка API endpoints"))

    if "error" in section:
        lines.append(f"Ошибка выполнения проверки: {section['error']}")
        return

    lines.append(f"Всего endpoints: {section.get('total', 0)}")
    lines.append(f"Успешно: {section.get('successful', 0)}")
    lines.append(f"Провалено: {section.get('failed', 0)}")
    lines.append(f"Среднее время ответа: {section.get('avg_response_time', 0)} ms")
    lines.append("")

    results = section.get("results", [])
    if not results:
        lines.append("Нет детальных результатов.")
        return

    lines.append("Детали по endpoints:")
    for r in results:
        status = "OK" if r.get("success") else "FAIL"
        lines.append(f"  [{status}] {r.get('method', 'GET')} {r.get('url', '-')}")
        lines.append(f"    Статус: {r.get('status')}, Время: {r.get('response_time')} ms")
        if r.get("error"):
            lines.append(f"    Ошибка: {r.get('error')}")
        if r.get("response_preview"):
            lines.append(f"    Превью ответа: {r['response_preview']}")
    lines.append("")


def _format_pages_section(section: Dict[str, Any], lines: List[str]) -> None:
    lines.append(_separator("Проверка веб-страниц"))

    if "error" in section:
        lines.append(f"Ошибка выполнения проверки: {section['error']}")
        return

    lines.append(f"Всего страниц: {section.get('total', 0)}")
    lines.append(f"Успешно: {section.get('successful', 0)}")
    lines.append(f"Провалено: {section.get('failed', 0)}")
    lines.append(f"Среднее время ответа: {section.get('avg_response_time', 0)} ms")
    lines.append("")

    results = section.get("results", [])
    if not results:
        lines.append("Нет детальных результатов.")
        return

    lines.append("Детали по страницам:")
    for r in results:
        status = "OK" if r.get("success") else "FAIL"
        title = r.get("title") or "-"
        lines.append(f"  [{status}] {r.get('method', 'GET')} {r.get('url', '-')}")
        lines.append(f"    Статус: {r.get('status')}, Время: {r.get('response_time')} ms")
        lines.append(f"    Заголовок: {title}")
        if r.get("error"):
            lines.append(f"    Ошибка: {r.get('error')}")
    lines.append("")


def _format_server_section(section: Dict[str, Any], lines: List[str]) -> None:
    lines.append(_separator("Состояние сервера"))

    if "error" in section:
        lines.append(f"Ошибка выполнения проверки: {section['error']}")
        return

    lines.append(f"Хост: {section.get('hostname', '-')}")
    lines.append(f"Платформа: {section.get('platform', '-')}")
    lines.append(f"Общий статус: {section.get('overall_status', 'unknown')}")
    lines.append("")

    cpu = section.get("cpu") or {}
    if cpu:
        lines.append("CPU:")
        lines.append(f"  Загрузка: {cpu.get('percent', '-')}% (порог: {cpu.get('threshold', '-')})")
        if cpu.get("load_avg"):
            lines.append(f"  Load average: {cpu.get('load_avg')}")
        lines.append(f"  Статус: {cpu.get('status', '-')}")
        lines.append("")

    mem = section.get("memory") or {}
    if mem:
        lines.append("Память:")
        lines.append(f"  Использовано: {mem.get('used', '-')} / {mem.get('total', '-')} байт")
        lines.append(f"  Процент: {mem.get('percent', '-')}% (порог: {mem.get('threshold', '-')})")
        lines.append(f"  Статус: {mem.get('status', '-')}")
        lines.append("")

    disk = section.get("disk") or {}
    if disk:
        lines.append("Диски:")
        for mount, info in disk.items():
            if not isinstance(info, dict):
                continue
            lines.append(f"  Точка монтирования: {mount}")
            if info.get("error"):
                lines.append(f"    Ошибка: {info['error']}")
            else:
                lines.append(f"    Использовано: {info.get('used', '-')} / {info.get('total', '-')} байт")
                lines.append(f"    Свободно: {info.get('free', '-')} байт")
                lines.append(f"    Процент: {info.get('percent', '-')}% (порог: {info.get('threshold', '-')})")
                lines.append(f"    Статус: {info.get('status', '-')}")
        lines.append("")

    uptime = section.get("uptime") or {}
    if uptime:
        lines.append("Аптайм:")
        lines.append(f"  Секунд: {uptime.get('seconds', '-')}")
        lines.append(f"  Человекочитаемо: {uptime.get('human', '-')}")
        lines.append("")

    network = section.get("network") or {}
    if network:
        lines.append("Сеть (общее):")
        lines.append(f"  Отправлено: {network.get('bytes_sent', '-')} байт")
        lines.append(f"  Получено: {network.get('bytes_recv', '-')} байт")
        lines.append("")


def _format_versions_section(section: Dict[str, Any], lines: List[str]) -> None:
    lines.append(_separator("Проверка версий Python пакетов"))

    if "error" in section:
        lines.append(f"Ошибка выполнения проверки: {section['error']}")
        return

    lines.append(f"Всего пакетов: {section.get('total_packages', 0)}")
    lines.append(f"Актуальны: {section.get('up_to_date', 0)}")
    lines.append(f"Нужны обновления: {section.get('updates_available', 0)}")
    lines.append(f"Мажорные обновления: {section.get('major_updates_available', 0)}")
    lines.append(f"Проверка не удалась: {section.get('check_failed', 0)}")
    lines.append("")

    packages = section.get("packages", [])
    if not packages:
        lines.append("Нет детальной информации по пакетам.")
        lines.append("")
        return

    lines.append("Пакеты с обновлениями:")
    for pkg in packages:
        if not pkg.get("needs_update"):
            continue
        name = pkg.get("name")
        cur = pkg.get("current_version")
        latest = pkg.get("latest_version")
        status = pkg.get("status", "update_available")
        lines.append(f"  {name}: {cur} -> {latest} ({status})")
    lines.append("")


def _format_node_section(section: Dict[str, Any], lines: List[str]) -> None:
    lines.append(_separator("Проверка версий Node.js пакетов (npm)"))

    if not section.get("enabled", False):
        lines.append("Проверка Node.js зависимостей отключена.")
        lines.append("")
        return

    if "error" in section:
        lines.append(f"Ошибка выполнения проверки npm пакетов: {section['error']}")
        lines.append("")
        return

    lines.append(f"Всего пакетов: {section.get('total_packages', 0)}")
    lines.append(f"Актуальны: {section.get('up_to_date', 0)}")
    lines.append(f"Нужны обновления: {section.get('updates_available', 0)}")
    lines.append(f"Мажорные обновления: {section.get('major_updates_available', 0)}")
    lines.append(f"Проверка не удалась: {section.get('check_failed', 0)}")
    lines.append("")

    packages = section.get("packages", [])
    if not packages:
        lines.append("Нет детальной информации по npm пакетам.")
        lines.append("")
        return

    to_update = [p for p in packages if p.get("needs_update")]
    if not to_update:
        lines.append("Все отслеживаемые npm пакеты актуальны.")
        lines.append("")
        return

    lines.append("npm пакеты с доступными обновлениями:")
    for pkg in to_update:
        name = pkg.get("name")
        cur = pkg.get("current_version")
        latest = pkg.get("latest_version") or "?"
        status = pkg.get("status", "update_available")
        source = pkg.get("source", "npm")
        projects = pkg.get("projects") or []

        lines.append(f"  {name}: {cur} -> {latest} ({status}, источник: {source})")
        if projects:
            lines.append(f"    Проекты: {', '.join(projects)}")
    lines.append("")


def _format_logs_section(section: Dict[str, Any], lines: List[str]) -> None:
    lines.append(_separator("Анализ лог-файлов"))

    if "error" in section:
        lines.append(f"Ошибка выполнения проверки: {section['error']}")
        return

    lines.append(f"Всего файлов: {section.get('total_files', 0)}")
    lines.append(f"Обработано: {section.get('processed_files', 0)}")
    lines.append(f"С ошибками: {section.get('failed_files', 0)}")
    lines.append("")

    files = section.get("files", [])
    if not files:
        lines.append("Нет детальной информации по файлам.")
        return

    for f in files:
        path = f.get("path", "-")
        lines.append(f"Файл: {path}")
        if f.get("error"):
            lines.append(f"  Ошибка: {f.get('error')}")
            continue
        lines.append(f"  Строк всего: {f.get('total_lines', '-')}")
        lines.append(f"  Проанализировано строк: {f.get('analyzed_lines', '-')}")
        lines.append(f"  Ошибок: {f.get('errors', 0)}")
        lines.append(f"  Предупреждений: {f.get('warnings', 0)}")
        lines.append(f"  Критических: {f.get('critical', 0)}")

        last_errors = f.get("last_errors") or []
        if last_errors:
            lines.append("  Последние ошибки:")
            for msg in last_errors:
                lines.append(f"    {msg}")
        lines.append("")


def _format_dns_section(section: Dict[str, Any], lines: List[str]) -> None:
    lines.append(_separator("Проверка DNS и WHOIS"))

    if "error" in section:
        lines.append(f"Ошибка выполнения проверки: {section['error']}")
        return

    lines.append(f"Всего доменов: {section.get('total_domains', 0)}")
    lines.append(f"Ошибок: {section.get('errors', 0)}")
    lines.append("")

    results = section.get("results", [])
    if not results:
        lines.append("Нет детальной информации по доменам.")
        return

    for d in results:
        domain = d.get("domain", "-")
        lines.append(f"Домен: {domain}")
        if d.get("error"):
            lines.append(f"  Ошибка: {d.get('error')}")
            continue

        lines.append(f"  Статус: {d.get('status', 'unknown')}")

        dns_info = d.get("dns") or {}
        if dns_info:
            lines.append("  DNS записи:")
            for rtype, value in dns_info.items():
                if isinstance(value, dict) and value.get("error"):
                    lines.append(f"    {rtype}: ошибка ({value.get('error')})")
                else:
                    lines.append(f"    {rtype}: {value}")

        whois_info = d.get("whois") or {}
        if whois_info:
            lines.append("  WHOIS:")
            if whois_info.get("error"):
                lines.append(f"    Ошибка WHOIS: {whois_info['error']}")
            else:
                registrar = whois_info.get("registrar", "-")
                creation = whois_info.get("creation_date", "-")
                expiration = whois_info.get("expiration_date", "-")
                ns = whois_info.get("name_servers") or "-"
                lines.append(f"    Регистратор: {registrar}")
                lines.append(f"    Создан: {creation}")
                lines.append(f"    Истекает: {expiration}")
                lines.append(f"    NS: {ns}")
        lines.append("")


def _format_network_section(section: Dict[str, Any], lines: List[str]) -> None:
    title = "Сетевые проверки (Порты / TCP / SMTP / Сертификаты)"
    lines.append(_separator(title))

    if not section.get("enabled", False):
        lines.append("Сетевые проверки отключены.")
        lines.append("")
        return

    lines.append(f"Общий статус: {section.get('overall_status', 'unknown')}")
    lines.append("")


# ===== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ PER-SITE ЛОГОВ =====

def _sanitize_site_name(raw: str) -> str:
    cleaned = []
    for ch in raw.lower():
        if ch.isalnum() or ch in (".", "-", "_"):
            cleaned.append(ch)
        else:
            cleaned.append("_")
    candidate = "".join(cleaned).strip("._")
    return candidate or "site"


def _extract_host(value: str) -> str:
    if not value:
        return "unknown"
    try:
        parsed = urlparse(value)
        host = parsed.netloc or parsed.path
        return host or "unknown"
    except Exception:
        return value


def _split_results_by_site(data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Группирует результаты по домену (host) для API/Page секций.
    """
    checks = data.get("checks", {}) or {}
    timestamp = data.get("timestamp")
    per_site: Dict[str, Dict[str, Any]] = {}

    def ensure_site(site_name: str) -> Dict[str, Any]:
        if site_name not in per_site:
            per_site[site_name] = {
                "timestamp": timestamp,
                "site": site_name,
                "checks": {},
            }
        return per_site[site_name]

    def process_results(
        section_key: str,
        items: Iterable[Dict[str, Any]],
        *,
        url_field_candidates: Tuple[str, ...] = ("url", "final_url"),
    ) -> None:
        for entry in items:
            url_value = None
            for field in url_field_candidates:
                url_value = entry.get(field)
                if url_value:
                    break
            site_name = _extract_host(url_value or entry.get("host") or "unknown")
            bucket = ensure_site(site_name)
            checks_bucket = bucket["checks"].setdefault(
                section_key,
                {
                    "total": 0,
                    "successful": 0,
                    "failed": 0,
                    "_latency_sum": 0.0,
                    "_latency_count": 0,
                    "avg_response_time": 0.0,
                    "results": [],
                },
            )

            checks_bucket["results"].append(entry)
            checks_bucket["total"] += 1
            if entry.get("success"):
                checks_bucket["successful"] += 1
            else:
                checks_bucket["failed"] += 1

            latency = entry.get("response_time")
            if isinstance(latency, (int, float)):
                checks_bucket["_latency_sum"] += float(latency)
                checks_bucket["_latency_count"] += 1

    api_section = checks.get("api") or {}
    api_results = api_section.get("results") or []
    process_results("api", api_results)

    page_section = checks.get("pages") or {}
    page_results = page_section.get("results") or []
    process_results("pages", page_results)

    # финализируем среднее время ответа
    for site_data in per_site.values():
        for section_key, section_value in list(site_data["checks"].items()):
            sum_latency = section_value.pop("_latency_sum", 0.0)
            count_latency = section_value.pop("_latency_count", 0)
            if count_latency:
                section_value["avg_response_time"] = round(sum_latency / count_latency, 2)
            else:
                section_value["avg_response_time"] = 0.0

    return per_site

    # --- Порты
    ports = section.get("ports", {})
    lines.append("Порты (open/closed):")
    lines.append(f"  Целей: {ports.get('total_targets', 0)}")
    lines.append(f"  Открыто: {ports.get('open', 0)}")
    lines.append(f"  Закрыто/таймаут: {ports.get('closed_or_timeout', 0)}")
    details = ports.get("results") or []
    if details:
        for r in details[:100]:
            mark = "OPEN" if r.get("open") else "CLOSED"
            host = r.get("host")
            port = r.get("port")
            lat = r.get("latency_ms", "-")
            err = r.get("error")
            lines.append(f"    [{mark}] {host}:{port} ({lat} ms){' — ' + err if err else ''}")
    lines.append("")

    # --- TCP
    tcp = section.get("tcp", {})
    lines.append("TCP-проверки:")
    lines.append(f"  Всего: {tcp.get('total_checks', 0)}")
    lines.append(f"  Успешно: {tcp.get('successful', 0)}")
    lines.append(f"  Провалено: {tcp.get('failed', 0)}")
    td = tcp.get("results") or []
    if td:
        for r in td[:50]:
            ok = "OK" if r.get("success") else "FAIL"
            proto = "TLS" if r.get("use_tls") else "TCP"
            lat = r.get("latency_ms", "-")
            lines.append(f"    [{ok}] {proto} {r.get('host')}:{r.get('port')} ({lat} ms)")
            if r.get("response_preview"):
                lines.append(f"      Превью ответа: {r['response_preview'][:200].replace(chr(10),' ')}")
            if r.get("error"):
                lines.append(f"      Ошибка: {r['error']}")
    lines.append("")

    # --- SMTP
    smtp = section.get("smtp", {})
    lines.append("SMTP-пробы:")
    lines.append(f"  Серверов: {smtp.get('total_servers', 0)}")
    lines.append(f"  Успешно: {smtp.get('successful', 0)}")
    lines.append(f"  Провалено: {smtp.get('failed', 0)}")
    sd = smtp.get("results") or []
    if sd:
        for r in sd[:50]:
            ok = "OK" if r.get("success") else "FAIL"
            lat = r.get("latency_ms", "-")
            tls_mode = "SMTPS" if r.get("tls") else ("SMTP+STARTTLS" if r.get("starttls") else "SMTP")
            lines.append(f"    [{ok}] {tls_mode} {r.get('host')}:{r.get('port')} ({lat} ms)")
            if r.get("banner"):
                lines.append(f"      Баннер: {r['banner'][:150].replace(chr(10),' ')}")
            if r.get("features"):
                lines.append(f"      Фичи: {', '.join(r['features'][:12])}")
            if r.get("auth_ok") is not None:
                lines.append(f"      Аутентификация: {'OK' if r.get('auth_ok') else 'NO'}")
            if r.get("error"):
                lines.append(f"      Ошибка: {r['error']}")
    lines.append("")

    # --- Сертификаты
    certs = section.get("certificates", {})
    lines.append("TLS-сертификаты:")
    lines.append(f"  Хостов: {certs.get('total_hosts', 0)}")
    lines.append(f"  ОК: {certs.get('ok', 0)}")
    lines.append(f"  Предупреждения: {certs.get('warn', 0)}")
    lines.append(f"  Истекшие: {certs.get('expired', 0)}")
    cd = certs.get("results") or []
    if cd:
        for r in cd[:50]:
            host = f"{r.get('host')}:{r.get('port')}"
            if r.get("error"):
                lines.append(f"    [ERR] {host} — {r['error']}")
                continue
            days = r.get("days_remaining")
            status = "EXPIRED" if r.get("expired") else ("WARN" if (days is not None and days <= 30) else "OK")
            lines.append(f"    [{status}] {host} — {days} дн. до истечения")
            if r.get("issuer"):
                lines.append(f"      Issuer: {r['issuer']}")
            if r.get("subject"):
                lines.append(f"      Subject: {r['subject']}")
            if r.get("san"):
                lines.append(f"      SAN: {', '.join(r['san'][:8])}")
            if r.get("not_after"):
                lines.append(f"      До: {r['not_after']}")
    lines.append("")
