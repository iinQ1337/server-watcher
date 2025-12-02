#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@file main.py
@brief Главный модуль системы мониторинга веб-сайтов и API
@details Запускает периодические проверки API, серверов, сетевых сервисов и др.
         Сохраняет результаты и может уведомлять через Telegram/Discord.
@author Monitoring Module
@date 2025-11-10
"""

import asyncio
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from utils.config_loader import load_config
from utils.logger import (
    install_global_exception_hooks,
    log_debug,
    log_error,
    log_info,
    setup_logger,
)
from utils.file_writer import (
    write_json_report,
    write_text_report,
    write_site_reports,
)
from utils.notifier import send_notification

from checker.api_checker import check_api_endpoints
from checker.page_checker import check_web_pages
from checker.server_checker import check_server_status
from checker.version_checker import check_versions
from checker.log_checker import check_logs
from checker.dns_checker import check_dns
from checker.net_checker import check_network
from checker.sensitive_paths_checker import check_sensitive_paths
from monitoring import (
    TaskManagerStream,
    DatabaseStream,
    DockerStream,
    QueueStream,
    ProcessSupervisor,
)
from monitoring.storage import MonitoringStorage

console = Console()


def _print_storage_overview(storage: MonitoringStorage) -> None:
    details = storage.describe()
    table = Table(
        title="Хранилище мониторинга",
        show_header=True,
        header_style="bold cyan",
        show_lines=False,
    )
    table.add_column("Слой", no_wrap=True)
    table.add_column("Хост/путь")
    table.add_column("Порт", no_wrap=True)
    table.add_column("База", no_wrap=True)
    table.add_column("Пользователь", no_wrap=True)
    table.add_column("Пароль", no_wrap=True)
    table.add_column("Активно", no_wrap=True)

    hot = details.get("hot", {})
    cold = details.get("cold", {})
    table.add_row(
        "hot (in-memory)",
        hot.get("host", "-"),
        hot.get("port", "-"),
        hot.get("name", "-"),
        hot.get("user", "-"),
        hot.get("password", "-"),
        hot.get("enabled", "-"),
    )
    table.add_row(
        "cold (on-disk)",
        cold.get("host", "-"),
        cold.get("port", "-"),
        cold.get("name", "-"),
        cold.get("user", "-"),
        cold.get("password", "-"),
        cold.get("enabled", "-"),
    )
    console.print(table)


async def run_all_checks(config: dict, storage: Optional[MonitoringStorage] = None) -> dict:
    """
    @brief Выполняет все проверки мониторинга
    @param config Словарь с конфигурацией
    @return Словарь с результатами всех проверок
    """
    results = {
        "timestamp": datetime.now().isoformat(),
        "checks": {},
    }
    enabled_sections = [
        name
        for name, section in (
            ("api", config.get("api_monitoring", {})),
            ("pages", config.get("page_monitoring", {})),
            ("server", config.get("server_monitoring", {})),
            ("versions", config.get("version_monitoring", {})),
            ("logs", config.get("log_monitoring", {})),
            ("dns", config.get("dns_monitoring", {})),
            ("network", config.get("network_monitoring", {})),
            ("sensitive_paths", config.get("sensitive_paths_monitoring", {})),
        )
        if section.get("enabled", False)
    ]
    log_info(f"Запуск набора проверок: {', '.join(enabled_sections) or 'ничего не включено'}")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:

        # === API Monitoring ===
        if config.get("api_monitoring", {}).get("enabled", False):
            task = progress.add_task("[cyan]Проверка API endpoints...", total=None)
            try:
                api_cfg = config.get("api_monitoring", {})
                # чтобы внутренняя логика знала глобальные параметры polling
                api_cfg["__root__"] = config
                log_info(
                    f"Запуск проверки API ({len(api_cfg.get('endpoints', []))} endpoints)"
                )
                results["checks"]["api"] = await check_api_endpoints(api_cfg)
                stats = results["checks"]["api"]
                log_info(
                    "API проверки завершены: "
                    f"total={stats.get('total')}, ok={stats.get('successful')}, "
                    f"failed={stats.get('failed')}"
                )
            except Exception as e:
                log_error("Ошибка при проверке API", exc=e)
                results["checks"]["api"] = {"error": str(e)}
            progress.remove_task(task)

        # === Web Pages ===
        if config.get("page_monitoring", {}).get("enabled", False):
            task = progress.add_task("[cyan]Проверка веб-страниц...", total=None)
            try:
                pages_cfg = config.get("page_monitoring", {})
                log_info(
                    f"Запуск проверки страниц ({len(pages_cfg.get('pages', []))} шт.)"
                )
                results["checks"]["pages"] = await check_web_pages(
                    pages_cfg
                )
                stats = results["checks"]["pages"]
                log_info(
                    "Проверка страниц завершена: "
                    f"total={stats.get('total')}, ok={stats.get('successful')}, "
                    f"failed={stats.get('failed')}, avg={stats.get('avg_response_time')} ms"
                )
            except Exception as e:
                log_error("Ошибка при проверке страниц", exc=e)
                results["checks"]["pages"] = {"error": str(e)}
            progress.remove_task(task)

        # === Server ===
        if config.get("server_monitoring", {}).get("enabled", False):
            task = progress.add_task("[cyan]Проверка состояния сервера...", total=None)
            try:
                log_info("Запуск проверки состояния сервера")
                results["checks"]["server"] = await check_server_status(
                    config.get("server_monitoring", {})
                )
                stats = results["checks"]["server"]
                log_info(
                    "Проверка сервера завершена: "
                    f"status={stats.get('overall_status')}, "
                    f"cpu={stats.get('cpu', {}).get('percent')}, "
                    f"mem={stats.get('memory', {}).get('percent')}"
                )
            except Exception as e:
                log_error("Ошибка при проверке сервера", exc=e)
                results["checks"]["server"] = {"error": str(e)}
            progress.remove_task(task)

        # === Versions ===
        if config.get("version_monitoring", {}).get("enabled", False):
            task = progress.add_task("[cyan]Проверка версий библиотек...", total=None)
            try:
                log_info("Запуск проверки версий пакетов")
                results["checks"]["versions"] = await check_versions(
                    config.get("version_monitoring", {})
                )
                stats = results["checks"]["versions"]
                log_info(
                    "Проверка версий завершена: "
                    f"total={stats.get('total_packages')}, "
                    f"updates={stats.get('updates_available')}, "
                    f"major={stats.get('major_updates_available')}, "
                    f"failed={stats.get('check_failed')}"
                )
            except Exception as e:
                log_error("Ошибка при проверке версий", exc=e)
                results["checks"]["versions"] = {"error": str(e)}
            progress.remove_task(task)

        # === Logs ===
        if config.get("log_monitoring", {}).get("enabled", False):
            task = progress.add_task("[cyan]Анализ логов...", total=None)
            try:
                log_info(
                    f"Анализируем логи ({len(config.get('log_monitoring', {}).get('log_files', []))} файлов)"
                )
                results["checks"]["logs"] = await check_logs(
                    config.get("log_monitoring", {})
                )
                stats = results["checks"]["logs"]
                log_info(
                    "Анализ логов завершен: "
                    f"processed={stats.get('processed_files')}, "
                    f"failed={stats.get('failed_files')}"
                )
            except Exception as e:
                log_error("Ошибка анализа логов", exc=e)
                results["checks"]["logs"] = {"error": str(e)}
            progress.remove_task(task)

        # === DNS ===
        if config.get("dns_monitoring", {}).get("enabled", False):
            task = progress.add_task("[cyan]Проверка DNS и WHOIS...", total=None)
            try:
                domains = config.get("dns_monitoring", {}).get("domains", [])
                log_info(f"Запуск проверки DNS/WHOIS ({len(domains)} доменов)")
                results["checks"]["dns"] = await check_dns(
                    config.get("dns_monitoring", {})
                )
                stats = results["checks"]["dns"]
                log_info(
                    "DNS проверки завершены: "
                    f"total={stats.get('total_domains')}, errors={stats.get('errors')}"
                )
            except Exception as e:
                log_error("Ошибка DNS проверки", exc=e)
                results["checks"]["dns"] = {"error": str(e)}
            progress.remove_task(task)

        # === Network ===
        if config.get("network_monitoring", {}).get("enabled", False):
            task = progress.add_task(
                "[cyan]Сетевые проверки (порты/TCP/SMTP/TLS)...", total=None
            )
            try:
                net_cfg = config.get("network_monitoring", {}) or {}
                log_info(
                    "Запуск сетевых проверок: "
                    f"ports={len(net_cfg.get('ports', []))}, "
                    f"tcp={len(net_cfg.get('tcp_checks', []))}, "
                    f"smtp={len(net_cfg.get('smtp', []))}, "
                    f"certs={len(net_cfg.get('certificates', []))}"
                )
                results["checks"]["network"] = await check_network(
                    net_cfg
                )
                stats = results["checks"]["network"]
                log_info(
                    "Сетевые проверки завершены: "
                    f"status={stats.get('overall_status')}, "
                    f"ports_open={stats.get('ports', {}).get('open')}, "
                    f"tcp_failed={stats.get('tcp', {}).get('failed')}, "
                    f"smtp_failed={stats.get('smtp', {}).get('failed')}"
                )
            except Exception as e:
                log_error("Ошибка сетевых проверок", exc=e)
                results["checks"]["network"] = {"error": str(e)}
            progress.remove_task(task)

        # === Sensitive Paths ===
        if config.get("sensitive_paths_monitoring", {}).get("enabled", False):
            task = progress.add_task(
                "[cyan]Проверка чувствительных директорий...", total=None
            )
            try:
                sp_cfg = config.get("sensitive_paths_monitoring", {}) or {}
                log_info(
                    f"Проверка чувствительных путей для {len(sp_cfg.get('urls', []))} URL"
                )
                results["checks"]["sensitive_paths"] = await check_sensitive_paths(
                    sp_cfg
                )
                stats = results["checks"]["sensitive_paths"]
                log_info(
                    "Проверка чувствительных директорий завершена: "
                    f"total={stats.get('total')}, exposed={stats.get('exposed')}, "
                    f"errors={stats.get('errors')}"
                )
            except Exception as e:
                log_error("Ошибка проверки чувствительных директорий", exc=e)
                results["checks"]["sensitive_paths"] = {"error": str(e)}
            progress.remove_task(task)

    if storage:
        output_dir = Path(config.get("output", {}).get("directory", "output"))
        storage.store_snapshot(
            category="checks",
            source="monitoring_loop",
            payload=results,
            json_path=output_dir / "latest_checks.json",
        )

    return results


async def save_reports(
    config: dict, results: dict, storage: Optional[MonitoringStorage] = None
) -> None:
    """
    Сохраняет JSON и текстовые отчеты
    """
    output_dir = Path(config.get("output", {}).get("directory", "output"))
    output_dir.mkdir(exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    json_enabled = config.get("output", {}).get("json_format", True)
    text_enabled = config.get("output", {}).get("text_format", False)

    try:
        if config.get("output", {}).get("json_format", True):
            json_path = output_dir / f"report_{date_str}.json"
            write_json_report(results, json_path)
            console.print(f"[green]✓[/green] JSON отчет сохранен: {json_path}")
            log_debug(f"JSON отчет сохранен в {json_path}")

        if config.get("output", {}).get("text_format", False):
            txt_path = output_dir / f"report_{date_str}.txt"
            write_text_report(results, txt_path)
            console.print(f"[green]✓[/green] Текстовый отчет сохранен: {txt_path}")
            log_debug(f"Текстовый отчет сохранен в {txt_path}")

        site_reports = write_site_reports(
            results,
            output_dir,
            date_str,
            write_json=json_enabled,
            write_text=text_enabled,
        )
        if site_reports:
            folders = ", ".join(sorted({site for site, _ in site_reports}))
            console.print(
                f"[green]✓[/green] Созданы per-site отчеты для: {folders}"
            )

        log_info("Отчеты успешно сохранены")
        if storage:
            storage.store_snapshot(
                category="reports",
                source="save_reports",
                payload=results,
                json_path=output_dir / "report_latest.json",
            )
    except Exception as e:
        log_error("Ошибка сохранения отчетов", exc=e)
        console.print(f"[bold red]Ошибка сохранения:[/bold red] {e}")


async def monitoring_loop(config: dict, storage: Optional[MonitoringStorage] = None):
    """
    Бесконечный цикл мониторинга согласно polling.interval_sec
    """
    polling_cfg = config.get("polling", {}) or {}
    interval = int(polling_cfg.get("interval_sec", 60))
    offline_attempts = int(polling_cfg.get("offline_attempts", 3))

    console.print(
        f"[bold cyan]Мониторинг запущен с интервалом {interval} сек.[/bold cyan]\n"
    )
    log_info(
        f"Мониторинг запущен: interval={interval}s, offline_attempts={offline_attempts}"
    )

    fail_counter = 0
    iteration = 0

    while True:
        iteration += 1
        console.print(
            f"\n[white]=== Итерация #{iteration} — {datetime.now().isoformat()} ===[/white]"
        )
        log_info(f"Начало итерации мониторинга #{iteration}")

        # Конфиг для нотификаций берём каждый цикл (на случай hot-reload через файл)
        notifications_cfg = config.get("notifications", {}) or {}
        alerts_cfg = config.get("alerts", {}) or {}
        common_tags = (notifications_cfg.get("common", {}) or {}).get("tags", []) or []

        try:
            results = await run_all_checks(config, storage=storage)
            await save_reports(config, results, storage=storage)

            # === УВЕДОМЛЕНИЯ ПО РЕЗУЛЬТАТАМ ===

            # ---- 1) API FAILURES ----
            if alerts_cfg.get("notify_api_failures", True):
                api_result = results.get("checks", {}).get("api", {}) or {}
                failed_total = int(api_result.get("failed", 0) or 0)
                if failed_total > 0:
                    failed_items = [
                        r
                        for r in api_result.get("results", []) or []
                        if not r.get("success")
                    ][:5]

                    lines = [
                        f"Failed {failed_total} of {api_result.get('total', 0)} API endpoints"
                    ]
                    for r in failed_items:
                        url = r.get("url", "-")
                        status = r.get("status")
                        err = r.get("error")
                        rt = r.get("response_time")
                        pieces = []
                        if status is not None:
                            pieces.append(f"status={status}")
                        if rt is not None:
                            pieces.append(f"{rt} ms")
                        if err:
                            pieces.append(err)
                        line = (
                            f"- {url} :: " + ", ".join(pieces)
                            if pieces
                            else f"- {url}"
                        )
                        lines.append(line)

                    details = "\n".join(lines)
                    # host = первый URL, который реально упал
                    host_url = (
                        failed_items[0].get("url")
                        if failed_items and failed_items[0].get("url")
                        else "api://summary"
                    )

                    await send_notification(
                        notifications_cfg,
                        event_type="api_failures",
                        host=host_url,
                        details=details,
                        tags=common_tags + ["api"],
                    )

            # ---- 2) TLS CERTIFICATE EXPIRY ----
            if alerts_cfg.get("tls_expiry_days") is not None:
                warn_days = int(alerts_cfg.get("tls_expiry_days", 30))
                net = results.get("checks", {}).get("network", {}) or {}
                certs_section = net.get("certificates", {}) or {}
                certs = certs_section.get("results", []) or []

                for c in certs:
                    host = c.get("host")
                    port = c.get("port", 443)
                    err = c.get("error")
                    days = c.get("days_remaining")
                    expired = c.get("expired", False)

                    if host:
                        if port == 443:
                            host_url = f"https://{host}"
                        else:
                            host_url = f"{host}:{port}"
                    else:
                        host_url = "-"

                    if err:
                        details = f"TLS check error: {err}"
                        await send_notification(
                            notifications_cfg,
                            event_type="tls_expiry",
                            host=host_url,
                            details=details,
                            tags=common_tags + ["tls"],
                        )
                        continue

                    if expired:
                        details = f"Certificate EXPIRED (days_remaining={days})"
                        await send_notification(
                            notifications_cfg,
                            event_type="tls_expiry",
                            host=host_url,
                            details=details,
                            tags=common_tags + ["tls"],
                        )
                    elif isinstance(days, (int, float)) and days <= warn_days:
                        details = (
                            f"Certificate expires in {int(days)} days "
                            f"(threshold {warn_days})"
                        )
                        await send_notification(
                            notifications_cfg,
                            event_type="tls_expiry",
                            host=host_url,
                            details=details,
                            tags=common_tags + ["tls"],
                        )

            # ---- 3) SENSITIVE PATHS EXPOSURE ----
            if alerts_cfg.get("notify_sensitive_exposure", True):
                sp = results.get("checks", {}).get("sensitive_paths", {}) or {}
                exposures = []
                for item in sp.get("results", []) or []:
                    exposed = item.get("exposed")
                    status = item.get("status")
                    url = item.get("url") or item.get("full_url") or "-"
                    path = item.get("path") or item.get("resource") or "-"

                    if exposed is True:
                        exposures.append((url, status, path))
                    elif exposed is None:
                        # fallback: считаем экспозицией некоторые "подозрительные" статусы
                        if status in (200, 206, 301, 302, 401, 403):
                            exposures.append((url, status, path))

                if exposures:
                    lines = [
                        f"Found {len(exposures)} exposed sensitive paths:",
                    ]
                    for (url, status, path) in exposures[:10]:
                        lines.append(f"- {url}  [{status}]  ({path})")
                    if len(exposures) > 10:
                        lines.append(f"... and {len(exposures) - 10} more")

                    details = "\n".join(lines)
                    host_url = exposures[0][0] if exposures[0] else "-"

                    await send_notification(
                        notifications_cfg,
                        event_type="sensitive_exposed",
                        host=host_url,
                        details=details,
                        tags=common_tags + ["security", "sensitive"],
                    )

            # ---- 4) SERVER LOAD ALERTS (CPU/MEM/DISK) ----
            if alerts_cfg.get("notify_server_load", True):
                srv = results.get("checks", {}).get("server", {}) or {}
                host_label = (
                    srv.get("hostname") or srv.get("platform") or "server"
                )

                msgs = []
                cpu = srv.get("cpu") or {}
                mem = srv.get("memory") or {}
                disks = srv.get("disk") or {}

                cpu_thr = cpu.get("threshold")
                cpu_pct = cpu.get("percent")
                if isinstance(cpu_pct, (int, float)) and isinstance(
                    cpu_thr, (int, float)
                ) and cpu_pct >= cpu_thr:
                    msgs.append(f"CPU {cpu_pct}% (threshold {cpu_thr}%)")

                mem_thr = mem.get("threshold")
                mem_pct = mem.get("percent")
                if isinstance(mem_pct, (int, float)) and isinstance(
                    mem_thr, (int, float)
                ) and mem_pct >= mem_thr:
                    msgs.append(f"Memory {mem_pct}% (threshold {mem_thr}%)")

                if isinstance(disks, dict):
                    for mount, info in disks.items():
                        if not isinstance(info, dict):
                            continue
                        thr = info.get("threshold")
                        pct = info.get("percent")
                        if isinstance(pct, (int, float)) and isinstance(
                            thr, (int, float)
                        ) and pct >= thr:
                            msgs.append(
                                f"Disk {mount}: {pct}% (threshold {thr}%)"
                            )

                if msgs:
                    details = " / ".join(msgs)
                    await send_notification(
                        notifications_cfg,
                        event_type="server_alerts",
                        host=str(host_label),
                        details=details,
                        tags=common_tags + ["server"],
                    )

            fail_counter = 0  # сброс, если цикл прошел без критической ошибки

        except Exception as e:
            fail_counter += 1
            log_error("Ошибка цикла мониторинга", exc=e)
            if fail_counter >= offline_attempts:
                # при падении самого мониторинга
                await send_notification(
                    notifications_cfg,
                    message=f"⚠️ Мониторинг упал {fail_counter} раз подряд",
                    event_type="system_error",
                    host="monitor",
                    details=str(e),
                    tags=common_tags + ["system"],
                )
                fail_counter = 0  # чтобы не заспамить

        log_debug(f"Итерация #{iteration} завершена, ждем {interval}с до следующей")
        await asyncio.sleep(interval)


async def main():
    console.print("[bold green]Запуск модуля мониторинга[/bold green]\n")

    config: dict
    storage: Optional[MonitoringStorage] = None
    try:
        config = load_config()
        setup_logger(config.get("logging", {}))
        install_global_exception_hooks(asyncio.get_running_loop())
        log_info("Конфигурация успешно загружена")
    except Exception as e:
        console.print(
            f"[bold red]Ошибка загрузки конфигурации:[/bold red] {e}"
        )
        return 1

    output_dir = Path((config.get("output") or {}).get("directory", "output"))
    storage = MonitoringStorage.from_config(config, base_dir=output_dir)
    storage.start()
    _print_storage_overview(storage)

    task_stream: Optional[TaskManagerStream] = TaskManagerStream.from_config(
        config, storage=storage
    )
    db_stream: Optional[DatabaseStream] = DatabaseStream.from_config(
        config, storage=storage
    )
    queue_stream: Optional[QueueStream] = QueueStream.from_config(
        config, storage=storage
    )
    docker_stream: Optional[DockerStream] = DockerStream.from_config(
        config, storage=storage
    )
    supervisor_threads = ProcessSupervisor.from_config(config)

    active_streams = [
        s
        for s in (
            task_stream,
            db_stream,
            queue_stream,
            docker_stream,
            *supervisor_threads,
        )
        if s
    ]
    for stream in active_streams:
        log_debug(f"Стартуем поток {stream.name}")
        stream.start()

    try:
        await monitoring_loop(config, storage=storage)
    finally:
        for stream in active_streams:
            try:
                log_debug(f"Останавливаем поток {stream.name}")
                stream.stop()
            except Exception:
                pass
        for stream in active_streams:
            stream.join(timeout=5)
        if storage:
            storage.stop()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
