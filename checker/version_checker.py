#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@file version_checker.py
@brief Модуль проверки версий установленных библиотек (Python + Node)
@details Проверяет устаревшие пакеты и потенциальные уязвимости
@author Monitoring Module
@date 2025-11-09
"""

import asyncio
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

from utils.logger import log_debug, log_error, log_info, log_warning


# ===== PYTHON / PIP =====


def get_installed_packages() -> List[Dict[str, str]]:
    """
    @brief Получает список установленных Python пакетов
    @return Список словарей с информацией о пакетах
    @throws subprocess.CalledProcessError При ошибках выполнения команды
    """
    try:
        result = subprocess.run(
            ["pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            check=True,
        )
        packages = json.loads(result.stdout)
        return packages
    except subprocess.CalledProcessError as e:
        raise Exception(f"Error getting installed packages: {e}")
    except json.JSONDecodeError as e:
        raise Exception(f"Error parsing pip output: {e}")


async def check_pypi_version(
    session: aiohttp.ClientSession,
    package_name: str,
    timeout: int = 10,
) -> Optional[str]:
    """
    @brief Проверяет последнюю версию пакета на PyPI
    @param session Асинхронная HTTP сессия
    @param package_name Название пакета
    @param timeout Таймаут запроса в секундах
    @return Последняя доступная версия или None при ошибке
    """
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as response:
            if response.status == 200:
                data = await response.json()
                return data.get("info", {}).get("version")
            return None
    except Exception:
        return None


def compare_versions(current: str, latest: str) -> Tuple[bool, str]:
    """
    @brief Сравнивает версии пакетов
    @param current Текущая версия
    @param latest Последняя версия
    @return Кортеж (нужно обновление, статус)
    """
    try:
        from packaging import version

        current_v = version.parse(current)
        latest_v = version.parse(latest)

        if current_v < latest_v:
            major_diff = getattr(latest_v, "major", 0) - getattr(current_v, "major", 0)
            if major_diff > 0:
                return True, "major_update_available"
            return True, "update_available"
        if current_v > latest_v:
            return False, "ahead_of_pypi"
        return False, "up_to_date"

    except Exception:
        # Fallback к простому сравнению строк
        if current != latest:
            return True, "update_available"
        return False, "up_to_date"


# ===== NODE / NPM =====


async def check_npm_version(
    session: aiohttp.ClientSession,
    package_name: str,
    timeout: int = 10,
) -> Optional[str]:
    """
    @brief Проверяет последнюю версию npm-пакета в реестре npm
    @param session Асинхронная HTTP сессия
    @param package_name Название пакета (включая scope, например @types/node)
    @param timeout Таймаут запроса в секундах
    @return Последняя доступная версия или None при ошибке
    """
    # npm registry: https://registry.npmjs.org/<name>/latest
    url = f"https://registry.npmjs.org/{package_name}/latest"
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as response:
            if response.status == 200:
                data = await response.json()
                # обычно версия лежит прямо в поле "version"
                version = data.get("version") or data.get("dist-tags", {}).get("latest")
                return version
            return None
    except Exception:
        return None


def _resolve_node_project_dir(raw_path: str) -> Optional[Path]:
    """
    @brief Пытается найти директорию проекта Node.js (где лежит package.json)
    @details Поддерживаются:
             * путь к корню проекта (/var/www/app)
             * путь к node_modules (/var/www/app/node_modules)
             * путь к любому файлу внутри проекта (поиск вверх до 3 уровней)
    """
    path = Path(raw_path).expanduser().resolve()
    if not path.exists():
        return None

    # /path/to/project
    if path.is_dir() and (path / "package.json").exists():
        return path

    # /path/to/project/node_modules
    if path.name == "node_modules" and (path.parent / "package.json").exists():
        return path.parent

    # Попробовать подняться выше максимум на 3 уровня
    for parent in list(path.parents)[:3]:
        if (parent / "package.json").exists():
            return parent

    return None


def _get_npm_dependencies(project_dir: Path) -> Dict[str, str]:
    """
    @brief Возвращает {имя_пакета: версия} для top-level зависимостей проекта
    @throws Exception если npm не установлен или вывод не удаётся распарсить
    """
    try:
        result = subprocess.run(
            ["npm", "ls", "--json", "--depth=0"],
            cwd=str(project_dir),
            capture_output=True,
            text=True,
            check=False,  # npm часто возвращает non-zero из-за warning'ов
        )
    except FileNotFoundError as e:
        raise Exception("npm is not installed or not found in PATH") from e

    if not result.stdout.strip():
        raise Exception(f"Empty npm ls output for {project_dir}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise Exception(
            f"Cannot parse npm ls JSON for {project_dir}: {e}"
        ) from e

    deps = data.get("dependencies") or {}
    versions: Dict[str, str] = {}
    for name, info in deps.items():
        if not isinstance(info, dict):
            continue
        ver = info.get("version") or info.get("resolved") or "unknown"
        versions[name] = ver

    return versions


def _collect_node_packages(
    paths: List[str],
    exclude_packages: List[str],
) -> List[Dict[str, Any]]:
    """
    @brief Собирает уникальный список npm пакетов из заданных путей проектов
    @param paths Список путей к проектам или их node_modules
    @param exclude_packages Список имён пакетов, которые нужно игнорировать
    @return Список словарей {name, version, projects}
    """
    excluded = set(exclude_packages)
    aggregated: Dict[str, Dict[str, Any]] = {}

    for raw_path in paths:
        project_dir = _resolve_node_project_dir(raw_path)
        if not project_dir:
            continue

        deps = _get_npm_dependencies(project_dir)

        for name, ver in deps.items():
            if name in excluded:
                continue

            if name not in aggregated:
                aggregated[name] = {
                    "name": name,
                    "version": ver,
                    "projects": {str(project_dir)},
                }
            else:
                # Если в разных проектах разные версии — запоминаем самую "новую"
                current_ver = aggregated[name]["version"]
                needs_update, _ = compare_versions(current_ver, ver)
                if needs_update:  # значит ver > current_ver (по нашей логике)
                    aggregated[name]["version"] = ver
                aggregated[name]["projects"].add(str(project_dir))

    # Преобразуем множество проектов в список для сериализации
    for pkg in aggregated.values():
        pkg["projects"] = sorted(pkg["projects"])

    return list(aggregated.values())


async def check_node_versions(node_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    @brief Проверяет версии Node.js (npm) пакетов на основе секции config["node"]
    @param node_config Подсекция конфигурации version_monitoring.node
    @return Словарь с результатами проверки npm пакетов
    """
    result: Dict[str, Any] = {
        "enabled": node_config.get("enabled", False),
        "total_packages": 0,
        "up_to_date": 0,
        "updates_available": 0,
        "major_updates_available": 0,
        "check_failed": 0,
        "packages": [],
    }

    if not result["enabled"]:
        return result

    paths: List[str] = node_config.get("paths", [])
    exclude_packages: List[str] = node_config.get("exclude_packages", [])

    log_info(f"[Versions][Node] Старт проверки npm пакетов из {len(paths)} путей")

    try:
        collected = _collect_node_packages(paths, exclude_packages)
        result["total_packages"] = len(collected)
        log_debug(f"[Versions][Node] Собрано {len(collected)} пакетов для проверки")

        if not collected:
            return result

        connector = aiohttp.TCPConnector(limit=20)
        timeout = aiohttp.ClientTimeout(total=30)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
        ) as session:

            async def check_package(pkg: Dict[str, Any]) -> Dict[str, Any]:
                package_result: Dict[str, Any] = {
                    "name": pkg["name"],
                    "current_version": pkg["version"],
                    "latest_version": None,
                    "status": "unknown",
                    "needs_update": False,
                    "source": "npm",
                    "projects": pkg.get("projects", []),
                }

                try:
                    latest = await check_npm_version(session, pkg["name"])
                    if latest:
                        package_result["latest_version"] = latest
                        needs_update, status = compare_versions(
                            pkg["version"],
                            latest,
                        )
                        package_result["needs_update"] = needs_update
                        package_result["status"] = status
                    else:
                        package_result["status"] = "registry_check_failed"
                except Exception as e:  # noqa: BLE001
                    package_result["status"] = "error"
                    package_result["error"] = str(e)

                return package_result

            tasks = [check_package(pkg) for pkg in collected]
            packages = await asyncio.gather(*tasks)

        result["packages"] = packages

        # Подсчёт статистики
        for pkg in packages:
            status = pkg.get("status")
            if status in ("up_to_date", "ahead_of_pypi"):
                result["up_to_date"] += 1
            elif status == "update_available":
                result["updates_available"] += 1
            elif status == "major_update_available":
                result["major_updates_available"] += 1
            else:
                result["check_failed"] += 1

    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)
        log_error("[Versions][Node] Ошибка проверки npm пакетов", exc=e)

    return result


# ===== ОБЩАЯ ФУНКЦИЯ ПРОВЕРКИ =====


async def check_versions(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    @brief Проверяет версии всех установленных пакетов (Python + Node)
    @param config Конфигурация проверки версий (version_monitoring)
    @return Словарь с результатами проверки
    """
    check_pypi = config.get("check_pypi", True)
    exclude_packages = config.get("exclude_packages", [])

    result: Dict[str, Any] = {
        "total_packages": 0,
        "up_to_date": 0,
        "updates_available": 0,
        "major_updates_available": 0,
        "check_failed": 0,
        "packages": [],       # Python
        # "node": {...} появится ниже, если включено
    }

    log_info("[Versions] Старт проверки Python пакетов")

    try:
        # --- Python / pip ---
        installed = get_installed_packages()
        installed = [p for p in installed if p["name"] not in exclude_packages]
        result["total_packages"] = len(installed)
        log_debug(f"[Versions] Обнаружено {len(installed)} Python пакетов после исключений")

        if not check_pypi:
            # Только список без проверки обновлений
            result["packages"] = installed
            log_info("[Versions] Проверка PyPI отключена, собран только список пакетов")
        else:
            connector = aiohttp.TCPConnector(limit=20)
            timeout = aiohttp.ClientTimeout(total=30)

            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
            ) as session:

                async def check_package(pkg: Dict[str, str]) -> Dict[str, Any]:
                    """Проверяет один Python пакет"""
                    package_result: Dict[str, Any] = {
                        "name": pkg["name"],
                        "current_version": pkg["version"],
                        "latest_version": None,
                        "status": "unknown",
                        "needs_update": False,
                    }

                    try:
                        latest = await check_pypi_version(session, pkg["name"])
                        if latest:
                            package_result["latest_version"] = latest
                            needs_update, status = compare_versions(
                                pkg["version"],
                                latest,
                            )
                            package_result["needs_update"] = needs_update
                            package_result["status"] = status
                        else:
                            package_result["status"] = "pypi_check_failed"
                    except Exception as e:  # noqa: BLE001
                        package_result["status"] = "error"
                        package_result["error"] = str(e)

                    return package_result

                tasks = [check_package(pkg) for pkg in installed]
                packages = await asyncio.gather(*tasks)

            result["packages"] = packages

            # Подсчет статистики по Python
            for pkg in packages:
                status = pkg.get("status")
                if status in ("up_to_date", "ahead_of_pypi"):
                    result["up_to_date"] += 1
                elif status == "update_available":
                    result["updates_available"] += 1
                elif status == "major_update_available":
                    result["major_updates_available"] += 1
                else:
                    result["check_failed"] += 1

        # --- Node / npm ---
        node_cfg = config.get("node") or {}
        if node_cfg.get("enabled"):
            result["node"] = await check_node_versions(node_cfg)

    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)
        log_error("[Versions] Ошибка проверки версий", exc=e)

    log_info(
        "[Versions] Завершено: "
        f"total={result.get('total_packages')}, "
        f"updates={result.get('updates_available')}, "
        f"major={result.get('major_updates_available')}, "
        f"failed={result.get('check_failed')}"
    )
    if result.get("error"):
        log_warning(f"[Versions] Ошибка в результате: {result['error']}")

    return result
