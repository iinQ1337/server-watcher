#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@file sensitive_paths_checker.py
@brief Проверка чувствительных файлов и директорий на веб-сайте
@details Пытается открыть набор известных чувствительных путей и определяет,
         какие из них доступны (потенциальная утечка конфигурации, исходников, логов и т.п.). 
@author
@date 2025-11-10
"""

import asyncio
from typing import Dict, Any, List
from urllib.parse import urljoin

import aiohttp

from utils.logger import log_debug, log_error, log_info, log_warning


SENSITIVE_PATHS: List[str] = [
    # --- Файлы окружения и конфигурации ---
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.test",
    ".env.example",
    ".htaccess",
    ".htpasswd",
    "config.php",
    "wp-config.php",
    "configuration.php",
    "database.php",
    "settings.php",
    "local.php",
    "parameters.yml",
    "parameters.yaml",
    "appsettings.json",
    "config.json",
    "config.yml",
    "config.yaml",

    # --- Файлы зависимостей и метаданных ---
    "composer.json",
    "composer.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "vite.config.js",
    "vite.config.ts",
    "webpack.config.js",
    "webpack.mix.js",
    "gulpfile.js",
    "tsconfig.json",
    "babel.config.js",

    # --- Файлы отладки и тестирования ---
    "phpinfo.php",
    "info.php",
    "test.php",
    "debug.php",
    "dev.php",
    "tests/",
    "__tests__/",
    "__mocks__/",
    "spec/",
    "coverage/",
    "jest.config.js",
    "cypress/",
    "playwright.config.js",

    # --- Временные и кеш директории ---
    "tmp/",
    "temp/",
    "cache/",
    "storage/",
    "logs/",
    "log/",
    "runtime/",
    "uploads/tmp/",
    "build/",
    "dist/",
    "out/",
    ".next/",
    ".vercel/",
    ".netlify/",
    "firebase-debug.log",

    # --- Системные директории и исходники ---
    "vendor/",
    "node_modules/",
    "bower_components/",
    "src/",
    "server/",
    "backend/",
    "api/",
    "scripts/",
    "bin/",
    "tools/",
    "private/",
    "internal/",
    "data/",
    "migrations/",
    "seeders/",
    "database/",

    # --- Системы контроля версий ---
    ".git/",
    ".gitignore",
    ".gitattributes",
    ".svn/",
    ".hg/",
    ".idea/",
    ".vscode/",
    ".editorconfig",

    # --- Бэкапы и дампы ---
    "backup.zip",
    "backup.tar",
    "backup.tar.gz",
    "db.sql",
    "dump.sql",
    "database.sql",
    "backup/",
    "backups/",
    "*.bak",
    "*.old",

    # --- Документация и лишние файлы ---
    "README",
    "README.md",
    "README.txt",
    "readme.html",
    "readme.php",
    "LICENSE",
    "LICENSE.txt",
    "CHANGELOG",
    "CHANGELOG.md",
    "composer.phar",
    "install.php",
    "setup.php",
    "installer.php",
    "examples/",
    "docs/",
    "documentation/",
    "samples/",
    "demo/",

    # --- SEO и публичные файлы ---
    "robots.txt",
    "sitemap.xml",
    "sitemap_index.xml",

    # --- Панели и доступ ---
    "admin/",
    "administrator/",
    "wp-admin/",
    "phpmyadmin/",
    "pma/",
    "cpanel/",
    "install/",
    "setup/",
    "installer/",
    "manage/",
    "dashboard/",

    # --- Скрытые и служебные файлы ---
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    "npm-debug.log",
    "yarn-error.log",
    "error_log",
    "debug.log",
    ".env.bak",
    ".env.old",
    ".env.save",

    # --- React / Frontend специфичные ---
    "coverage/",
    ".eslintrc.js",
    ".eslintrc.json",
    ".prettierrc",
    ".prettierrc.js",
    ".prettierignore",
    ".stylelintignore",
    ".stylelintrc",
    ".storybook/",
    ".storybook-static/",
    "vite.config.*",
    "webpack.config.*",
    "tsconfig.node.json",
]


def _normalize_paths(extra_paths: List[str]) -> List[str]:
    base = list(SENSITIVE_PATHS)
    for p in extra_paths:
        if p not in base:
            base.append(p)
    return base


async def _check_single_path(
    session: aiohttp.ClientSession,
    base_url: str,
    path: str,
    timeout: float,
    treat_403_as_exposed: bool,
    treat_401_as_exposed: bool,
) -> Dict[str, Any]:
    # Поддержка шаблонов вида vite.config.* — очень простой подход: просто дергаем как есть.
    # Если хочется реально разворачивать маски, нужно будет расширить.
    url = urljoin(base_url.rstrip("/") + "/", path)

    result: Dict[str, Any] = {
        "base_url": base_url,
        "path": path,
        "url": url,
        "status": None,
        "exposed": False,
        "error": None,
    }

    try:
        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        # Для таких проверок HEAD обычно достаточно, но некоторые сервера не любят HEAD → используем GET.
        async with session.get(url, timeout=timeout_obj, ssl=True) as resp:
            result["status"] = resp.status

            # Что считаем "подозрительно доступным":
            # 200 / 206 — содержимое доступно
            # 301 / 302 / 307 / 308 — редирект (часто тоже нежелателен для скрытых путей)
            # 401 / 403 — часто всё равно признак "существует, но закрыто"
            if resp.status in (200, 206):
                result["exposed"] = True
            elif resp.status in (301, 302, 307, 308):
                result["exposed"] = True
            elif resp.status == 403 and treat_403_as_exposed:
                result["exposed"] = True
            elif resp.status == 401 and treat_401_as_exposed:
                result["exposed"] = True

    except asyncio.TimeoutError:
        result["error"] = "timeout"
    except aiohttp.ClientError as e:
        result["error"] = f"connection error: {e}"
    except Exception as e:
        result["error"] = f"unexpected error: {e}"

    if result["exposed"]:
        log_warning(f"[sensitive_paths] Exposed path detected: {url} (status={result['status']})")
    else:
        log_debug(f"[sensitive_paths] Checked: {url} (status={result['status']}, error={result['error']})")

    return result


async def check_sensitive_paths(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    @brief Проверка чувствительных директорий и файлов
    Ожидаемый формат конфигурации (например, sensitive_paths_monitoring):
      {
        "enabled": true,
        "base_urls": ["https://example.com", "https://app.example.com"],
        "extra_paths": ["custom-secret/"],      # опционально
        "timeout": 5,
        "concurrency": 20,
        "treat_403_as_exposed": true,
        "treat_401_as_exposed": false
      }
    """
    enabled = config.get("enabled", False)
    if not enabled:
        return {"enabled": False, "total_checked": 0, "exposed": 0, "errors": 0, "results": []}

    base_urls: List[str] = config.get("base_urls", [])
    extra_paths: List[str] = config.get("extra_paths", [])
    timeout = float(config.get("timeout", 5))
    concurrency = int(config.get("concurrency", 20))
    treat_403_as_exposed = bool(config.get("treat_403_as_exposed", True))
    treat_401_as_exposed = bool(config.get("treat_401_as_exposed", False))

    if not base_urls:
        return {
            "enabled": True,
            "error": "no base_urls configured",
            "total_checked": 0,
            "exposed": 0,
            "errors": 0,
            "results": [],
        }

    paths = _normalize_paths(extra_paths)
    log_info(
        f"[sensitive_paths] Старт: base_urls={len(base_urls)}, paths={len(paths)}, concurrency={concurrency}, timeout={timeout}s"
    )

    sem = asyncio.Semaphore(concurrency)

    connector = aiohttp.TCPConnector(limit=concurrency * 2)
    client_timeout = aiohttp.ClientTimeout(total=timeout + 2)

    async with aiohttp.ClientSession(connector=connector, timeout=client_timeout) as session:
        tasks = []

        async def wrapped_check(base: str, path: str):
            async with sem:
                return await _check_single_path(
                    session,
                    base,
                    path,
                    timeout=timeout,
                    treat_403_as_exposed=treat_403_as_exposed,
                    treat_401_as_exposed=treat_401_as_exposed,
                )

        for base in base_urls:
            for p in paths:
                tasks.append(asyncio.create_task(wrapped_check(base, p)))

        try:
            raw_results = await asyncio.gather(*tasks, return_exceptions=False)
        except Exception as exc:  # pragma: no cover - защитный блок
            log_error("[sensitive_paths] Ошибка при выполнении проверок", exc=exc)
            return {
                "enabled": True,
                "error": str(exc),
                "total_checked": 0,
                "exposed": 0,
                "errors": 1,
                "results": [],
            }

    exposed = 0
    errors = 0
    for r in raw_results:
        if r.get("exposed"):
            exposed += 1
        if r.get("error"):
            errors += 1

    summary = {
        "enabled": True,
        "total_checked": len(raw_results),
        "exposed": exposed,
        "errors": errors,
        "results": raw_results,
    }
    log_info(
        f"[sensitive_paths] Завершено: total={summary['total_checked']}, exposed={summary['exposed']}, errors={summary['errors']}"
    )
    if errors:
        log_warning(f"[sensitive_paths] Обнаружено {errors} ошибок при проверке")

    return summary
