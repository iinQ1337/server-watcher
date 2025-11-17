#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@file logger.py
@brief Модуль настройки логирования
@details Предоставляет функции для настройки логгера и удобные обёртки для логирования сообщений разных уровней
@author Monitoring Module
@date 2025-11-09
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from typing import Dict, Any, Optional

# Global project logger
LOGGER = logging.getLogger("monitoring")


def _ensure_basic_config() -> None:
    """
    Ensure a basic config is present so early log_* calls work before setup_logger()
    """
    root_logger = logging.getLogger()
    if not root_logger.handlers:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            stream=sys.stdout,
        )


# Basic configuration for early calls
_ensure_basic_config()


def setup_logger(config: Dict[str, Any]) -> logging.Logger:
    """
    Configure the project logger.
    config:
      - level: DEBUG|INFO|WARNING|ERROR|CRITICAL
      - format: log line format
      - file: path to log file
      - console: enable console logging (default True)
      - max_bytes: rotating file max size (default 5MB)
      - backup_count: number of rotations (default 5)
    """
    global LOGGER

    level_name = str(config.get("level", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)
    fmt = config.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    log_file = config.get("file", "monitoring.log")

    console_enabled = config.get("console", True)
    file_enabled = bool(log_file)

    max_bytes = int(config.get("max_bytes", 5 * 1024 * 1024))  # 5 MB
    backup_count = int(config.get("backup_count", 5))

    # Clean previous handlers to avoid duplication
    LOGGER.handlers.clear()
    LOGGER.setLevel(level)
    LOGGER.propagate = False

    formatter = logging.Formatter(fmt)

    if console_enabled:
        console_handler = logging.StreamHandler(stream=sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        LOGGER.addHandler(console_handler)

    if file_enabled:
        try:
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            LOGGER.addHandler(file_handler)
        except Exception as e:
            LOGGER.error(f"Failed to set up file logger: {e}")

    LOGGER.debug("Logger 'monitoring' configured")
    return LOGGER


def get_logger() -> logging.Logger:
    return LOGGER


# --- Standard helpers ---

def log_debug(message: str, exc: Optional[BaseException] = None) -> None:
    LOGGER.debug(message, exc_info=exc) if exc else LOGGER.debug(message)

def log_info(message: str, exc: Optional[BaseException] = None) -> None:
    LOGGER.info(message, exc_info=exc) if exc else LOGGER.info(message)

def log_warning(message: str, exc: Optional[BaseException] = None) -> None:
    LOGGER.warning(message, exc_info=exc) if exc else LOGGER.warning(message)

def log_error(message: str, exc: Optional[BaseException] = None) -> None:
    LOGGER.error(message, exc_info=exc) if exc else LOGGER.error(message)

def log_exception(message: str) -> None:
    LOGGER.exception(message)


# --- Large/long message helpers (prevents line truncation by chunking) ---

def log_large_info(message: str, chunk_size: int = 10000) -> None:
    """
    Log very long messages safely by splitting into chunks.
    """
    if message is None:
        return
    for i in range(0, len(message), chunk_size):
        LOGGER.info(message[i:i+chunk_size])

def log_large_debug(message: str, chunk_size: int = 10000) -> None:
    if message is None:
        return
    for i in range(0, len(message), chunk_size):
        LOGGER.debug(message[i:i+chunk_size])

def log_large_error(message: str, chunk_size: int = 10000) -> None:
    if message is None:
        return
    for i in range(0, len(message), chunk_size):
        LOGGER.error(message[i:i+chunk_size])
