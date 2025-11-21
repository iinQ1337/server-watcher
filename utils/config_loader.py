#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@file config_loader.py
@brief Модуль загрузки конфигурации
@details Загружает конфигурацию из YAML, JSON или переменных окружения
@author Monitoring Module
@date 2025-11-09
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional

import yaml


def load_yaml_config(file_path: str) -> Dict[str, Any]:
    """
    @brief Загружает конфигурацию из YAML файла
    @param file_path Путь к YAML файлу
    @return Словарь с конфигурацией
    @throws FileNotFoundError Если файл не найден
    @throws yaml.YAMLError При ошибках парсинга YAML
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    return config if config else {}


def load_json_config(file_path: str) -> Dict[str, Any]:
    """
    @brief Загружает конфигурацию из JSON файла
    @param file_path Путь к JSON файлу
    @return Словарь с конфигурацией
    @throws FileNotFoundError Если файл не найден
    @throws json.JSONDecodeError При ошибках парсинга JSON
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    return config if config else {}


def load_env_config() -> Dict[str, Any]:
    """
    @brief Загружает конфигурацию из переменных окружения
    @return Словарь с конфигурацией из переменных окружения
    """
    config: Dict[str, Any] = {}

    # Пример: MONITOR_CONFIG_PATH - путь к конфигу
    if os.getenv('MONITOR_CONFIG_PATH'):
        config['config_path'] = os.getenv('MONITOR_CONFIG_PATH')

    # Пример: MONITOR_OUTPUT_DIR - директория для отчетов
    if os.getenv('MONITOR_OUTPUT_DIR'):
        config['output'] = config.get('output', {})
        config['output']['directory'] = os.getenv('MONITOR_OUTPUT_DIR')

    # Пример: MONITOR_LOG_LEVEL - уровень логирования
    if os.getenv('MONITOR_LOG_LEVEL'):
        config['logging'] = config.get('logging', {})
        config['logging']['level'] = os.getenv('MONITOR_LOG_LEVEL')

    return config


def merge_configs(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    @brief Рекурсивно объединяет две конфигурации
    @param base Базовая конфигурация
    @param override Конфигурация для переопределения
    @return Объединенная конфигурация
    """
    result = base.copy()

    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_configs(result[key], value)
        else:
            result[key] = value

    return result


def get_default_config() -> Dict[str, Any]:
    """
    @brief Возвращает конфигурацию по умолчанию
    @return Словарь с конфигурацией по умолчанию
    """
    return {
        'logging': {
            'level': 'INFO',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'file': 'monitoring.log'
        },
        'output': {
            'directory': 'output',
            'json_format': True,
            'text_format': True
        },
        'dashboard': {
            'site_history': {
                'files_per_site': 5,
            },
            'themes': [],
            'active_theme_id': None,
            'task_manager': {
                'enabled': True,
                'interval_sec': 2.0,
                'history_points': 90,
                'top_processes': 8,
            },
            'databases_stream': {
                'enabled': True,
                'interval_sec': 60,
                'thresholds': {
                    'replication_lag_ms': 250,
                    'storage_percent': 85,
                },
                'instances': [],
                'backups': [],
                'alerts': [],
            },
            'docker_stream': {
                'enabled': True,
                'interval_sec': 20,
                'use_cli': True,
                'default_node': None,
                'containers': [],
                'nodes': [],
                'events': [],
            },
        },
        'api_monitoring': {
            'enabled': True,
            'endpoints': []
        },
        'version_monitoring': {
            'enabled': True,
            'check_pypi': True,
            'exclude_packages': [],
            'node': {
                'enabled': False,
                'paths': [],
                'exclude_packages': [],
            },
        },
        'page_monitoring': {
            'enabled': True,
            'pages': []
        },
        'server_monitoring': {
            'enabled': True,
            'check_cpu': True,
            'check_memory': True,
            'check_disk': True,
            'check_uptime': True,
            'check_network': True,
            'thresholds': {
                'cpu_percent': 90,
                'memory_percent': 90,
                'disk_percent': 90
            }
        },
        'security_monitoring': {
            'enabled': True,
            'check_ssl': True,
            'check_headers': True,
            'check_exposed_files': True,
            'urls': []
        },
        'version_monitoring': {
            'enabled': True,
            'check_pypi': True,
            'exclude_packages': []
        },
        'log_monitoring': {
            'enabled': False,
            'log_files': [],
            'max_lines_per_file': 1000
        },
        'dns_monitoring': {
            'enabled': False,
            'check_whois': True,
            'domains': [],
            'record_types': ['A', 'AAAA', 'MX', 'TXT']
        },
        'network_monitoring': {
            'enabled': False,
            'ports': [],         # [{host, ports:[...], timeout_ms}]
            'tcp_checks': [],    # [{host, port, use_tls, send, expect_contains, timeout_ms}]
            'smtp': [],          # [{host, port, tls, starttls, username, password, helo_host, timeout_ms}]
            'certificates': [],  # [{host, port, timeout_ms}]
            'warn_days': 30
        },
        'supervisor': {
            'enabled': False,
            'log_directory': 'output/supervisor',
            'healthcheck': {
                'enabled': False,
                'host': '127.0.0.1',
                'port': 8130,
            },
            'watchdog': {
                'enabled': True,
                'check_interval_sec': 5,
                'stale_threshold_sec': 45,
            },
            'processes': [],
        },
    }


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    @brief Загружает полную конфигурацию из различных источников
    @param config_path Путь к файлу конфигурации (опционально)
    @return Словарь с полной конфигурацией
    @throws FileNotFoundError Если указанный файл не найден
    @throws Exception При ошибках загрузки конфигурации
    """
    # Начинаем с конфигурации по умолчанию
    config = get_default_config()

    # Определяем путь к конфигу
    if config_path is None:
        # Ищем config.yaml или config.json в текущей директории
        if Path('config.yaml').exists():
            config_path = 'config.yaml'
        elif Path('config.yml').exists():
            config_path = 'config.yml'
        elif Path('config.json').exists():
            config_path = 'config.json'
        else:
            # Проверяем переменную окружения
            config_path = os.getenv('MONITOR_CONFIG_PATH')

    # Загружаем файл конфигурации
    if config_path and Path(config_path).exists():
        file_ext = Path(config_path).suffix.lower()

        try:
            if file_ext in ['.yaml', '.yml']:
                file_config = load_yaml_config(config_path)
            elif file_ext == '.json':
                file_config = load_json_config(config_path)
            else:
                raise ValueError(f"Unsupported config format: {file_ext}")

            config = merge_configs(config, file_config)
        except Exception as e:
            raise Exception(f"Error loading config from {config_path}: {e}")

    # Переопределяем переменными окружения
    env_config = load_env_config()
    if env_config:
        config = merge_configs(config, env_config)

    return config
