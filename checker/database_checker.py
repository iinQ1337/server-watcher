#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import time
from typing import Dict, Any, Optional


async def check_mysql_connection(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    @brief Проверяет подключение к MySQL
    @param config Конфигурация подключения (host, port, user, password, database)
    @return Словарь с результатами проверки
    @throws Exception При ошибках подключения
    """
    result = {
        'type': 'mysql',
        'host': config.get('host', 'localhost'),
        'port': config.get('port', 3306),
        'database': config.get('database'),
        'connected': False,
        'response_time': None,
        'version': None,
        'error': None
    }
    
    try:
        import aiomysql
        
        start_time = time.time()
        
        connection = await aiomysql.connect(
            host=config.get('host', 'localhost'),
            port=config.get('port', 3306),
            user=config.get('user'),
            password=config.get('password'),
            db=config.get('database'),
            connect_timeout=config.get('timeout', 10)
        )
        
        response_time = (time.time() - start_time) * 1000
        result['response_time'] = round(response_time, 2)
        result['connected'] = True
        
        # Получение версии
        async with connection.cursor() as cursor:
            await cursor.execute("SELECT VERSION()")
            version = await cursor.fetchone()
            result['version'] = version[0] if version else None
            
            # Тестовый запрос
            if config.get('test_query'):
                query_start = time.time()
                await cursor.execute(config['test_query'])
                query_time = (time.time() - query_start) * 1000
                result['test_query_time'] = round(query_time, 2)
        
        connection.close()
        
    except ImportError:
        result['error'] = "aiomysql not installed. Install with: pip install aiomysql"
    except Exception as e:
        result['error'] = str(e)
    
    return result


async def check_postgresql_connection(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    @brief Проверяет подключение к PostgreSQL
    @param config Конфигурация подключения
    @return Словарь с результатами проверки
    @throws Exception При ошибках подключения
    """
    result = {
        'type': 'postgresql',
        'host': config.get('host', 'localhost'),
        'port': config.get('port', 5432),
        'database': config.get('database'),
        'connected': False,
        'response_time': None,
        'version': None,
        'error': None
    }
    
    try:
        import asyncpg
        
        start_time = time.time()
        
        connection = await asyncpg.connect(
            host=config.get('host', 'localhost'),
            port=config.get('port', 5432),
            user=config.get('user'),
            password=config.get('password'),
            database=config.get('database'),
            timeout=config.get('timeout', 10)
        )
        
        response_time = (time.time() - start_time) * 1000
        result['response_time'] = round(response_time, 2)
        result['connected'] = True
        
        # Получение версии
        version = await connection.fetchval('SELECT version()')
        result['version'] = version
        
        # Тестовый запрос
        if config.get('test_query'):
            query_start = time.time()
            await connection.fetch(config['test_query'])
            query_time = (time.time() - query_start) * 1000
            result['test_query_time'] = round(query_time, 2)
        
        await connection.close()
        
    except ImportError:
        result['error'] = "asyncpg not installed. Install with: pip install asyncpg"
    except Exception as e:
        result['error'] = str(e)
    
    return result


async def check_databases(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    @brief Проверяет все настроенные базы данных
    @param config Конфигурация проверки баз данных
    @return Словарь с результатами проверок
    @throws Exception При критических ошибках
    """
    databases = config.get('databases', [])
    
    results = {
        'total': len(databases),
        'connected': 0,
        'failed': 0,
        'databases': []
    }
    
    for db_config in databases:
        db_type = db_config.get('type', 'mysql').lower()
        
        try:
            if db_type == 'mysql':
                db_result = await check_mysql_connection(db_config)
            elif db_type in ['postgresql', 'postgres']:
                db_result = await check_postgresql_connection(db_config)
            else:
                db_result = {
                    'type': db_type,
                    'error': f"Unsupported database type: {db_type}"
                }
            
            if db_result.get('connected'):
                results['connected'] += 1
            else:
                results['failed'] += 1
            
            results['databases'].append(db_result)
            
        except Exception as e:
            results['failed'] += 1
            results['databases'].append({
                'type': db_type,
                'error': str(e),
                'connected': False
            })
    
    return results
