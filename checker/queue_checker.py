#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@file queue_checker.py
@brief Модуль проверки очередей сообщений
@details Проверяет Redis, RabbitMQ и другие очереди
@author Monitoring Module
@date 2025-11-09
"""

import asyncio
import time
from typing import Dict, Any, Optional


async def check_redis_connection(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    @brief Проверяет подключение к Redis
    @param config Конфигурация подключения (host, port, password, db)
    @return Словарь с результатами проверки
    @throws Exception При ошибках подключения
    """
    result = {
        'type': 'redis',
        'host': config.get('host', 'localhost'),
        'port': config.get('port', 6379),
        'db': config.get('db', 0),
        'connected': False,
        'response_time': None,
        'version': None,
        'memory_used': None,
        'keys_count': None,
        'error': None
    }
    
    try:
        import aioredis
        
        start_time = time.time()
        
        redis = await aioredis.create_redis_pool(
            f"redis://{config.get('host', 'localhost')}:{config.get('port', 6379)}",
            password=config.get('password'),
            db=config.get('db', 0),
            timeout=config.get('timeout', 10)
        )
        
        response_time = (time.time() - start_time) * 1000
        result['response_time'] = round(response_time, 2)
        result['connected'] = True
        
        # Получение информации
        info = await redis.info()
        result['version'] = info.get('redis_version')
        result['memory_used'] = info.get('used_memory_human')
        
        # Количество ключей
        dbsize = await redis.dbsize()
        result['keys_count'] = dbsize
        
        # Проверка конкретной очереди (если указана)
        if config.get('queue_name'):
            queue_length = await redis.llen(config['queue_name'])
            result['queue_length'] = queue_length
        
        redis.close()
        await redis.wait_closed()
        
    except ImportError:
        result['error'] = "aioredis not installed. Install with: pip install aioredis"
    except Exception as e:
        result['error'] = str(e)
    
    return result


async def check_rabbitmq_connection(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    @brief Проверяет подключение к RabbitMQ
    @param config Конфигурация подключения
    @return Словарь с результатами проверки
    @throws Exception При ошибках подключения
    """
    result = {
        'type': 'rabbitmq',
        'host': config.get('host', 'localhost'),
        'port': config.get('port', 5672),
        'connected': False,
        'response_time': None,
        'queues': {},
        'error': None
    }
    
    try:
        import aio_pika
        
        start_time = time.time()
        
        connection = await aio_pika.connect_robust(
            host=config.get('host', 'localhost'),
            port=config.get('port', 5672),
            login=config.get('user', 'guest'),
            password=config.get('password', 'guest'),
            virtualhost=config.get('vhost', '/'),
            timeout=config.get('timeout', 10)
        )
        
        response_time = (time.time() - start_time) * 1000
        result['response_time'] = round(response_time, 2)
        result['connected'] = True
        
        # Проверка очередей
        channel = await connection.channel()
        
        for queue_name in config.get('queues', []):
            try:
                queue = await channel.declare_queue(queue_name, passive=True)
                result['queues'][queue_name] = {
                    'message_count': queue.declaration_result.message_count,
                    'consumer_count': queue.declaration_result.consumer_count
                }
            except Exception as e:
                result['queues'][queue_name] = {'error': str(e)}
        
        await connection.close()
        
    except ImportError:
        result['error'] = "aio_pika not installed. Install with: pip install aio-pika"
    except Exception as e:
        result['error'] = str(e)
    
    return result


async def check_queues(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    @brief Проверяет все настроенные очереди
    @param config Конфигурация проверки очередей
    @return Словарь с результатами проверок
    @throws Exception При критических ошибках
    """
    queues = config.get('queues', [])
    
    results = {
        'total': len(queues),
        'connected': 0,
        'failed': 0,
        'queues': []
    }
    
    for queue_config in queues:
        queue_type = queue_config.get('type', 'redis').lower()
        
        try:
            if queue_type == 'redis':
                queue_result = await check_redis_connection(queue_config)
            elif queue_type in ['rabbitmq', 'rabbit']:
                queue_result = await check_rabbitmq_connection(queue_config)
            else:
                queue_result = {
                    'type': queue_type,
                    'error': f"Unsupported queue type: {queue_type}"
                }
            
            if queue_result.get('connected'):
                results['connected'] += 1
            else:
                results['failed'] += 1
            
            results['queues'].append(queue_result)
            
        except Exception as e:
            results['failed'] += 1
            results['queues'].append({
                'type': queue_type,
                'error': str(e),
                'connected': False
            })
    
    return results