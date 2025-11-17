# Локальный стенд для тестов БД и Docker

1. Запустите stack:
   ```bash
   docker compose -f dev/local-stack-compose.yml up -d
   ```
   Запустятся:
   - `monitoring-db` (Postgres 16, user/password/db: `monitor`)
   - `monitoring-demo-app` (Nginx с health-check на `/health`, порт 8080)
   - `monitoring-worker` (долгоживущий контейнер для демонстрации статуса)

2. Пример конфига для потока БД (`config.yaml`):
   ```yaml
   dashboard:
     databases_stream:
       enabled: true
       instances:
         - type: postgresql
           id: local-db
           name: Local Postgres
           host: localhost
           port: 5432
           user: monitor
           password: monitor
           database: monitor
           replication_lag_ms: 0
           storage_total_gb: 5
           storage_used_gb: 1
   ```

3. Поток Docker (`docker_stream`) будет собирать данные из запущенного compose через `docker stats/ps` — ничего дополнительно не требуется.

4. Остановка:
   ```bash
   docker compose -f dev/local-stack-compose.yml down -v
   ```
