## Local DB & Docker Test Stand

1. Start the stack:
   ```bash
   docker compose -f dev/local-stack-compose.yml up -d
   ```
   This launches:
   - `monitoring-db` (Postgres 16, user/password/db: `monitor`)
   - `monitoring-demo-app` (Nginx with a `/health` endpoint, port 8080)
   - `monitoring-worker` (long-running container to demonstrate status)

2. Sample config for the DB stream (`config.yaml`):
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

3. Docker stream (`docker_stream`) will collect data from the running compose via `docker stats/ps` — no extra setup required.

4. Stop the stack:
   ```bash
   docker compose -f dev/local-stack-compose.yml down -v
   ```
