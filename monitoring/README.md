This folder contains configuration files to run Prometheus, Loki, Promtail, and Grafana alongside the tatou server using docker-compose.

Quick start (macOS / Linux / WSL):

1. Ensure Docker Desktop is running and docker-compose is available.
2. From the project root run:

```bash
# build the server and start monitoring stack
docker compose up --build -d prometheus loki promtail grafana server
```

Note: On Apple Silicon you may need to allow amd64 images via Docker Desktop or add `platform: linux/amd64` to grafana, loki, promtail images in docker-compose.

What each service does:
- prometheus: scrapes the tatou server `/metrics` endpoint.
- loki: stores logs ingested by promtail.
- promtail: tails `server/logs/*.json.log` and pushes JSON entries to Loki.
- grafana: configured with Prometheus and Loki datasources and a basic dashboard.

Verify:
- Open Grafana at http://localhost:3000 (admin/admin). Look for the "Tatou Overview" dashboard.
- Prometheus: http://localhost:9090 and query `tatou_events_total`
- Loki: http://localhost:3100/ and explore logs from `{job="tatou"}`

Notes and next steps:
- This setup mounts `./server/logs` into promtail. Ensure the server writes the structured JSON logs at `/app/logs/security.json.log` (the app attempts to do so).
- In production, secure Grafana (change the admin password), and configure retention policies for Loki/Prometheus storage.
