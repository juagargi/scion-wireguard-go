# wgexp monitoring

A small Docker Compose setup that observes the wireguard-go experiment runner
(`tests/experiment`). It mirrors `$SCION/tools/hummbwtester/monitoring/` with distinct names, so
both stacks run side by side.

| | hummbwtester | wgexp |
| --- | --- | --- |
| Compose project | (directory name) | `wgexp-monitoring` |
| Containers | `hummbwtester-prometheus`, `hummbwtester-grafana` | `wgexp-prometheus`, `wgexp-grafana` |
| Prometheus port | 8090 | 8091 (`PROMETHEUS_PORT`) |
| Grafana port | 3000 | 3001 (`GRAFANA_PORT`) |
| Volumes | `prometheus-data`, `grafana-data` (project prefixed) | `wgexp-prometheus-data`, `wgexp-grafana-data` (project prefixed) |

Prometheus runs with host networking and scrapes every second. Targets come from file_sd files that
the runner writes to `tests/experiment/gen/prometheus/` (mounted read-only at
`/etc/prometheus/targets`). The same `prometheus.yml` serves Docker and SSH deployments.

## Files

- `docker-compose.yml`: Prometheus and Grafana (service `grafana`, also used by the SSH `ensure_grafana`)
- `prometheus.yml`: the three scrape jobs below
- `grafana/provisioning`: Prometheus data source (uid `prometheus`, URL `http://host.docker.internal:${PROMETHEUS_PORT}`) and dashboard loading (folder `wgexp`)
- `grafana/dashboards/wgexp-overview.json`: dashboard `wgexp Overview` (uid `wgexp-overview`)

## Scrape jobs

| job | file (under `gen/prometheus/`) | targets | labels |
| --- | --- | --- | --- |
| `wireguard` | `wireguard.json` | each wireguard-go endpoint's `/metrics` | `experiment`, `tunnel`, `endpoint`, `peer`, `class`, `tunnel_class`, `isd_as`, `node` |
| `scion-border-routers` | `border_routers.json` | the SCION border routers | `as`, `br` (as in hummbwtester) |
| `wgexp-runner` | `runner.json` | the runner's metrics endpoint | `experiment` |

File_sd labels win over same-named labels in scraped series. An empty or missing file (`[]`) is fine.

## Use

The runner's `setup` starts the stack (`docker compose -p wgexp-monitoring up -d`) and `teardown`
stops it, keeping the volumes. By hand, from this directory:

```bash
mkdir -p ../gen/prometheus   # otherwise Docker creates it as root
docker compose -p wgexp-monitoring up -d
docker compose -p wgexp-monitoring down        # add -v to drop the data volumes
```

- Prometheus: [http://localhost:8091](http://localhost:8091) (`/targets` shows the job states)
- Grafana: [http://localhost:3001](http://localhost:3001), login `admin` / `admin`

Override ports with `PROMETHEUS_PORT=18091 GRAFANA_PORT=13001 docker compose -p wgexp-monitoring up -d`.
The data source follows `PROMETHEUS_PORT`; for SSH deployments the runner's setup recreates Grafana
(`up -d --no-deps --force-recreate grafana`) with the forwarded Prometheus port.

## Dashboard

`wgexp Overview` has a `$tunnel` variable (`label_values(wireguard_sent_bytes_total, tunnel)`), refreshes
every second, and shows the last 15 minutes. Panels:

- Traffic rate per endpoint; send-receive gap per direction
- Workload goodput, copy progress, state timeline, verification results
- Ping RTT p95, jitter, loss per minute
- Best-effort loss per minute; reservation setup (p95 and count by result); reservations bought
- wireguard-go errors
- Border-router panels copied from hummbwtester (queue depths, demotions, priority drops, BFD, CPU scheduling, kernel receive overflows)

Workload state changes (`changes(wgexp_workload_state[30s]) > 0`) appear as annotations.
