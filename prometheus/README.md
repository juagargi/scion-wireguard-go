# A throwaway Prometheus for the integration test

This is a single Prometheus container configured to scrape the metrics of
a client-like and server-like wireguard-go instances of the tiny topology integration test.
See the file `tests/scion-integration.py`.
```
docker compose up -d        # Prometheus on http://localhost:8090
../tests/scion-integration.py --scion-dir ~/devel/scion --size 1G --bwlimit 25mbps
```
Samples are kept for seven days in a Docker volume;
the container can be stopped and started between runs without losing them.

## Hardcoded Values

`prometheus.yml` names the tester addresses of tiny.topo literally:

| AS | address | what the test runs there |
| --- | --- | --- |
| `1-ff00:0:111` | `172.20.0.29:28015` | the sending wireguard-go |
| `1-ff00:0:112` | `[fd00:f00d:cafe::7f00:15]:28015` | the receiving wireguard-go |


The port, `28015`, is `defaultAPIPort` in `conn/scion_path_manager.go`;
wireguard-go serves `/metrics` along the path manager's `/paths` API.
It walks to 28016 and 28017 when the port is taken, so a scrape of an instance that has moved will
also just fail.


## The metrics

| series | meaning |
| --- | --- |
| `sent_bytes_total` | bytes written to the underlay, SCION and UDP headers included |
| `received_bytes_total` | bytes read from the underlay, likewise |
| `reservation_setup_duration_seconds` | how long the last Hummingbird reservation took to search, buy and redeem |

Both counters keep the `isd_as` and `role` labels from `prometheus.yml`,
so the two sides of the tunnel share one job and are told apart in the query:

    rate(sent_bytes_total{role="source"}[1m])

Mind the range. `scrape_interval` is 10s, and a range that spans a single sample yields nothing at all,
so `increase(sent_bytes_total[10s])` is always empty.
Use a window of a minute or more, or `$__rate_interval` if you point a Grafana at this.


## Editing the configuration

This whole directory is bind-mounted into the container, not `prometheus.yml` alone,
so that editing the file is automatically reflected in the container. After an edit:

    docker compose kill -s HUP prometheus
