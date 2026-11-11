# wireguard-go experiment runner

`experiment.py` runs wireguard-go tunnels over SCION, with and without Hummingbird reservations, on a
shaped network and observes them. One JSON file describes the whole experiment: the tunnels, the
workloads that run through them (rsync file copies with sha256 verification, iperf3, ping), the
shaping of the links and the monitoring. Typical use: a 1 GiB copy over a reserved tunnel while a
second, best-effort tunnel overloads the same bottleneck link.

It reuses the Docker and SSH orchestration of `$SCION/tools/hummbwtester` (imported, never copied).

Commands, all with `--config FILE` and `--scion-dir DIR` (default `$SCION_DIR`):

- `setup [--dry-run]`: idempotent. Builds wireguard-go (`make`), prepares the topology, shaping,
  marketplace, JWT, binary and monitoring. `--dry-run` changes nothing and lists every step.
  Prints the config's `informative` lines first and ends with `setup: done.` or `setup: FAILED.`
- `run`: starts from a clean slate, brings the tunnels up, runs the workloads, collects logs, writes
  `results.json`, and cleans up what it created (also on Ctrl-C). Exit status 0 if and only if every
  primary workload passed, including its verification.
- `teardown`: reverses setup, continues past failures and reports them at the end.

## Requirements

- Linux, `python3`, `make` and Go (for `make`), and `docker` with the compose plugin.
- A SCION checkout, given with `--scion-dir` or `$SCION_DIR`, with `tools/hummbwtester`.
  Its Python imports need **PyYAML**, and **bcrypt** for SSH deployments.
- `jsonschema` is optional: when importable, the unit tests also validate the examples against the schema.
- `WGEXP_MARKETPLACE_PASSWORD` (the `password_env` of the config): the marketplace password.
  Unset, it defaults to `1234`, the development password of the generated topology's accounts and of the
  deployed SCIERA marketplace's users. It is read from the environment, never from JSON.
- Tools on every tester (container or host): `ip`, `rsync`, `iperf3`, `ping`, `sha256sum` (SSH also `nc`),
  `/dev/net/tun`, and root (Docker) or passwordless `sudo -n` (SSH). `setup` checks these.

## First run (Docker tiny topology)

From the SCION checkout, build the images and generate the tiny topology once:

```bash
cd $SCION
make build-dev
make docker-images
./scion.sh topology -d -c topology/tiny.topo -m 1-ff00:0:111
```

Then, from this repository (`experiment-docker.json`, name `docker-tiny-1g`):

```bash
export SCION_DIR=$SCION
python3 tests/experiment/experiment.py setup --config tests/experiment/experiment-docker.json --dry-run
python3 tests/experiment/experiment.py setup --config tests/experiment/experiment-docker.json
python3 tests/experiment/experiment.py run   --config tests/experiment/experiment-docker.json
python3 tests/experiment/experiment.py teardown --config tests/experiment/experiment-docker.json
```

The configuration: tunnel `ab` (QoS1 in AS 111, QoS2 in AS 112) with a Hummingbird reservation of 20 mbps
copies 1 GiB, rsync limited to the reservation; tunnel `cd` (BE1 in 110, BE2 in 112, same container as QoS2)
sends UDP iperf3 at 50 mbps as best-effort load; both inter-AS links are shaped to 50 mbit.

The regular cycle afterwards: `setup` once per `./scion.sh stop`/start (it is idempotent, a second one
changes nothing), then `run` as often as you like, `teardown` when done. `./scion.sh stop` removes the
bridges and their qdiscs: after it always rerun `setup`, never only `./scion.sh start`.
A second `setup` fetches a new marketplace JWT.

## What each command changes

Docker deployment:

| command | changes |
| --- | --- |
| `setup` | `make` in this repo (builds `./wireguard-go`); patches the border-router configs in `$SCION/gen` with `deployment.router`; adds `hummbwtester_tc_*` helper services to `gen/scion-dc.yml`; `./scion.sh start`; waits for SCION reachability; applies TBF qdiscs in the border-router namespaces; copies the binary to `/share/bin/wireguard-go`; installs the marketplace JWT (mode 600) at `/tmp/hummbwtester-marketplace.jwt` in the sender containers; writes Prometheus targets to `tests/experiment/gen/prometheus/`; starts the `wgexp-prometheus` and `wgexp-grafana` containers |
| `run` | creates `/tmp/wgexp/runs/<run_id>/` in the testers, the `wgx-*` TUN devices, wireguard-go, rsync and iperf3 processes, and the payload; the runner serves its own metrics on `monitoring.runner_metrics_port`. Everything is removed at the end; logs go to `tests/experiment/logs/<run_id>/` |
| `teardown` | stops our leftovers and removes `/tmp/wgexp`; removes the qdiscs; stops the monitoring containers; removes the JWT |

`teardown` does **not** revert: the patched border-router configs, the `hummbwtester_tc_*` services in
`gen/scion-dc.yml`, `/share/bin/wireguard-go`, the Prometheus/Grafana Docker volumes (kept on
purpose, so dashboards and history survive), nor the running SCION topology (it is not stopped).
`./scion.sh topology` regenerates the first two.

SSH deployment: `setup` first checks that the controller's and every host's clocks are NTP-synchronized
and within 0.25 s of each other (`run` checks this again). It also deploys and configures the marketplace on its host,
applies selective qdiscs on the hosts, may need a manual step for the static-info Note (it prints it),
copies the binary to each host, starts Prometheus on the monitoring host (files in
`/var/tmp/wgexp-prometheus`, so they survive a reboot), and starts a local Grafana.
Every other host with metric sources (wireguard-go endpoints, border routers) runs a Prometheus agent
(`wgexp-prometheus-agent`). The agent scrapes locally and remote-writes to the central Prometheus
through an SSH `-R` tunnel, and keeps what it cannot deliver until it can. Only the runner's metrics on
the controller are still relayed. Before querying Prometheus for `results.json`, `run` waits up to 30 s for the agents
to deliver the run's last samples. `teardown` removes the qdiscs, stops Grafana, the agents (after
they send their backlog), the tunnels, Prometheus **and the marketplace**, and removes the setup
directories it created on the hosts.

A router in `deployment.metrics.routers` with `"display": false` is scraped and stored with the label
`display="false"`. The dashboard and the Prometheus figures in `results.json` leave it out.

## Configuration

The format is [`experiment.schema.json`](experiment.schema.json) (JSON Schema, with descriptions for
every field); examples: [`experiment-docker.json`](experiment-docker.json) and
[`experiment-sciera.json`](experiment-sciera.json). `config.py` adds the rules a schema cannot express
(unique names and ports per host, tunnel IPs in one prefix, reservation present iff `hummingbird`
section, ...), with errors that name the JSON path. Sections: `name`, `informative`, `hummingbird`,
`tunnels` (two endpoints each), `workloads`, `run`, `monitoring`, `deployment`, `tc`.

- **Workload kinds**: `file_copy` (rsync against a daemon on the receiver's tunnel IP, `size`,
  `verify`, `repeat`, `bwlimit`, `keep_files`), `iperf3` (`protocol`, `bandwidth`, `length`,
  `duration`, `parallel`) and `ping` (`interval`, `payload_size`). `role` is `primary` (decides the
  exit status) or `background` (runs from the start of warmup until the primaries are done plus cooldown).
- **`bwlimit`** of `file_copy`: `reservation` (default for a sender with a reservation), `none`, or an
  explicit bandwidth. WireGuard does not pace: without a limit a Hummingbird sender overruns its
  reservation, the excess is demoted to best effort, and the run "passes" without testing anything.
  `reservation` means the reserved bandwidth times `PAYLOAD_EFFICIENCY` (0.8 in `workloads.py`), because
  the reservation counts full SCION packets while rsync limits payload.
- **Best-effort load** is iperf3 over UDP at the bottleneck rate (UDP does not back off, so it
  overloads the link). UDP needs `bandwidth`; `length` defaults to tunnel `mtu` - 100 and must fit in
  `mtu` - 28.
- **Tunnel `mtu`** is 1000 on the tiny topology: its 110-111 link has an MTU of 1280, and the
  SCION and Hummingbird headers take the rest. Raise it only if the path's header length is known.
- Endpoint `path_filter`s pin each tunnel to a path; QoS2 and BE2 share one container and are told apart by
  interface, `listen_port` and `api_port` (`SCION_PATH_API_ADDRESS`).
- `run.max_duration` caps a run; every primary `timeout` must be at most that.
- `deployment` and `hummingbird.marketplace` use exactly hummbwtester's fields (its parsers reject
  unknown ones), so a new field there must first exist in hummbwtester.

## Monitoring

`setup` starts a Prometheus and a Grafana of its own (compose project `wgexp-monitoring`,
containers `wgexp-prometheus`, `wgexp-grafana`):

- Prometheus: <http://localhost:8091>, Grafana: <http://localhost:3001> (`admin` / `admin`),
  dashboard `wgexp Overview`, uid `wgexp-overview`. Prometheus scrapes every second.
- They coexist with hummbwtester's stack (8090 / 3000, `hummbwtester-*` containers).
  Running both experiments at the same time is not supported: they share the marketplace and the
  Docker qdisc state, and either teardown stops the shared marketplace.
- Scraped: each wireguard-go `/metrics`, the border routers, and the runner. The runner exports
  `wgexp_workload_state`, `wgexp_workload_bytes_total`, `wgexp_workload_iterations_total`,
  `wgexp_workload_restarts_total`, `wgexp_verify_total`, `wgexp_iperf3_datagrams_total`,
  `wgexp_iperf3_lost_datagrams_total`, `wgexp_ping_rtt_seconds`, `wgexp_ping_sent_total`,
  `wgexp_ping_received_total`, `wgexp_ping_jitter_seconds`, `wgexp_reservations_total` and
  `wgexp_run_info`.
- Details, ports and panels: [`monitoring/README.md`](monitoring/README.md).

## Results and logs

Each run writes `tests/experiment/logs/<YYYYMMDD-HHMMSS>-<name>/`:

- `results.json`: run id, config path and sha256, start/end, `interrupted`, `passed`, per-workload
  outcome (`state` passed/failed/stopped/timeout, bytes, goodput, restarts, details such as the
  sha256 of both copies), per-sender reservation counts (bought, failed, handovers, marketplace
  addresses), Prometheus summary values, and `grafana_url`, which opens the dashboard on the run window.
  The Prometheus values include `priority_drops` (`busy_forwarder` or `egress_down`) and the drops at
  a downed egress interface (BFD down), for priority traffic (`priority_drops_egress_down`) and for
  all traffic (`drops_egress_down`).
  Bytes and goodput are what the receiver got: for UDP iperf3 that excludes the lost datagrams, whose
  count is in `details` and in the printed summary.
- `wg-<endpoint>.log`: wireguard-go log of each endpoint.
- `<workload>.*.log`: rsync, iperf3 client/server and ping logs.

The same summary is printed at the end of `run`. Logs are not deleted by `teardown`.

## SSH / SCIERA mode

`experiment-sciera.json` describes three SCIERA hosts (rnp, ufes, ufms) with a marketplace on ufms.
It is implemented and unit-tested with mocks, but **has not been run against real hosts**. It touches
production machines (marketplace service, qdiscs, binaries, SSH tunnels), so do not run it without an
explicit go-ahead. Start with `setup --dry-run`, which changes nothing and lists every step.
Notes: `bcrypt` and PyYAML are needed locally; `hummingbird.marketplace_insecure` is still `true`
(not checked against ufms's certificate); with `location_override` hummbwtester's SSH setup withdraws
the marketplace Note, which is why the runner sets `HUMMINGBIRD_MARKETPLACE_ADDRESS` from the config.

## Unit tests

```bash
make test-experiment
```

This runs `python3 -m unittest discover -s tests/experiment -p 'test_*.py'`. The tests mock Docker and SSH.
Without `$SCION_DIR` and PyYAML the tests that load hummbwtester (`test_infra.py`, compatibility checks)
are skipped; the schema check needs `jsonschema`. For the full set, with a virtual environment:

```bash
python3 -m venv /tmp/wgexp-venv && /tmp/wgexp-venv/bin/pip install pyyaml bcrypt jsonschema
SCION_DIR=$SCION PATH=/tmp/wgexp-venv/bin:$PATH make test-experiment
```

## Troubleshooting

- `--scion-dir ... is required` or `hummbwtester was already imported from ...`: pass the right checkout.
- Preflight fails: it names the host and the problem (missing tool, no `/dev/net/tun`, no passwordless
  sudo, `listen_port` outside the AS's dispatched ports, overlapping route, too little disk).
  Fix it and rerun `setup`.
- The border routers log at debug level; a long run without a Docker log limit in `gen/scion-dc.yml`
  fills the disk. Preflight reports it.
- After `./scion.sh stop`/`start`, qdiscs and the marketplace state are gone: rerun `setup`.
- A second `setup` re-fetches the marketplace JWT; this is expected.
- The run "passes" but the reservation was never used: check `bwlimit` and the `senders` section of
  `results.json` (`reservations_bought`, `handovers`).
- A copy that fails verification: set `keep_files: true` and compare the files in
  `/tmp/wgexp/runs/<run_id>/work/` in the containers.
- **Path lookups**: the daemon's segment lookups fail now and then, so wireguard-go may log
  `no paths found ... keeping the N cached ones and retrying`. It keeps its paths and asks again
  with growing delays, so this is not an error of the run. If the tunnel stalls anyway, keep the `wg-*.log` files.
- **Never `pkill` by name** (`wireguard-go`, `rsync`, `iperf3`) in testers: QoS2 and BE2 share a container,
  and the runner tracks its processes by pidfile. Use `teardown`, which stops only what it started.
- Leftover `wgx-*` devices or processes after a crash: `teardown` removes them.
