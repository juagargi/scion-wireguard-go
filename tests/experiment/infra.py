"""Infrastructure of an experiment: the SCION topology, shaping, marketplace, JWT, binaries, monitoring.

This is the only module that imports hummbwtester (``$SCION/tools/hummbwtester/scripts``), lazily
through load_hummbwtester(). It never calls hummbwtester's own top-level setup(), run() or
teardown(), never patches its constants, and never modifies the SCION checkout.

The integrator (experiment.py) uses one object, created once per command::

    infra = Infra.for_experiment(experiment, scion_dir, dry_run=args.dry_run)   # Docker or SSH

    # setup, in this order
    failures  = infra.setup_infrastructure()   # Docker: BR configs, compose, scion.sh start, qdiscs
                                               # SSH: marketplace service, selective qdiscs, Notes
    problems  = infra.preflight()              # tools, /dev/net/tun, sudo, ports, routes, disk
    binaries  = infra.install_binary(path)     # {host_key: on-host wireguard-go path}
    jwts      = infra.install_jwt()            # {host_key: on-host jwt path} or None
    failures += infra.setup_monitoring()       # file_sd targets, Prometheus, Grafana, relays

    # run (a separate process; nothing from setup needs to be remembered)
    infra.hosts()                  # {host_key: Host}
    infra.sciond_address(ep)       # SCION_DAEMON_ADDRESS of an endpoint
    infra.binary_paths(), infra.jwt_paths(), infra.run_dir(host_key)
    infra.write_targets()          # refresh gen/prometheus/*.json (also done by setup_monitoring)
    infra.grafana_url(start, end), infra.prometheus_url

    # teardown
    errors = infra.teardown_infrastructure()   # list of error strings, empty if everything went well

Every setup method returns a list of failure strings. Outside dry-run a failing step raises InfraError
(setup stops at the first failure, like hummbwtester). With dry_run every step still performs its
checks and reads, prints "dry-run: would ...", changes nothing, and a failing step is reported and
collected so that one dry run shows every problem; the returned list is then not empty.
preflight() behaves the same.

host_key is the unit that identifies a machine: the ISD-AS of the tester container on Docker, the
deployment node on SSH (Endpoint.host_key).

Generated state: tests/experiment/gen/prometheus/{wireguard,border_routers,runner}.json.
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import importlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional

try:  # tests and experiment.py put tests/experiment on sys.path; support the package form too
    from config import Endpoint, Experiment, FileCopy
except ImportError:  # pragma: no cover
    from .config import Endpoint, Experiment, FileCopy

HERE = Path(__file__).resolve().parent
GEN_DIR = HERE / "gen"
MONITORING_DIR = HERE / "monitoring"
MONITORING_COMPOSE = MONITORING_DIR / "docker-compose.yml"
MONITORING_PROJECT = "wgexp-monitoring"
PROMETHEUS_CONTAINER = "wgexp-prometheus"
GRAFANA_CONTAINER = "wgexp-grafana"
DASHBOARD_UID = "wgexp-overview"

# Where the binary and the JWT are on a Docker tester. The JWT path is the one of hummbwtester's
# install_docker_jwt/remove_docker_jwt (pinned by test_infra.py).
DOCKER_BINARY = "/share/bin/wireguard-go"
DOCKER_JWT = "/tmp/hummbwtester-marketplace.jwt"
DOCKER_RUN_DIR = "/tmp/wgexp"
SSH_BINARY_MODE = "700"

TARGET_WIREGUARD = "targets/wireguard.json"
TARGET_RUNNER = "targets/runner.json"
TARGET_ROUTERS = "targets/border_routers.json"
TARGET_FILES = (TARGET_WIREGUARD, TARGET_RUNNER, TARGET_ROUTERS)

REQUIRED_TOOLS = ("ip", "rsync", "iperf3", "ping", "sha256sum")
SSH_REQUIRED_TOOLS = (*REQUIRED_TOOLS, "nc")  # remote.preflight always uses nc for the daemon check
TINY_DISPATCHED_PORTS = (31000, 32767)
# One copy on each side, rsync's temporary file, and slack: as in tests/scion-end2end.py.
DISK_SPACE_FACTOR = 2.5
UNCAPPED_ROUTER_LOG_FACTOR = 3.0
MONITORING_WAIT_SECONDS = 30
MONITORING_SETTLE_SECONDS = 2
SCION_WAIT_SECONDS = 60

# Modules whose absence is reported before the SSH marketplace is set up (the topology
# generator's marketplace module imports bcrypt). A test may empty this tuple.
SSH_REQUIRED_MODULES = ("bcrypt",)

# The MonitoringStack of the SSH deployment, written once (see wgexp_stack()).
WGEXP_STACK_FIELDS: dict[str, Any] = {
    "prometheus_config": MONITORING_DIR / "prometheus.yml",
    "remote_dir": "/tmp/wgexp/prometheus",
    "prometheus_container": PROMETHEUS_CONTAINER,
    "prometheus_project": "wgexp-ssh",
    "remote_prometheus_port": 8091,
    "config_hash_label": "org.scion.wgexp.config-sha256",
    "grafana_container": GRAFANA_CONTAINER,
    "grafana_compose": MONITORING_COMPOSE,
    "grafana_project": MONITORING_PROJECT,
    "tunnel_state_dir": Path("/tmp/wgexp/ssh-tunnels"),
}


class InfraError(RuntimeError):
    """An infrastructure step failed, or a prerequisite is missing."""


# What a failing step of hummbwtester or of a host command raises (ConfigError is a ValueError,
# SSHError and HostError are RuntimeErrors, KeyError/IndexError come from malformed documents).
_RECOVERABLE = (ValueError, RuntimeError, OSError, LookupError, subprocess.SubprocessError)


# ---------------------------------------------------------------------------------------------
# hummbwtester
# ---------------------------------------------------------------------------------------------

_LOADED: dict[str, SimpleNamespace] = {}


def _require_module(name: str, why: str) -> None:
    if importlib.util.find_spec(name) is None:
        raise InfraError(f"the Python module {name!r} is missing; {why} (pip install {name})")


def load_hummbwtester(scion_dir: Path) -> SimpleNamespace:
    """Import hummbwtester's reusable modules from the SCION checkout scion_dir.

    Returns a namespace with ``orchestration``, ``remote`` (ssh_orchestration) and ``ssh_setup``.
    """
    root = Path(scion_dir).resolve()
    key = str(root)
    if key in _LOADED:
        return _LOADED[key]
    scripts = root / "tools" / "hummbwtester" / "scripts"
    if not (scripts / "orchestration.py").is_file():
        raise InfraError(f"{scripts / 'orchestration.py'} does not exist; is --scion-dir a "
                         "SCION checkout with tools/hummbwtester?")
    _require_module("yaml", "hummbwtester's orchestration needs PyYAML")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    try:
        orchestration = importlib.import_module("tools.hummbwtester.scripts.orchestration")
        remote = importlib.import_module("tools.hummbwtester.scripts.ssh_orchestration")
        ssh_setup = importlib.import_module("tools.hummbwtester.scripts.ssh_setup")
    except ModuleNotFoundError as err:
        raise InfraError(f"importing hummbwtester from {root} failed: the Python module "
                         f"{err.name!r} is missing") from err
    if Path(orchestration.ROOT).resolve() != root:
        raise InfraError(f"hummbwtester was already imported from {orchestration.ROOT}, "
                         f"not from {root}; one checkout per process")
    _LOADED[key] = SimpleNamespace(orchestration=orchestration, remote=remote, ssh_setup=ssh_setup)
    return _LOADED[key]


def wgexp_stack(ssh_setup: Any, prometheus_port: Optional[int] = None) -> Any:
    """The MonitoringStack of this tool (containers wgexp-*, project wgexp-ssh / wgexp-monitoring)."""
    fields = dict(WGEXP_STACK_FIELDS)
    if prometheus_port is not None:
        fields["remote_prometheus_port"] = prometheus_port
    return ssh_setup.MonitoringStack(**fields)


# ---------------------------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------------------------

def reserving_endpoints(experiment: Experiment) -> tuple[Endpoint, ...]:
    return tuple(e for e in experiment.endpoints if e.hummingbird is not None)


def wireguard_labels(experiment: Experiment, endpoint: Endpoint, node: str) -> dict[str, str]:
    """The file_sd labels of one endpoint's API (the contract with the dashboard)."""
    peer = experiment.peer_of(endpoint.name)
    return {
        "experiment": experiment.name,
        "tunnel": endpoint.tunnel_id,
        "endpoint": endpoint.name,
        "peer": peer.name,
        "class": "hummingbird" if endpoint.hummingbird is not None else "best_effort",
        "tunnel_class": ("hummingbird" if endpoint.hummingbird is not None
                         or peer.hummingbird is not None else "best_effort"),
        "isd_as": endpoint.isd_as,
        "node": node,
    }


def scrape_host(endpoint: Endpoint) -> str:
    """The address on the endpoint's own host at which its API answers."""
    bind = endpoint.api_bind
    if bind in ("0.0.0.0", "::", ""):
        bind = "127.0.0.1"
    return f"[{bind}]" if ":" in bind else bind


def file_sd(entries: Sequence[Mapping[str, Any]]) -> str:
    return json.dumps(list(entries), indent=2) + "\n"


def parse_dispatched_ports(spec: Any) -> Optional[tuple[int, int]]:
    """'31000-32767' -> (31000, 32767); None for 'all', a missing or unparsable value."""
    if not spec or spec == "all":
        return None
    parts = str(spec).strip().split("-")
    if len(parts) != 2 or not all(p.isdigit() for p in parts):
        return None
    return int(parts[0]), int(parts[1])


def host_payload_bytes(experiment: Experiment) -> dict[str, int]:
    """The bytes of file_copy payload each host holds: the sender's source and the receiver's copy."""
    totals: dict[str, int] = {}
    for w in experiment.workloads:
        if not isinstance(w, FileCopy):
            continue
        for ep in (w.sender, w.receiver):
            totals[ep.host_key] = totals.get(ep.host_key, 0) + w.size_bytes
    return totals


def ms_since_epoch(value: Any) -> int:
    if isinstance(value, datetime.datetime):
        return int(value.timestamp() * 1000)
    return int(float(value) * 1000)


_ROUTE_TYPES = {"unicast", "local", "broadcast", "multicast", "throw", "unreachable", "prohibit",
                "blackhole", "nat", "anycast"}


def route_clashes(output: str, own_interfaces: set[str]) -> list[str]:
    """The route lines of `ip -o route show to ...` that do not belong to our own wgx devices.

    The default route covers every prefix and is not a clash.
    """
    clashes = []
    for line in output.splitlines():
        tokens = line.split()
        if tokens and tokens[0] in _ROUTE_TYPES:
            tokens = tokens[1:]
        if not tokens or tokens[0] == "default":
            continue
        device = tokens[tokens.index("dev") + 1] if "dev" in tokens[:-1] else None
        if device in own_interfaces:
            continue
        clashes.append(line.strip())
    return clashes


# ---------------------------------------------------------------------------------------------
# The infrastructure object
# ---------------------------------------------------------------------------------------------

class Infra:
    """Common part of DockerInfra and SSHInfra; create it with Infra.for_experiment()."""

    kind = ""

    def __init__(self, experiment: Experiment, scion_dir: Path, dry_run: bool = False, *,
                 hb: Any = None, gen_dir: Optional[Path] = None,
                 host_factory: Optional[Callable[[str], Any]] = None) -> None:
        self.experiment = experiment
        self.scion_dir = Path(scion_dir)
        self.dry_run = dry_run
        self.hb = hb if hb is not None else load_hummbwtester(self.scion_dir)
        self.gen_dir = Path(gen_dir) if gen_dir is not None else GEN_DIR
        self._host_factory = host_factory
        self._hosts: dict[str, Any] = {}

    @staticmethod
    def for_experiment(experiment: Experiment, scion_dir: Path, dry_run: bool = False,
                       **kwargs: Any) -> "Infra":
        """DockerInfra or SSHInfra, according to experiment.deployment.kind."""
        cls = {"docker": DockerInfra, "ssh": SSHInfra}[experiment.deployment.kind]
        return cls(experiment, scion_dir, dry_run, **kwargs)

    # -- helpers --------------------------------------------------------------------------

    def _say(self, message: str) -> None:
        print(message, flush=True)

    def _plan(self, message: str) -> None:
        """Print what a step does ("would ..." in a dry run) and report whether to do it."""
        self._say(f"dry-run: would {message}" if self.dry_run else message)

    def _steps(self, steps: Sequence[tuple[str, Callable[[], Any]]]) -> list[str]:
        """Run the steps. Outside dry-run the first failure raises InfraError."""
        failures: list[str] = []
        for label, step in steps:
            try:
                step()
            except InfraError as err:
                if not self.dry_run:
                    raise
                failures.append(f"{label}: {err}")
                self._say(f"dry-run: step {label} FAILED: {err}")
            except _RECOVERABLE as err:
                if not self.dry_run:
                    raise InfraError(f"{label}: {err}") from err
                failures.append(f"{label}: {err}")
                self._say(f"dry-run: step {label} FAILED: {err}")
        return failures

    @property
    def target_dir(self) -> Path:
        return self.gen_dir / "prometheus"

    @property
    def prometheus_url(self) -> str:
        return f"http://127.0.0.1:{self.experiment.monitoring.prometheus_port}"

    def grafana_url(self, start: Any, end: Any = None) -> str:
        """The dashboard on the run window; start and end are epoch seconds or datetimes."""
        port = self.experiment.monitoring.grafana_port
        window = f"from={ms_since_epoch(start)}&to=" + (
            str(ms_since_epoch(end)) if end is not None else "now")
        return f"http://127.0.0.1:{port}/d/{DASHBOARD_UID}/{DASHBOARD_UID}?orgId=1&{window}"

    def host_keys(self) -> list[str]:
        return sorted({e.host_key for e in self.experiment.endpoints})

    def endpoints_on(self, host_key: str) -> list[Endpoint]:
        return [e for e in self.experiment.endpoints if e.host_key == host_key]

    def hosts(self) -> dict[str, Any]:
        """{host_key: Host} for every host the experiment uses."""
        for key in self.host_keys():
            if key not in self._hosts:
                self._hosts[key] = self._make_host(key)
        return {key: self._hosts[key] for key in self.host_keys()}

    def _make_host(self, host_key: str) -> Any:
        if self._host_factory is not None:
            return self._host_factory(host_key)
        return self._default_host(host_key)

    def _default_host(self, host_key: str) -> Any:  # pragma: no cover - overridden
        raise NotImplementedError

    def _host(self, host_key: str) -> Any:
        return self.hosts()[host_key]

    def binary_paths(self) -> dict[str, str]:
        raise NotImplementedError

    def jwt_paths(self) -> Optional[dict[str, str]]:
        raise NotImplementedError

    def run_dir(self, host_key: str) -> str:
        raise NotImplementedError

    def sciond_address(self, endpoint: Endpoint) -> str:
        raise NotImplementedError

    def target_documents(self) -> dict[str, str]:
        """The three file_sd documents, keyed by 'targets/<name>.json'."""
        raise NotImplementedError

    def write_targets(self) -> dict[str, str]:
        """Write the documents to gen/prometheus/<name>.json (as the current user)."""
        documents = self.target_documents()
        self.target_dir.mkdir(parents=True, exist_ok=True)
        for relative, text in documents.items():
            path = self.target_dir / Path(relative).name
            if not path.exists() or path.read_text() != text:
                path.write_text(text)
        self._say(f"wrote Prometheus targets to {self.target_dir}")
        return documents

    # -- preflight ---------------------------------------------------------------------------

    check_tools_in_generic = True

    def preflight(self) -> list[str]:
        """Check every host; raise InfraError listing all problems (dry-run: print and return them)."""
        problems: list[str] = []
        try:
            problems += self._preflight_hosts()
        except _RECOVERABLE as err:
            problems.append(str(err))
        for key in self.host_keys():
            try:
                problems += self._host_problems(key)
            except _RECOVERABLE as err:
                problems.append(f"{key}: {err}")
        try:
            problems += self._disk_problems()
        except _RECOVERABLE as err:
            problems.append(f"disk space: {err}")
        if not problems:
            self._say("preflight: every host is ready")
            return []
        for problem in problems:
            self._say(f"preflight: {problem}")
        if self.dry_run:
            return problems
        raise InfraError("preflight failed:\n  " + "\n  ".join(problems))

    def _preflight_hosts(self) -> list[str]:
        return []

    def _dispatched_ports(self, host_key: str) -> Optional[tuple[int, int]]:
        raise NotImplementedError

    def _host_problems(self, host_key: str) -> list[str]:
        host = self._host(host_key)
        name = host_key
        problems: list[str] = []
        if self.check_tools_in_generic:
            script = ('for t in "$@"; do command -v "$t" >/dev/null 2>&1 || echo "$t"; done')
            result = host.run(["bash", "-c", script, "_", *REQUIRED_TOOLS], check=False)
            missing = result.stdout.split()
            if result.returncode != 0 and not missing:
                missing = ["(could not run the tool check)"]
            if missing:
                problems.append(f"{name}: missing tools: {', '.join(missing)}")
        if host.run(["test", "-c", "/dev/net/tun"], check=False).returncode != 0:
            problems.append(f"{name}: /dev/net/tun is not available (WireGuard needs a TUN device)")
        problems += self._root_problems(host, name)
        # listen_port inside dispatched_ports: the border router only delivers those directly
        ports = self._dispatched_ports(host_key)
        for ep in self.endpoints_on(host_key):
            if ports is not None and not ports[0] <= ep.listen_port <= ports[1]:
                problems.append(
                    f"{name}: endpoint {ep.name} listen_port {ep.listen_port} is outside the "
                    f"dispatched_ports range {ports[0]}-{ports[1]} of {ep.isd_as}")
        # no tunnel prefix may overlap a route the host already has
        own = {e.interface for e in self.endpoints_on(host_key)}
        seen: set[str] = set()
        for ep in self.endpoints_on(host_key):
            tunnel = self.experiment.tunnel_of(ep.name)
            if tunnel.id in seen:
                continue
            seen.add(tunnel.id)
            family = ["-6"] if tunnel.network.version == 6 else []
            for selector in ("root", "match"):
                result = host.run(["ip", *family, "-o", "route", "show", "to", selector,
                                   str(tunnel.network)], check=False)
                if result.returncode != 0:
                    problems.append(f"{name}: `ip route show` failed for {tunnel.network}: "
                                    f"{result.stderr.strip()}")
                    break
                for line in route_clashes(result.stdout, own):
                    problems.append(f"{name}: tunnel {tunnel.id} prefix {tunnel.network} overlaps "
                                    f"an existing route: {line}")
        return problems

    def _root_problems(self, host: Any, name: str) -> list[str]:
        return []

    def _disk_problems(self) -> list[str]:
        raise NotImplementedError

    # -- the rest of the interface, implemented per deployment ---------------------------------

    def setup_infrastructure(self) -> list[str]:
        raise NotImplementedError

    def setup_monitoring(self) -> list[str]:
        raise NotImplementedError

    def install_binary(self, binary: Path) -> dict[str, str]:
        raise NotImplementedError

    def install_jwt(self) -> Optional[dict[str, str]]:
        raise NotImplementedError

    def teardown_infrastructure(self) -> list[str]:
        raise NotImplementedError

    @staticmethod
    def sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with Path(path).open("rb") as file:
            for chunk in iter(lambda: file.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _attempt(self, errors: list[str], label: str, action: Callable[[], Any]) -> None:
        try:
            action()
        except _RECOVERABLE as err:
            errors.append(f"{label}: {err}")
            self._say(f"teardown: {label} failed: {err}")


def _http_answers(url: str) -> bool:
    try:
        urllib.request.urlopen(url, timeout=3)
    except urllib.error.HTTPError:
        return False  # an error status means the service is not (yet) healthy
    except (urllib.error.URLError, OSError):
        return False
    return True


def _container_running(container: str) -> bool:
    result = subprocess.run(["docker", "inspect", "--format", "{{.State.Running}}", container],
                            check=False, capture_output=True, text=True)
    return result.returncode == 0 and result.stdout.strip() == "true"


def _require_running(container: str) -> None:
    if _container_running(container):
        return
    logs = subprocess.run(["docker", "logs", "--tail", "5", container], check=False,
                          capture_output=True, text=True)
    raise InfraError(f"{container} is not running; last log lines:\n{logs.stdout}{logs.stderr}"
                     .rstrip())


def wait_service(container: str, url: str, seconds: int = MONITORING_WAIT_SECONDS,
                 settle: float = MONITORING_SETTLE_SECONDS) -> None:
    """Wait until the container runs and answers at url (hummbwtester's _wait_service).

    Another process holding the port would answer too, while the container has already exited
    on a bind failure; the container is therefore checked again once the url answered and the
    startup settled.
    """
    for _ in range(seconds):
        _require_running(container)
        if _http_answers(url):
            time.sleep(settle)
            _require_running(container)
            return
        time.sleep(1)
    raise InfraError(f"{container} does not answer at {url} after {seconds}s")


# ---------------------------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------------------------

class DockerInfra(Infra):
    kind = "docker"

    def _default_host(self, host_key: str) -> Any:
        import hosts  # lazy: hosts.py is implemented concurrently
        return hosts.DockerHost(self.scion_dir, host_key)

    @property
    def o(self) -> Any:
        return self.hb.orchestration

    def _service(self, isd_as: str) -> str:
        return self.o.tester_service(isd_as)

    def run_dir(self, host_key: str) -> str:
        return DOCKER_RUN_DIR

    def binary_paths(self) -> dict[str, str]:
        return {key: DOCKER_BINARY for key in self.host_keys()}

    def jwt_paths(self) -> Optional[dict[str, str]]:
        senders = reserving_endpoints(self.experiment)
        if not senders:
            return None
        return {e.host_key: DOCKER_JWT for e in senders}

    def sciond_address(self, endpoint: Endpoint) -> str:
        """SCION_DAEMON of the endpoint's tester container, as tests/scion-end2end.py reads it."""
        result = self._host(endpoint.host_key).run(["printenv", "SCION_DAEMON"])
        address = result.stdout.strip()
        if not address:
            raise InfraError(f"{self._service(endpoint.isd_as)} has no SCION_DAEMON variable")
        return address

    # -- topology ------------------------------------------------------------------------

    def setup_infrastructure(self) -> list[str]:
        o, exp = self.o, self.experiment
        tc = exp.tc
        state: dict[str, Any] = {}

        def read_topology() -> None:
            compose = o.compose_data()
            for ia in sorted({e.isd_as for e in exp.endpoints}):
                if self._service(ia) not in compose["services"]:
                    raise InfraError(f"the generated topology has no service {self._service(ia)} "
                                     f"for {ia}")
            state["compose"] = compose
            state["peers"] = o.inter_as_router_peers(compose) if tc else {}
            self._say(f"topology: {len(compose['services'])} services in {o.COMPOSE}"
                      + (f", {len(state['peers'])} shaped border routers" if tc else ""))

        def routers() -> None:
            self._plan(f"patch the border-router configs with {exp.deployment.router or '{}'}")
            if not self.dry_run:
                o.patch_router_configs(exp.deployment.router)

        def compose() -> None:
            if not tc:
                self._say("no tc section: no shaping, the tc helper services are not added")
                return
            self._plan("add the tc helper services to gen/scion-dc.yml")
            if not self.dry_run:
                o.patch_compose(state["compose"], state["peers"], tc)

        def start() -> None:
            self._plan("run ./scion.sh start")
            if not self.dry_run:
                o.run([str(o.ROOT / "scion.sh"), "start"], cwd=o.ROOT)

        def reachability() -> None:
            for tunnel in exp.tunnels:
                a, b = tunnel.endpoints
                for src, dst in ((a, b), (b, a)):
                    address = dst.host or self._host(dst.host_key).address()
                    destination = f"{dst.isd_as},{address}"
                    if self.dry_run:
                        self._plan(f"wait until {src.isd_as} reaches {destination} "
                                   f"(tunnel {tunnel.id})")
                        continue
                    self._say(f"waiting for SCION: {src.isd_as} -> {destination} "
                              f"(tunnel {tunnel.id})")
                    o.wait_for_scion(src.isd_as, destination, SCION_WAIT_SECONDS)

        def qdiscs() -> None:
            if not tc:
                return
            self._plan(f"apply the TBF qdiscs ({tc}) on {len(state.get('peers', {}))} "
                       "border routers and record them")
            if not self.dry_run:
                o.ensure_docker_qdiscs(state["compose"], tc, state["peers"])

        return self._steps([
            ("1. topology", read_topology),
            ("2. border-router configs", routers),
            ("3. compose", compose),
            ("4. scion.sh start", start),
            ("5. SCION reachability", reachability),
            ("6. qdiscs", qdiscs),
        ])

    # -- binary and JWT ----------------------------------------------------------------------

    def install_binary(self, binary: Path) -> dict[str, str]:
        o = self.o
        digest = self.sha256(binary)
        failures = self._steps([(f"binary on {key}", lambda key=key: self._install_binary_on(
            key, Path(binary), digest)) for key in self.host_keys()])
        if failures:
            raise InfraError("; ".join(failures))
        return self.binary_paths()

    def _install_binary_on(self, host_key: str, binary: Path, digest: str) -> None:
        o = self.o
        service = self._service(host_key)
        current = o.run(o.dc_args("exec", "-T", service, "sha256sum", DOCKER_BINARY),
                        cwd=o.ROOT, check=False, capture_output=True)
        if current.returncode == 0 and current.stdout.split() and current.stdout.split()[0] == digest:
            self._say(f"wireguard-go in {service} is current")
            return
        self._plan(f"copy {binary} to {service}:{DOCKER_BINARY}")
        if self.dry_run:
            return
        staged = DOCKER_BINARY + ".new"
        o.run(o.dc_args("cp", str(binary), f"{service}:{staged}"), cwd=o.ROOT)
        # mv replaces the file atomically; a running instance keeps its old inode
        o.run(o.dc_args("exec", "-T", service, "bash", "-c",
                        f"chmod 755 {staged} && mv -f {staged} {DOCKER_BINARY}"), cwd=o.ROOT)
        o.run(o.dc_args("exec", "-T", service, "test", "-x", DOCKER_BINARY), cwd=o.ROOT)

    def install_jwt(self) -> Optional[dict[str, str]]:
        from config import ConfigError, check_environment
        paths = self.jwt_paths()
        if paths is None:
            return None
        o, exp = self.o, self.experiment
        if self.dry_run:
            self._plan("obtain the marketplace JWT and install it (mode 600) at "
                       f"{DOCKER_JWT} in {', '.join(self._service(k) for k in sorted(paths))}")
            return paths
        mp = exp.marketplace
        assert mp is not None
        try:
            password = check_environment(exp)
        except ConfigError as err:
            raise InfraError(str(err)) from err
        if password:
            # the generated topology's account has a fixed development password; the variable is
            # read by hummbwtester's get_jwt.py, never passed in argv
            os.environ.setdefault(mp.password_env, password)
        cfg = o.parse_marketplace_config(dict(exp.raw["hummingbird"]["marketplace"]), "docker")
        try:
            url = cfg.url if cfg.location_override else o.marketplace_registration_website()
            self._say(f"requesting a marketplace JWT for {cfg.username} at {url}")
            token = o.obtain_marketplace_jwt(cfg, url)
        except ValueError as err:
            raise InfraError(str(err)) from err
        local, remote = o.install_docker_jwt(token, {self._service(k) for k in paths})
        local.unlink(missing_ok=True)
        if remote != DOCKER_JWT:
            raise InfraError(f"hummbwtester installed the JWT at {remote}, expected {DOCKER_JWT}")
        return paths

    # -- monitoring ----------------------------------------------------------------------------

    def _address_of_tester(self, isd_as: str) -> str:
        """The container IP at which the host reaches the tester's namespace (docker inspect).

        The tester shares the network namespace of its dispatcher (network_mode: service:...), so
        the address belongs to that container.
        """
        o = self.o
        service = self._service(isd_as)
        out = subprocess.run(o.dc_args("ps", "-q", service), cwd=o.ROOT, check=False,
                             capture_output=True, text=True).stdout.split()
        if not out:
            raise InfraError(f"{service} is not running; the topology must be started first")
        container = out[0]
        mode = self._inspect(container, "{{.HostConfig.NetworkMode}}")
        if mode.startswith("container:"):
            container = mode[len("container:"):]
        fields = self._inspect(
            container, "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{.GlobalIPv6Address}} {{end}}"
        ).split()
        v4 = next((f for f in fields if "." in f), None)
        v6 = next((f for f in fields if ":" in f), None)
        address = v4 or v6
        if not address:
            raise InfraError(f"cannot find the IP address of {service} (container {container[:12]})")
        return address

    @staticmethod
    def _inspect(container: str, template: str) -> str:
        result = subprocess.run(["docker", "inspect", "--format", template, container],
                                check=False, capture_output=True, text=True)
        if result.returncode != 0:
            raise InfraError(f"docker inspect {container[:12]} failed: {result.stderr.strip()}")
        return result.stdout.strip()

    def target_documents(self) -> dict[str, str]:
        exp, o = self.experiment, self.o
        wireguard = []
        addresses: dict[str, str] = {}
        for ep in exp.endpoints:
            if ep.isd_as not in addresses:
                addresses[ep.isd_as] = self._address_of_tester(ep.isd_as)
            wireguard.append({
                "targets": [o.join_host_port(addresses[ep.isd_as], ep.api_port)],
                "labels": wireguard_labels(exp, ep, self._service(ep.isd_as)),
            })
        runner = [{"targets": [f"127.0.0.1:{exp.monitoring.runner_metrics_port}"],
                   "labels": {"experiment": exp.name}}]
        return {
            TARGET_WIREGUARD: file_sd(wireguard),
            TARGET_RUNNER: file_sd(runner),
            TARGET_ROUTERS: file_sd(o.border_router_targets()),
        }

    def _compose_env(self) -> dict[str, str]:
        mon = self.experiment.monitoring
        return {**os.environ, "PROMETHEUS_PORT": str(mon.prometheus_port),
                "GRAFANA_PORT": str(mon.grafana_port)}

    def _owner_check(self, container: str, service: str) -> bool:
        """Whether the container exists; refuse one that belongs to another Compose project."""
        owner = self.o.local_container_owner(container)
        expected = f"{MONITORING_PROJECT}/{service}"
        if owner is not None and owner != expected:
            raise InfraError(f"{container} exists but belongs to {owner}, not {expected}; "
                             "refusing to replace it")
        return owner is not None

    def setup_monitoring(self) -> list[str]:
        o, mon = self.o, self.experiment.monitoring
        state: dict[str, bool] = {}

        def owners() -> None:
            state["prometheus"] = self._owner_check(PROMETHEUS_CONTAINER, "prometheus")
            state["grafana"] = self._owner_check(GRAFANA_CONTAINER, "grafana")

        def targets() -> None:
            if self.dry_run:
                self._plan(f"write the Prometheus targets to {self.target_dir}")
                return
            self.write_targets()

        def start() -> None:
            exists = state.get("prometheus") and state.get("grafana")
            self._plan(f"run docker compose -p {MONITORING_PROJECT} up -d prometheus grafana "
                       f"(ports {mon.prometheus_port} and {mon.grafana_port}), which "
                       + ("keeps up-to-date containers" if exists else "starts them"))
            if not self.dry_run:
                self.target_dir.mkdir(parents=True, exist_ok=True)
                o.run(o.monitoring_compose("up", "-d", "prometheus", "grafana", quiet=True,
                                           compose=MONITORING_COMPOSE, project=MONITORING_PROJECT),
                      env=self._compose_env())

        def wait() -> None:
            prometheus = f"http://127.0.0.1:{mon.prometheus_port}/-/ready"
            grafana = f"http://127.0.0.1:{mon.grafana_port}/api/health"
            if self.dry_run:
                self._plan(f"check that {PROMETHEUS_CONTAINER} and {GRAFANA_CONTAINER} keep "
                           f"running and answer at {prometheus} and {grafana}")
                return
            wait_service(PROMETHEUS_CONTAINER, prometheus)
            wait_service(GRAFANA_CONTAINER, grafana)
            self._say(f"Prometheus http://127.0.0.1:{mon.prometheus_port} and Grafana "
                      f"http://127.0.0.1:{mon.grafana_port} are running")

        return self._steps([("1. container ownership", owners), ("2. targets", targets),
                            ("3. start", start), ("4. wait", wait)])

    # -- preflight ---------------------------------------------------------------------------

    def _dispatched_ports(self, host_key: str) -> Optional[tuple[int, int]]:
        as_part = host_key.split("-", 1)[1].replace(":", "_")
        topology = Path(self.o.GEN) / f"AS{as_part}" / "topology.json"
        try:
            return parse_dispatched_ports(json.loads(topology.read_text()).get("dispatched_ports"))
        except (OSError, ValueError):
            return TINY_DISPATCHED_PORTS

    def _docker_root(self) -> Path:
        result = subprocess.run(["docker", "info", "--format", "{{.DockerRootDir}}"], check=False,
                                capture_output=True, text=True)
        root = Path(result.stdout.strip() or "/")
        # /var/lib/docker is usually unreadable; the filesystem containing it is the answer
        while not os.access(root, os.X_OK) and root != root.parent:
            root = root.parent
        return root

    def _routers_bound_their_logs(self) -> bool:
        o = self.o
        listing = subprocess.run(o.dc_args("ps", "--format", "{{.Service}}"), cwd=o.ROOT,
                                 check=False, capture_output=True, text=True)
        routers = [s for s in listing.stdout.split() if s.startswith("br")]
        if not routers:
            return False
        containers = subprocess.run(o.dc_args("ps", "-q", *routers), cwd=o.ROOT, check=False,
                                    capture_output=True, text=True).stdout.split()
        if len(containers) != len(routers):
            return False
        caps = subprocess.run(
            ["docker", "inspect", "--format",
             '{{index .HostConfig.LogConfig.Config "max-size"}}', *containers],
            check=False, capture_output=True, text=True)
        values = [line.strip() for line in caps.stdout.splitlines()]
        return len(values) == len(containers) and all(v and v != "<no value>" for v in values)

    def _disk_problems(self) -> list[str]:
        payload = sum(host_payload_bytes(self.experiment).values()) // 2  # each copy counted twice
        if payload == 0:
            return []
        factor = DISK_SPACE_FACTOR
        note = ""
        if not self._routers_bound_their_logs():
            factor += UNCAPPED_ROUTER_LOG_FACTOR
            note = (" (the border routers log at debug level into an unbounded Docker json-file; "
                    "cap them with logging: {driver: json-file, options: {max-size: 100m, "
                    "max-file: '3'}} on the br* services of gen/scion-dc.yml)")
        root = self._docker_root()
        needed = int(payload * factor)
        free = shutil.disk_usage(root).free
        if free >= needed:
            return []
        return [f"{root} has {free / 1e9:.1f} GB free but the payload needs about "
                f"{needed / 1e9:.1f} GB{note}"]

    # -- teardown ------------------------------------------------------------------------------

    def _stop_monitoring(self) -> None:
        o = self.o
        services = [s for s, c in (("prometheus", PROMETHEUS_CONTAINER),
                                   ("grafana", GRAFANA_CONTAINER))
                    if self._owner_check(c, s)]
        if not services:
            self._say("the monitoring containers are not running")
            return
        o.run(o.monitoring_compose("rm", "--stop", "--force", *services, quiet=True,
                                   compose=MONITORING_COMPOSE, project=MONITORING_PROJECT),
              env=self._compose_env())

    def teardown_infrastructure(self) -> list[str]:
        o, exp = self.o, self.experiment
        errors: list[str] = []
        if exp.tc:
            self._attempt(errors, "remove qdiscs", o.remove_docker_qdiscs)
        self._attempt(errors, "stop monitoring", self._stop_monitoring)
        jwt = self.jwt_paths()
        if jwt:
            self._attempt(errors, "remove JWT", lambda: o.remove_docker_jwt(
                {self._service(k) for k in jwt}, DOCKER_JWT))
        return errors


# ---------------------------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------------------------

class SSHInfra(Infra):
    kind = "ssh"
    check_tools_in_generic = False  # remote.preflight checks them, with the same tool list

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.stack = wgexp_stack(self.hb.ssh_setup, self.experiment.monitoring.prometheus_port)
        self.inventory = self._build_inventory()

    @property
    def remote(self) -> Any:
        return self.hb.remote

    @property
    def ss(self) -> Any:
        return self.hb.ssh_setup

    def _build_inventory(self) -> Any:
        """hummbwtester's Inventory of our config: deployment and hummingbird.marketplace as given."""
        exp = self.experiment
        root = copy.deepcopy(exp.raw)
        # Our schema has no such field: the controller port has only one source.
        root["deployment"]["metrics"]["local_prometheus_port"] = exp.monitoring.prometheus_port
        participants = {e.name: e.node for e in exp.endpoints}
        try:
            return self.hb.remote.load_deployment(root, participants,
                                                  relay_ports=len(exp.endpoints) + 1)
        except ValueError as err:
            raise InfraError(f"deployment: {err}") from err

    def _default_host(self, host_key: str) -> Any:
        import hosts  # lazy: hosts.py is implemented concurrently
        return hosts.SSHHost(self.inventory.hosts[host_key])

    def _ssh_host(self, node: str) -> Any:
        return self.inventory.hosts[node]

    def run_dir(self, host_key: str) -> str:
        return self._ssh_host(host_key).run_dir

    def binary_paths(self) -> dict[str, str]:
        return {k: self.remote.setup_dir(self._ssh_host(k)) + "/wireguard-go"
                for k in self.host_keys()}

    def jwt_paths(self) -> Optional[dict[str, str]]:
        senders = reserving_endpoints(self.experiment)
        if not senders:
            return None
        return {e.host_key: self.remote.jwt_path(self._ssh_host(e.host_key)) for e in senders}

    def sciond_address(self, endpoint: Endpoint) -> str:
        return self._ssh_host(endpoint.host_key).sciond

    # -- setup ---------------------------------------------------------------------------------

    def _require_modules(self) -> None:
        for name in SSH_REQUIRED_MODULES:
            _require_module(name, "hummbwtester's SSH marketplace setup needs it")

    def setup_infrastructure(self) -> list[str]:
        inv, ss, tc = self.inventory, self.ss, self.experiment.tc
        manual: list[str] = []
        completed = False
        if inv.shaping and not tc:
            raise InfraError("tc: the section is required because deployment.shaping is not empty")

        def notes() -> None:
            manual.extend(ss.ensure_marketplace_notes(inv, self.dry_run))

        steps = [
            ("1. marketplace service", lambda: (self._require_modules(),
                                                ss.ensure_marketplace(inv, self.dry_run))),
            ("2. selective qdiscs", lambda: ss.ensure_selective_qdiscs(inv, tc, self.dry_run)),
            ("3. static info Note", notes),
        ]
        failures: list[str] = []
        try:
            failures = self._steps(steps)
            completed = True
        finally:
            # A later failure must not hide the manual steps that already changed files need.
            if completed or manual:
                ss.print_manual_steps("setup", manual, self.dry_run)
        return failures

    def _preflight_hosts(self) -> list[str]:
        inv = self.inventory
        problems: list[str] = []
        participants = set(self.host_keys())
        for name in sorted(set(self.ss.setup_hosts(inv)) | participants):
            tools = SSH_REQUIRED_TOOLS if name in participants else self.remote.DEFAULT_REQUIRED_TOOLS
            try:
                self.remote.preflight(inv.hosts[name], self.dry_run, required_tools=tools)
            except (subprocess.SubprocessError, RuntimeError, OSError, ValueError) as err:
                problems.append(f"{name}: {err}")
        return problems

    def _root_problems(self, host: Any, name: str) -> list[str]:
        if host.run(["true"], check=False, root=True).returncode != 0:
            return [f"{name}: `sudo -n true` fails; WireGuard and the qdiscs need passwordless sudo"]
        return []

    def _dispatched_ports(self, host_key: str) -> Optional[tuple[int, int]]:
        path = self.ss.SCION_CONFIG_DIR + "/topology.json"
        return parse_dispatched_ports(json.loads(self._host(host_key).read_text(path))
                                      .get("dispatched_ports"))

    def _disk_problems(self) -> list[str]:
        problems = []
        for key, payload in sorted(host_payload_bytes(self.experiment).items()):
            host = self._host(key)
            run_dir = self._ssh_host(key).run_dir
            script = ('d="$1"; while [ ! -d "$d" ] && [ "$d" != / ]; do d=$(dirname "$d"); done; '
                      'df -Pk "$d"')
            result = host.run(["bash", "-c", script, "_", run_dir], check=False)
            lines = result.stdout.strip().splitlines()
            try:
                free = int(lines[-1].split()[3]) * 1024
            except (IndexError, ValueError):
                problems.append(f"{key}: cannot read the free space of {run_dir}")
                continue
            needed = int(payload * DISK_SPACE_FACTOR)
            if free < needed:
                problems.append(f"{key}: {run_dir} has {free / 1e9:.1f} GB free but the payload "
                                f"needs about {needed / 1e9:.1f} GB")
        return problems

    # -- binary and JWT ----------------------------------------------------------------------

    def install_binary(self, binary: Path) -> dict[str, str]:
        paths = self.binary_paths()

        def one(key: str) -> None:
            host = self._ssh_host(key)
            if self.ss.copy_if_changed(host, Path(binary), paths[key], SSH_BINARY_MODE,
                                       self.dry_run):
                self._say(f"{'dry-run: would deploy' if self.dry_run else 'deployed'} "
                          f"wireguard-go to {key}")
            else:
                self._say(f"wireguard-go on {key} is current")

        failures = self._steps([(f"binary on {k}", lambda k=k: one(k)) for k in paths])
        if failures:
            raise InfraError("; ".join(failures))
        return paths

    def install_jwt(self) -> Optional[dict[str, str]]:
        paths = self.jwt_paths()
        if paths is None:
            return None
        local: Optional[Path] = None
        try:
            # Logging in only reads the marketplace, so a dry run does it too (as hummbwtester).
            token = self.ss.obtain_marketplace_jwt(self.inventory)
            local = self.hb.orchestration.write_private_jwt(token)
            for key in sorted(paths):
                host = self._ssh_host(key)
                if self.ss.copy_if_changed(host, local, paths[key], "600", self.dry_run):
                    self._say(f"{'dry-run: would upload' if self.dry_run else 'uploaded'} "
                              f"marketplace JWT to {key}")
                else:
                    self._say(f"marketplace JWT on {key} is current")
        except _RECOVERABLE as err:
            raise InfraError(f"marketplace JWT: {err}") from err
        finally:
            if local is not None:
                local.unlink(missing_ok=True)
        return paths

    # -- monitoring ----------------------------------------------------------------------------

    def metric_sources(self) -> list[Any]:
        """Relay ports: local_port_base + i for endpoint i, + len(endpoints) for the runner,
        then one per border router."""
        exp, inv, ss = self.experiment, self.inventory, self.ss
        base, n = inv.local_port_base, len(exp.endpoints)
        sources = [
            ss.MetricSource(ep.node, f"{scrape_host(ep)}:{ep.api_port}", base + i,
                            wireguard_labels(exp, ep, ep.node), TARGET_WIREGUARD)
            for i, ep in enumerate(exp.endpoints)
        ]
        # host=None: the runner is on the controller, only the -R half of a relay is needed
        sources.append(ss.MetricSource(None, f"127.0.0.1:{exp.monitoring.runner_metrics_port}",
                                       base + n, {"experiment": exp.name}, TARGET_RUNNER))
        sources.extend(ss.router_metric_sources(inv, base + n + 1))
        return sources

    def target_documents(self) -> dict[str, str]:
        return self.ss.target_documents_for(self.inventory, self.metric_sources(), TARGET_FILES)

    def setup_monitoring(self) -> list[str]:
        ss, inv, stack, mon = self.ss, self.inventory, self.stack, self.experiment.monitoring
        state: dict[str, Any] = {}

        def targets() -> None:
            state["documents"] = self.target_documents()
            if self.dry_run:
                self._plan(f"write the Prometheus targets to {self.target_dir}")
                return
            self.target_dir.mkdir(parents=True, exist_ok=True)
            for relative, text in state["documents"].items():
                (self.target_dir / Path(relative).name).write_text(text)

        def prometheus() -> None:
            ss.ensure_prometheus(inv, state["documents"], self.dry_run, stack=stack)

        def relays() -> None:
            specs = ss.tunnel_specs_for(inv, self.metric_sources())
            ss.ensure_tunnels(specs, ss.prometheus_forward(inv), self.dry_run, stack=stack)

        def grafana() -> None:
            # ensure_grafana builds its health-check URL from this variable (default 3000)
            os.environ["GRAFANA_PORT"] = str(mon.grafana_port)
            ss.ensure_grafana(ss.prometheus_forward(inv), self.dry_run, stack=stack)

        def need_documents() -> None:
            if "documents" not in state:
                raise InfraError("the targets could not be built")

        return self._steps([
            ("1. targets", targets),
            ("2. Prometheus", lambda: (need_documents(), prometheus())),
            ("3. metric relays", relays),
            ("4. Grafana", grafana),
        ])

    # -- teardown ------------------------------------------------------------------------------

    def _stop_local_grafana(self) -> None:
        o = self.hb.orchestration
        owner = o.local_container_owner(GRAFANA_CONTAINER)
        expected = f"{MONITORING_PROJECT}/grafana"
        if owner is None:
            return
        if owner != expected:
            raise InfraError(f"{GRAFANA_CONTAINER} belongs to {owner}, not {expected}; "
                             "refusing to stop it")
        mon = self.experiment.monitoring
        env = {**os.environ, "PROMETHEUS_PORT": str(mon.prometheus_port),
               "GRAFANA_PORT": str(mon.grafana_port)}
        o.run(o.monitoring_compose("rm", "--stop", "--force", "grafana", quiet=True,
                                   compose=MONITORING_COMPOSE, project=MONITORING_PROJECT),
              env=env)

    def _rm_rf(self, host: Any, path: str) -> None:
        import shlex
        self.remote.ssh_command(host, f"rm -rf {shlex.quote(path)}",
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def teardown_infrastructure(self) -> list[str]:
        ss, inv, stack = self.ss, self.inventory, self.stack
        errors: list[str] = []
        self._attempt(errors, "remove selective qdiscs",
                      lambda: ss.remove_selective_qdiscs(inv, self.experiment.tc))
        self._attempt(errors, "stop Grafana", self._stop_local_grafana)
        self._attempt(errors, "stop Prometheus",
                      lambda: ss.stop_prometheus(inv.hosts[inv.prometheus_host], stack=stack))
        self._attempt(errors, "close the metric relays", lambda: ss.stop_tunnels(stack=stack))
        self._attempt(errors, "stop the marketplace", lambda: ss.stop_marketplace(inv))
        prometheus_host = inv.hosts[inv.prometheus_host]
        self._attempt(errors, f"remove {stack.remote_dir} on {prometheus_host.name}",
                      lambda: self._rm_rf(prometheus_host, stack.remote_dir))
        for name in sorted(set(ss.setup_hosts(inv)) | set(self.host_keys())):
            host = inv.hosts[name]
            self._attempt(errors, f"remove {self.remote.setup_dir(host)} on {name}",
                          lambda host=host: self._rm_rf(host, self.remote.setup_dir(host)))
        return errors
