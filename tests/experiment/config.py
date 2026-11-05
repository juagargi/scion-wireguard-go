"""Load and validate an experiment configuration (experiment.schema.json).

Standard library only: this module must import and run without PyYAML, jsonschema or
hummbwtester, so that the unit tests run anywhere. The JSON schema covers shapes; this module
re-checks the shapes it needs (it rejects unknown fields, missing fields and wrong types, with the
JSON path of the offending value) and then enforces the semantic rules of the experiment
(unique names, ports and interfaces, tunnel prefixes, workload endpoints, ...). Every error is a ConfigError whose message starts with the JSON path,
e.g. ``tunnels[1].endpoints[0].api_port: ...``.

Not checked here, because hummbwtester owns them: the marketplace rules that depend on the
deployment (host required on SSH and forbidden on Docker, scion_address on loopback, interfaces
SSH-only) and the content of deployment.hosts/metrics/shaping. infra.py runs
``orchestration.parse_marketplace_config`` and ``ssh_orchestration.load_deployment`` for those.

Defaults decided here (all from the schema, except where noted):

* interface: ``wgx-<tunnel id>``.
* api_bind: ``0.0.0.0`` on Docker, ``127.0.0.1`` on SSH. In Docker the testers' API is scraped by
  the host-networked Prometheus through the container IP, so it has to listen on all interfaces;
  the schema spells this default ``0.0.0.0`` (the same as net.Listen's ``:port``), which is what is
  implemented. On SSH hosts ``POST /path`` is unauthenticated, so the API stays on loopback.
  Use Endpoint.api_address for the ``SCION_PATH_API_ADDRESS`` value (IPv6 binds get brackets).
* Endpoint.host: ``None`` when absent. Docker: the runner discovers it at run time (``scion address``
  in the tester container). SSH: always set.
* iperf3 ``length``: tunnel mtu - 100 for UDP, ``None`` (iperf3's own default) for TCP.
* bwlimit of file_copy: ``reservation`` if the sender has a reservation, else ``none``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional, Union


class ConfigError(Exception):
    """An invalid experiment configuration. The message starts with the JSON path."""


# ---------------------------------------------------------------------------------------------
# Value parsers
# ---------------------------------------------------------------------------------------------

_BANDWIDTH_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)?)([kKmMgG])bps$")
_DURATION_RE = re.compile(r"^-?(?:[0-9]+(?:\.[0-9]+)?(?:ns|us|µs|ms|s|m|h))+$")
_DURATION_PART_RE = re.compile(r"([0-9]+(?:\.[0-9]+)?)(ns|us|µs|ms|s|m|h)")
_SIZE_RE = re.compile(r"^([0-9]+)(B|KiB|MiB|GiB|TiB)$")
_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_TUNNEL_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,11}$")
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
_ISD_AS_RE = re.compile(
    r"^[0-9]+-([0-9]+|[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4})$")
_ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")

_BANDWIDTH_UNITS = {"k": 10**3, "m": 10**6, "g": 10**9}
_DURATION_UNITS = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1.0, "m": 60.0, "h": 3600.0}
_SIZE_UNITS = {"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40}


def parse_bandwidth(text: str) -> int:
    """'20mbps' -> bits per second (decimal prefixes, as wireguard-go reads them)."""
    m = _BANDWIDTH_RE.match(text) if isinstance(text, str) else None
    if not m:
        raise ValueError(f"invalid bandwidth {text!r}, expected e.g. 20mbps")
    return int(round(float(m.group(1)) * _BANDWIDTH_UNITS[m.group(2).lower()]))


def parse_duration(text: str) -> float:
    """A Go duration ('30s', '-5s', '1m30s', '200ms', '0') -> seconds."""
    if text == "0":
        return 0.0
    if not isinstance(text, str) or not _DURATION_RE.match(text):
        raise ValueError(f"invalid duration {text!r}, expected a Go duration such as 30s or 1m30s")
    total = sum(float(n) * _DURATION_UNITS[u] for n, u in _DURATION_PART_RE.findall(text))
    return -total if text.startswith("-") else total


def parse_size(text: str) -> int:
    """'1GiB' -> bytes (binary units)."""
    m = _SIZE_RE.match(text) if isinstance(text, str) else None
    if not m:
        raise ValueError(f"invalid size {text!r}, expected e.g. 1GiB")
    return int(m.group(1)) * _SIZE_UNITS[m.group(2)]


# ---------------------------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Reservation:
    """endpoint.hummingbird: the reservations the endpoint buys towards its peer."""
    bandwidth: str
    bandwidth_bps: int
    duration: str
    duration_seconds: float
    reverse_bandwidth: Optional[str] = None
    reverse_bandwidth_bps: Optional[int] = None
    renewal_ahead: Optional[str] = None
    renewal_ahead_seconds: Optional[float] = None
    reservation_overlap: Optional[str] = None
    reservation_overlap_seconds: Optional[float] = None
    humm_start_offset: Optional[str] = None
    humm_start_offset_seconds: Optional[float] = None
    partial: Optional[str] = None
    path_to_marketplace_filter: Optional[str] = None
    max_price: Optional[int] = None

    def env(self) -> dict[str, str]:
        """The HUMMINGBIRD_* variables of this reservation (strings as given in the config).

        HUMMINGBIRD_MARKETPLACE_INSECURE and HUMMINGBIRD_MARKETPLACE_ADDRESS come from the
        experiment, see Experiment.hummingbird_env().
        """
        pairs = (
            ("HUMMINGBIRD_BANDWIDTH", self.bandwidth),
            ("HUMMINGBIRD_REVERSE_BANDWIDTH", self.reverse_bandwidth),
            ("HUMMINGBIRD_DURATION", self.duration),
            ("HUMMINGBIRD_RENEWAL_AHEAD", self.renewal_ahead),
            ("HUMMINGBIRD_RESERVATION_OVERLAP", self.reservation_overlap),
            ("HUMMINGBIRD_START_OFFSET", self.humm_start_offset),
            ("HUMMINGBIRD_PARTIAL", self.partial),
            ("HUMMINGBIRD_PATH_TO_MARKETPLACE_FILTER", self.path_to_marketplace_filter),
            ("HUMMINGBIRD_MAX_PRICE", None if self.max_price is None else str(self.max_price)),
        )
        return {k: v for k, v in pairs if v is not None}


@dataclass(frozen=True)
class Endpoint:
    name: str
    tunnel_id: str
    isd_as: str
    node: Optional[str]            # SSH deployment host; None on Docker
    host: Optional[str]            # SCION host address; None on Docker = discover at run time
    listen_port: int
    tunnel_ip: str
    api_port: int
    api_bind: str
    interface: str
    path_filter: Optional[str]
    path_policy: Optional[str]
    hummingbird: Optional[Reservation]
    env: dict = field(default_factory=dict)
    deployment_kind: str = "docker"

    @property
    def host_key(self) -> str:
        """The unit that identifies the machine/container: node on SSH, isd_as on Docker."""
        return self.node if self.node is not None else self.isd_as

    @property
    def api_address(self) -> str:
        """SCION_PATH_API_ADDRESS: api_bind:api_port, IPv6 binds in brackets."""
        bind = f"[{self.api_bind}]" if ":" in self.api_bind else self.api_bind
        return f"{bind}:{self.api_port}"


@dataclass(frozen=True)
class Tunnel:
    id: str
    mtu: int
    prefix_len: int
    persistent_keepalive: int
    use_batch: bool
    endpoints: tuple
    network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


@dataclass(frozen=True)
class Marketplace:
    host: Optional[str]
    scion_address: Optional[str]
    username: str
    password_env: str
    sub_account: Optional[str]
    location_override: bool
    interfaces: Optional[dict]


@dataclass(frozen=True)
class Workload:
    id: str
    kind: str
    from_: str
    to: str
    role: str
    start_delay: float
    timeout: Optional[float]
    tunnel: Tunnel

    @property
    def sender(self) -> Endpoint:
        return next(e for e in self.tunnel.endpoints if e.name == self.from_)

    @property
    def receiver(self) -> Endpoint:
        return next(e for e in self.tunnel.endpoints if e.name == self.to)


@dataclass(frozen=True)
class FileCopy(Workload):
    size: str
    size_bytes: int
    verify: bool
    repeat: int
    bwlimit: str                       # "reservation", "none" or a bandwidth such as "5mbps"
    bwlimit_bps: Optional[int]         # only for an explicit rate
    keep_files: bool


@dataclass(frozen=True)
class Iperf3(Workload):
    protocol: str
    bandwidth: Optional[str]
    bandwidth_bps: Optional[int]
    length: Optional[int]
    duration: Optional[float]          # seconds; None = until stopped (-t 0)
    parallel: int
    server_port: int                   # unique per receiver host, 5201 + index


@dataclass(frozen=True)
class Ping(Workload):
    interval: float                    # seconds
    payload_size: int


@dataclass(frozen=True)
class RunSettings:
    warmup: float
    cooldown: float
    max_duration: Optional[float]


@dataclass(frozen=True)
class Monitoring:
    prometheus_port: int
    grafana_port: int
    runner_metrics_port: int
    scrape_interval_seconds: float
    scrape_interval: str = "1s"


@dataclass(frozen=True)
class DockerDeployment:
    router: dict = field(default_factory=dict)
    kind: str = "docker"


@dataclass(frozen=True)
class SSHDeployment:
    raw: dict                          # the deployment section as in the JSON
    kind: str = "ssh"

    @property
    def hosts(self) -> dict:
        return self.raw["hosts"]


Deployment = Union[DockerDeployment, SSHDeployment]


@dataclass(frozen=True)
class Experiment:
    name: str
    path: Path
    sha256: str
    informative: tuple
    marketplace: Optional[Marketplace]
    marketplace_insecure: bool
    tunnels: tuple
    workloads: tuple
    run: RunSettings
    monitoring: Monitoring
    deployment: Deployment
    tc: dict
    raw: dict

    @property
    def kind(self) -> str:
        return self.deployment.kind

    @property
    def endpoints(self) -> tuple:
        return tuple(e for t in self.tunnels for e in t.endpoints)

    def endpoint(self, name: str) -> Endpoint:
        for e in self.endpoints:
            if e.name == name:
                return e
        raise KeyError(name)

    def tunnel_of(self, endpoint_name: str) -> Tunnel:
        for t in self.tunnels:
            if any(e.name == endpoint_name for e in t.endpoints):
                return t
        raise KeyError(endpoint_name)

    def peer_of(self, endpoint_name: str) -> Endpoint:
        a, b = self.tunnel_of(endpoint_name).endpoints
        return b if a.name == endpoint_name else a

    def hummingbird_env(self, endpoint: Union[str, Endpoint]) -> dict[str, str]:
        """All Hummingbird variables of an endpoint (empty without a reservation): the
        reservation's, HUMMINGBIRD_MARKETPLACE_INSECURE=1 and, with location_override,
        HUMMINGBIRD_MARKETPLACE_ADDRESS. SCION_MARKETPLACE_JWT is added by the caller."""
        ep = self.endpoint(endpoint) if isinstance(endpoint, str) else endpoint
        if ep.hummingbird is None:
            return {}
        env = ep.hummingbird.env()
        if self.marketplace_insecure:
            env["HUMMINGBIRD_MARKETPLACE_INSECURE"] = "1"
        if self.marketplace is not None and self.marketplace.location_override:
            env["HUMMINGBIRD_MARKETPLACE_ADDRESS"] = self.marketplace.scion_address
        return env


# ---------------------------------------------------------------------------------------------
# Structural helpers (each error names the JSON path)
# ---------------------------------------------------------------------------------------------

def _fail(path: str, message: str) -> "ConfigError":
    return ConfigError(f"{path}: {message}" if path else message)


def _obj(value: Any, path: str, required: tuple = (), optional: tuple = ()) -> dict:
    if not isinstance(value, dict):
        raise _fail(path, "must be an object")
    for key in required:
        if key not in value:
            raise _fail(path, f"missing required field '{key}'")
    for key in value:
        if key not in required and key not in optional:
            raise _fail(f"{path}.{key}" if path else key, "unknown field")
    return value


def _list(value: Any, path: str, min_items: int = 0, max_items: Optional[int] = None) -> list:
    if not isinstance(value, list):
        raise _fail(path, "must be an array")
    if len(value) < min_items or (max_items is not None and len(value) > max_items):
        want = f"at least {min_items}" if max_items is None else f"{min_items}..{max_items}"
        if min_items == max_items:
            want = str(min_items)
        raise _fail(path, f"must have {want} items, has {len(value)}")
    return value


def _str(value: Any, path: str, pattern: Optional["re.Pattern"] = None, what: str = "") -> str:
    if not isinstance(value, str) or (not value and pattern is None):
        raise _fail(path, "must be a non-empty string")
    if pattern is not None and not pattern.match(value):
        raise _fail(path, f"invalid {what or 'value'} {value!r}")
    return value


def _int(value: Any, path: str, lo: Optional[int] = None, hi: Optional[int] = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail(path, "must be an integer")
    if (lo is not None and value < lo) or (hi is not None and value > hi):
        raise _fail(path, f"{value} is out of range {lo}..{hi}")
    return value


def _bool(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise _fail(path, "must be a boolean")
    return value


def _port(value: Any, path: str) -> int:
    return _int(value, path, 1, 65535)


def _ip(value: Any, path: str) -> str:
    if not isinstance(value, str):
        raise _fail(path, "must be an IP address string")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise _fail(path, f"invalid IP address {value!r}") from None
    return value


def _duration(value: Any, path: str) -> float:
    try:
        return parse_duration(value)
    except ValueError as e:
        raise _fail(path, str(e)) from None


def _bandwidth(value: Any, path: str) -> int:
    try:
        return parse_bandwidth(value)
    except ValueError as e:
        raise _fail(path, str(e)) from None


# ---------------------------------------------------------------------------------------------
# Section parsers
# ---------------------------------------------------------------------------------------------

def _parse_reservation(raw: Any, path: str) -> Reservation:
    d = _obj(raw, path, ("bandwidth", "duration"),
             ("reverse_bandwidth", "renewal_ahead", "reservation_overlap", "humm_start_offset",
              "partial", "path_to_marketplace_filter", "max_price"))
    kw: dict[str, Any] = {}
    kw["bandwidth"] = d["bandwidth"]
    kw["bandwidth_bps"] = _bandwidth(d["bandwidth"], f"{path}.bandwidth")
    kw["duration"] = d["duration"]
    kw["duration_seconds"] = _duration(d["duration"], f"{path}.duration")
    if kw["duration_seconds"] <= 0:
        raise _fail(f"{path}.duration", "must be positive")
    if "reverse_bandwidth" in d:
        kw["reverse_bandwidth"] = d["reverse_bandwidth"]
        kw["reverse_bandwidth_bps"] = _bandwidth(d["reverse_bandwidth"], f"{path}.reverse_bandwidth")
    for key in ("renewal_ahead", "reservation_overlap", "humm_start_offset"):
        if key in d:
            kw[key] = d[key]
            kw[key + "_seconds"] = _duration(d[key], f"{path}.{key}")
    for key in ("partial", "path_to_marketplace_filter"):
        if key in d:
            kw[key] = _str(d[key], f"{path}.{key}")
    if "max_price" in d:
        kw["max_price"] = _int(d["max_price"], f"{path}.max_price", 0)
    return Reservation(**kw)


def _parse_marketplace(raw: Any, path: str) -> Marketplace:
    d = _obj(raw, path, ("username", "password_env", "location_override"),
             ("host", "scion_address", "sub_account", "interfaces"))
    _str(d["username"], f"{path}.username")
    _str(d["password_env"], f"{path}.password_env", _ENV_NAME_RE, "environment variable name")
    _bool(d["location_override"], f"{path}.location_override")
    for key in ("host", "scion_address", "sub_account"):
        if key in d:
            _str(d[key], f"{path}.{key}")
    if "scion_address" in d and not re.match(r"^\[[0-9]+-[0-9a-fA-F:]+,[^\]]+\]:[0-9]{1,5}$",
                                             d["scion_address"]):
        raise _fail(f"{path}.scion_address",
                    f"{d['scion_address']!r} is not a SCION address [ISD-AS,IP]:port")
    if d["location_override"] and "scion_address" not in d:
        raise _fail(f"{path}.scion_address", "is required with location_override")
    if "interfaces" in d:
        ifaces = _obj(d["interfaces"], f"{path}.interfaces", optional=tuple(d["interfaces"])
                      if isinstance(d["interfaces"], dict) else ())
        for ia, ids in ifaces.items():
            _str(ia, f"{path}.interfaces", _ISD_AS_RE, "ISD-AS")
            for i, v in enumerate(_list(ids, f"{path}.interfaces.{ia}")):
                _int(v, f"{path}.interfaces.{ia}[{i}]", 0)
    return Marketplace(
        host=d.get("host"), scion_address=d.get("scion_address"), username=d["username"],
        password_env=d["password_env"], sub_account=d.get("sub_account"),
        location_override=d["location_override"], interfaces=d.get("interfaces"))


def _parse_endpoint(raw: Any, path: str, tunnel_id: str, kind: str,
                    ssh_hosts: Mapping[str, Any]) -> Endpoint:
    d = _obj(raw, path, ("name", "isd_as", "listen_port", "tunnel_ip", "api_port"),
             ("node", "host", "interface", "api_bind", "path_filter", "path_policy",
              "hummingbird", "env"))
    name = _str(d["name"], f"{path}.name", _ID_RE, "name")
    isd_as = _str(d["isd_as"], f"{path}.isd_as", _ISD_AS_RE, "ISD-AS")
    if kind == "ssh":
        if "node" not in d:
            raise _fail(f"{path}.node", "is required in an ssh deployment")
        node = _str(d["node"], f"{path}.node")
        if node not in ssh_hosts:
            raise _fail(f"{path}.node",
                        f"{node!r} is not a host of deployment.hosts ({', '.join(sorted(ssh_hosts))})")
        if "host" not in d:
            raise _fail(f"{path}.host", "is required in an ssh deployment")
    else:
        if "node" in d:
            raise _fail(f"{path}.node", "is not allowed in a docker deployment "
                        "(the endpoint runs in the tester container of isd_as)")
        node = None
    host = _ip(d["host"], f"{path}.host") if "host" in d else None
    interface = d.get("interface", f"wgx-{tunnel_id}")
    _str(interface, f"{path}.interface", _IFACE_RE, "interface name (1-15 chars)")
    api_bind = _ip(d["api_bind"], f"{path}.api_bind") if "api_bind" in d else (
        "127.0.0.1" if kind == "ssh" else "0.0.0.0")
    env = d.get("env", {})
    _obj(env, f"{path}.env", optional=tuple(env) if isinstance(env, dict) else ())
    for k, v in env.items():
        if not isinstance(v, str):
            raise _fail(f"{path}.env.{k}", "must be a string")
    return Endpoint(
        name=name, tunnel_id=tunnel_id, isd_as=isd_as, node=node, host=host,
        listen_port=_port(d["listen_port"], f"{path}.listen_port"),
        tunnel_ip=_ip(d["tunnel_ip"], f"{path}.tunnel_ip"),
        api_port=_port(d["api_port"], f"{path}.api_port"), api_bind=api_bind,
        interface=interface,
        path_filter=_str(d["path_filter"], f"{path}.path_filter") if "path_filter" in d else None,
        path_policy=_str(d["path_policy"], f"{path}.path_policy") if "path_policy" in d else None,
        hummingbird=(_parse_reservation(d["hummingbird"], f"{path}.hummingbird")
                     if "hummingbird" in d else None),
        env=dict(env), deployment_kind=kind)


def _parse_tunnel(raw: Any, path: str, kind: str, ssh_hosts: Mapping[str, Any]) -> Tunnel:
    d = _obj(raw, path, ("id", "endpoints"),
             ("prefix_len", "mtu", "persistent_keepalive", "use_batch"))
    tid = _str(d["id"], f"{path}.id", _TUNNEL_ID_RE, "tunnel id (1-11 chars)")
    prefix_len = _int(d.get("prefix_len", 24), f"{path}.prefix_len", 8, 30)
    mtu = _int(d.get("mtu", 1000), f"{path}.mtu", 576, 9000)
    keepalive = _int(d.get("persistent_keepalive", 25), f"{path}.persistent_keepalive", 0)
    use_batch = _bool(d.get("use_batch", True), f"{path}.use_batch")
    eps = tuple(_parse_endpoint(e, f"{path}.endpoints[{i}]", tid, kind, ssh_hosts)
                for i, e in enumerate(_list(d["endpoints"], f"{path}.endpoints", 2, 2)))
    a, b = eps
    ia, ib = ipaddress.ip_address(a.tunnel_ip), ipaddress.ip_address(b.tunnel_ip)
    if ia.version != ib.version:
        raise _fail(f"{path}.endpoints[1].tunnel_ip",
                    f"{b.tunnel_ip} is not the same IP version as {a.tunnel_ip}")
    network = ipaddress.ip_network(f"{a.tunnel_ip}/{prefix_len}", strict=False)
    if ib not in network:
        raise _fail(f"{path}.endpoints[1].tunnel_ip",
                    f"{b.tunnel_ip} is not in {network}, the /{prefix_len} of "
                    f"{path}.endpoints[0].tunnel_ip ({a.tunnel_ip})")
    if ia == ib:
        raise _fail(f"{path}.endpoints[1].tunnel_ip", f"equals the tunnel_ip of endpoints[0]")
    return Tunnel(id=tid, mtu=mtu, prefix_len=prefix_len, persistent_keepalive=keepalive,
                  use_batch=use_batch, endpoints=eps, network=network)


def _parse_workload(raw: Any, path: str, experiment_endpoints: Mapping[str, Endpoint],
                    tunnels_of: Mapping[str, Tunnel], port_counter: dict, run_has_max: bool
                    ) -> Workload:
    if not isinstance(raw, dict):
        raise _fail(path, "must be an object")
    kind = raw.get("kind")
    if kind not in ("file_copy", "iperf3", "ping"):
        raise _fail(f"{path}.kind", f"must be file_copy, iperf3 or ping, got {kind!r}")
    common_req = ("id", "kind", "from", "to")
    common_opt = ("role", "start_delay", "timeout")
    extra = {
        "file_copy": (("size",), ("verify", "repeat", "bwlimit", "keep_files")),
        "iperf3": ((), ("protocol", "bandwidth", "length", "duration", "parallel")),
        "ping": ((), ("interval", "payload_size")),
    }[kind]
    d = _obj(raw, path, common_req + extra[0], common_opt + extra[1])
    wid = _str(d["id"], f"{path}.id", _ID_RE, "id")
    from_, to = _str(d["from"], f"{path}.from", _ID_RE, "endpoint name"), \
        _str(d["to"], f"{path}.to", _ID_RE, "endpoint name")
    for key, ep in (("from", from_), ("to", to)):
        if ep not in experiment_endpoints:
            raise _fail(f"{path}.{key}", f"unknown endpoint {ep!r}")
    tunnel = tunnels_of[from_]
    if tunnels_of[to] is not tunnel or from_ == to:
        raise _fail(f"{path}.to", f"{to!r} is not the other end of the tunnel of "
                    f"{path}.from ({from_!r}, tunnel {tunnel.id!r})")
    role = d.get("role", "primary")
    if role not in ("primary", "background"):
        raise _fail(f"{path}.role", f"must be primary or background, got {role!r}")
    start_delay = _duration(d.get("start_delay", "0s"), f"{path}.start_delay")
    timeout = _duration(d["timeout"], f"{path}.timeout") if "timeout" in d else None
    if timeout is not None and timeout <= 0:
        raise _fail(f"{path}.timeout", "must be positive")
    base = dict(id=wid, kind=kind, from_=from_, to=to, role=role, start_delay=start_delay,
                timeout=timeout, tunnel=tunnel)
    sender = experiment_endpoints[from_]

    if kind == "file_copy":
        size = d["size"]
        try:
            size_bytes = parse_size(size)
        except ValueError as e:
            raise _fail(f"{path}.size", str(e)) from None
        if size_bytes <= 0:
            raise _fail(f"{path}.size", "must be positive")
        repeat = _int(d.get("repeat", 1), f"{path}.repeat", 0)
        if repeat == 0 and role != "background":
            raise _fail(f"{path}.repeat", "0 (repeat until stopped) is only allowed for "
                        "background workloads")
        bwlimit = d.get("bwlimit", "reservation" if sender.hummingbird else "none")
        bwlimit_bps = None
        if bwlimit == "reservation":
            if sender.hummingbird is None:
                raise _fail(f"{path}.bwlimit", f"'reservation' needs a sender with a reservation, "
                            f"but endpoint {from_!r} has no hummingbird section")
        elif bwlimit != "none":
            bwlimit_bps = _bandwidth(bwlimit, f"{path}.bwlimit")
        return FileCopy(**base, size=size, size_bytes=size_bytes,
                        verify=_bool(d.get("verify", True), f"{path}.verify"), repeat=repeat,
                        bwlimit=bwlimit, bwlimit_bps=bwlimit_bps,
                        keep_files=_bool(d.get("keep_files", False), f"{path}.keep_files"))

    if kind == "iperf3":
        protocol = d.get("protocol", "tcp")
        if protocol not in ("tcp", "udp"):
            raise _fail(f"{path}.protocol", f"must be tcp or udp, got {protocol!r}")
        bandwidth = bandwidth_bps = None
        if "bandwidth" in d:
            bandwidth = d["bandwidth"]
            bandwidth_bps = _bandwidth(bandwidth, f"{path}.bandwidth")
        elif protocol == "udp":
            raise _fail(f"{path}.bandwidth", "is required for protocol udp")
        length = None
        if "length" in d:
            length = _int(d["length"], f"{path}.length", 64, 65507)
        elif protocol == "udp":
            length = tunnel.mtu - 100
        if protocol == "udp" and length > tunnel.mtu - 28:
            raise _fail(f"{path}.length", f"{length} does not fit into the tunnel mtu "
                        f"{tunnel.mtu} - 28 = {tunnel.mtu - 28} (tunnel {tunnel.id!r})")
        duration = None
        if "duration" in d:
            duration = _duration(d["duration"], f"{path}.duration")
            if duration <= 0:
                raise _fail(f"{path}.duration", "must be positive")
        elif role != "background":
            raise _fail(f"{path}.duration", "is required for primary workloads "
                        "(without it iperf3 runs until stopped, background only)")
        receiver = experiment_endpoints[to]
        index = port_counter.get(receiver.host_key, 0)
        port_counter[receiver.host_key] = index + 1
        return Iperf3(**base, protocol=protocol, bandwidth=bandwidth, bandwidth_bps=bandwidth_bps,
                      length=length, duration=duration,
                      parallel=_int(d.get("parallel", 1), f"{path}.parallel", 1),
                      server_port=5201 + index)

    interval = _duration(d.get("interval", "200ms"), f"{path}.interval")
    if interval <= 0:
        raise _fail(f"{path}.interval", "must be positive")
    return Ping(**base, interval=interval,
                payload_size=_int(d.get("payload_size", 56), f"{path}.payload_size", 0, 1400))


def _parse_run(raw: Any) -> RunSettings:
    d = _obj(raw, "run", optional=("warmup", "cooldown", "max_duration"))
    warmup = _duration(d.get("warmup", "30s"), "run.warmup")
    cooldown = _duration(d.get("cooldown", "10s"), "run.cooldown")
    max_duration = _duration(d["max_duration"], "run.max_duration") if "max_duration" in d else None
    for key, v in (("warmup", warmup), ("cooldown", cooldown)):
        if v < 0:
            raise _fail(f"run.{key}", "must not be negative")
    if max_duration is not None and max_duration <= 0:
        raise _fail("run.max_duration", "must be positive")
    return RunSettings(warmup, cooldown, max_duration)


def _parse_monitoring(raw: Any) -> Monitoring:
    d = _obj(raw, "monitoring", optional=("prometheus_port", "grafana_port",
                                           "runner_metrics_port", "scrape_interval"))
    interval = d.get("scrape_interval", "1s")
    seconds = _duration(interval, "monitoring.scrape_interval")
    if seconds <= 0:
        raise _fail("monitoring.scrape_interval", "must be positive")
    return Monitoring(
        prometheus_port=_port(d.get("prometheus_port", 8091), "monitoring.prometheus_port"),
        grafana_port=_port(d.get("grafana_port", 3001), "monitoring.grafana_port"),
        runner_metrics_port=_port(d.get("runner_metrics_port", 9189),
                                  "monitoring.runner_metrics_port"),
        scrape_interval_seconds=seconds, scrape_interval=interval)


_TC_VALUE_RE = re.compile(r"^[0-9]+(\.[0-9]+)?([bB]it|[kKmMgG]bit|b|kb|mb|gb|ms|us|s)?$")


def _parse_tc(raw: Any) -> dict:
    d = _obj(raw, "tc", ("rate", "burst", "limit"))
    for k, v in d.items():
        _str(v, f"tc.{k}", _TC_VALUE_RE, "tc value")
    return dict(d)


def _parse_deployment(raw: Any) -> Deployment:
    if not isinstance(raw, dict):
        raise _fail("deployment", "must be an object")
    kind = raw.get("kind")
    if kind == "docker":
        d = _obj(raw, "deployment", ("kind",), ("router",))
        router = d.get("router", {})
        _obj(router, "deployment.router", optional=(
            "send_buffer_size", "receive_buffer_size", "ingress_batch_size",
            "processor_queue_size", "egress_batch_size", "egress_queue_size"))
        for k, v in router.items():
            _int(v, f"deployment.router.{k}", 0)
        return DockerDeployment(router=dict(router))
    if kind == "ssh":
        # The rest belongs to hummbwtester's load_deployment; only the shape needed here.
        _obj(raw, "deployment", ("kind", "hosts", "metrics", "shaping"))
        hosts = _obj(raw["hosts"], "deployment.hosts", optional=tuple(raw["hosts"])
                     if isinstance(raw["hosts"], dict) else ())
        if not hosts:
            raise _fail("deployment.hosts", "must not be empty")
        _obj(raw["metrics"], "deployment.metrics", ("prometheus",),
             ("local_port_base", "routers", "local_prometheus_port"))
        _list(raw["shaping"], "deployment.shaping")
        return SSHDeployment(raw=raw)
    raise _fail("deployment.kind", f"must be docker or ssh, got {kind!r}")


# ---------------------------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------------------------

def _unique(experiment_paths: list, what: str) -> None:
    seen: dict[str, str] = {}
    for value, path in experiment_paths:
        if value in seen:
            raise _fail(path, f"duplicate {what} {value!r} (first used at {seen[value]})")
        seen[value] = path


def load_config(path: Path) -> Experiment:
    """Read, validate and return the experiment at path. Raises ConfigError."""
    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError as e:
        raise ConfigError(f"{path}: cannot read: {e}") from None
    try:
        raw = json.loads(data)
    except ValueError as e:
        raise ConfigError(f"{path}: invalid JSON: {e}") from None
    return parse_config(raw, path, hashlib.sha256(data).hexdigest())


def parse_config(raw: Any, path: Path, sha256: str = "") -> Experiment:
    """Validate an already parsed configuration (what load_config does after reading)."""
    top = _obj(raw, "", ("tunnels", "workloads", "deployment"),
               ("$schema", "informative", "name", "hummingbird", "run", "monitoring", "tc"))
    name = _str(top["name"], "name", _ID_RE, "name") if "name" in top else Path(path).stem
    if "name" not in top:
        _str(name, "name", _ID_RE, "name (from the file name)")
    informative = tuple(_str(s, f"informative[{i}]") if s != "" else s
                        for i, s in enumerate(_list(top.get("informative", []), "informative")))
    deployment = _parse_deployment(top["deployment"])
    kind = deployment.kind
    ssh_hosts = deployment.hosts if kind == "ssh" else {}

    # hummingbird section
    marketplace = None
    insecure = False
    if "hummingbird" in top:
        h = _obj(top["hummingbird"], "hummingbird", ("marketplace",), ("marketplace_insecure",))
        marketplace = _parse_marketplace(h["marketplace"], "hummingbird.marketplace")
        insecure = _bool(h.get("marketplace_insecure", False), "hummingbird.marketplace_insecure")
        if marketplace.host is not None and kind == "ssh" and marketplace.host not in ssh_hosts:
            raise _fail("hummingbird.marketplace.host",
                        f"{marketplace.host!r} is not a host of deployment.hosts")

    # tunnels and endpoints
    tunnels = tuple(_parse_tunnel(t, f"tunnels[{i}]", kind, ssh_hosts)
                    for i, t in enumerate(_list(top["tunnels"], "tunnels", 1)))
    _unique([(t.id, f"tunnels[{i}].id") for i, t in enumerate(tunnels)], "tunnel id")
    _unique([(e.name, f"tunnels[{i}].endpoints[{j}].name")
             for i, t in enumerate(tunnels) for j, e in enumerate(t.endpoints)], "endpoint name")

    def where(e: Endpoint) -> str:
        i = next(k for k, t in enumerate(tunnels) if t.id == e.tunnel_id)
        j = next(k for k, x in enumerate(tunnels[i].endpoints) if x.name == e.name)
        return f"tunnels[{i}].endpoints[{j}]"

    # per host: listen_port, api_port, interface
    for field_name in ("listen_port", "api_port", "interface"):
        seen: dict[tuple, Endpoint] = {}
        for t in tunnels:
            for e in t.endpoints:
                key = (e.host_key, getattr(e, field_name))
                if key in seen:
                    other = seen[key]
                    raise _fail(f"{where(e)}.{field_name}",
                                f"{key[1]!r} is already used by {where(other)} ({other.name}) "
                                f"on host {e.host_key!r}")
                seen[key] = e

    # tunnel prefixes
    for i, a in enumerate(tunnels):
        for j in range(i):
            b = tunnels[j]
            if a.network.version == b.network.version and a.network.overlaps(b.network):
                raise _fail(f"tunnels[{i}].endpoints[0].tunnel_ip",
                            f"the network {a.network} of tunnel {a.id!r} overlaps {b.network} "
                            f"of tunnel {b.id!r} (tunnels[{j}])")

    # hummingbird iff some endpoint has a reservation
    with_reservation = [where(e) for t in tunnels for e in t.endpoints if e.hummingbird]
    if with_reservation and marketplace is None:
        raise _fail("hummingbird", f"is required because {with_reservation[0]}.hummingbird "
                    "has a reservation")
    if not with_reservation and "hummingbird" in top:
        raise _fail("hummingbird", "is present but no endpoint has a hummingbird reservation")

    # run / monitoring / tc
    run = _parse_run(top.get("run", {}))
    monitoring = _parse_monitoring(top.get("monitoring", {}))
    tc = _parse_tc(top["tc"]) if "tc" in top else {}

    # workloads
    endpoints = {e.name: e for t in tunnels for e in t.endpoints}
    tunnels_of = {e.name: t for t in tunnels for e in t.endpoints}
    port_counter: dict[str, int] = {}
    workloads = tuple(
        _parse_workload(w, f"workloads[{i}]", endpoints, tunnels_of, port_counter,
                        run.max_duration is not None)
        for i, w in enumerate(_list(top["workloads"], "workloads", 1)))
    _unique([(w.id, f"workloads[{i}].id") for i, w in enumerate(workloads)], "workload id")
    # iperf3 server ports are assigned uniquely per receiver host; check anyway
    seen_ports: dict[tuple, str] = {}
    for i, w in enumerate(workloads):
        if isinstance(w, Iperf3):
            key = (w.receiver.host_key, w.server_port)
            if key in seen_ports:
                raise _fail(f"workloads[{i}]", f"iperf3 server port {w.server_port} is already "
                            f"used by {seen_ports[key]} on host {key[0]!r}")
            seen_ports[key] = f"workloads[{i}]"

    # primary workloads and max_duration
    if not any(w.role == "primary" for w in workloads) and run.max_duration is None:
        raise _fail("run.max_duration", "is required when there is no primary workload")
    if run.max_duration is not None:
        for i, w in enumerate(workloads):
            if w.role == "primary" and w.timeout is not None and w.timeout > run.max_duration:
                raise _fail(f"workloads[{i}].timeout",
                            f"{raw['workloads'][i]['timeout']} exceeds run.max_duration "
                            f"({top['run']['max_duration']})")

    return Experiment(
        name=name, path=Path(path), sha256=sha256, informative=informative,
        marketplace=marketplace, marketplace_insecure=insecure, tunnels=tunnels,
        workloads=workloads, run=run, monitoring=monitoring, deployment=deployment, tc=tc,
        raw=raw)


def check_environment(experiment: Experiment, env: Mapping[str, str] = os.environ) -> Optional[str]:
    """Return the marketplace password (None without a marketplace).

    The password is read from the variable named by hummingbird.marketplace.password_env. On
    Docker, where the generated topology's marketplace account has the password 1234, an unset
    variable defaults to '1234'. On SSH an unset or empty variable raises ConfigError.
    """
    mp = experiment.marketplace
    if mp is None:
        return None
    value = env.get(mp.password_env)
    if value:
        return value
    if experiment.kind == "docker":
        return "1234"
    raise ConfigError(f"hummingbird.marketplace.password_env: environment variable "
                      f"{mp.password_env} is not set")
