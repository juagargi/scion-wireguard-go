"""The runner's own /metrics endpoint: a tiny prometheus_client-like API, standard library only.

Text exposition format 0.0.4. Counters are named as given (the plan's names already end in _total).
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional, Sequence

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

WORKLOAD_LABELS = ("workload", "kind", "role", "tunnel", "from", "to")

DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
# ping: 0.1 ms .. 5 s
RTT_BUCKETS = (0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1,
               0.25, 0.5, 1.0, 2.5, 5.0)


def _escape_help(text: str) -> str:
    return text.replace("\\", "\\\\").replace("\n", "\\n")


def _escape_label(text: str) -> str:
    return text.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _fmt(value: float) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    if value == int(value) and abs(value) < 1e15:
        return str(int(value))
    return repr(float(value))


def _labelstr(names: Sequence[str], values: Sequence[str], extra: str = "") -> str:
    parts = [f'{n}="{_escape_label(v)}"' for n, v in zip(names, values)]
    if extra:
        parts.append(extra)
    return "{" + ",".join(parts) + "}" if parts else ""


class _Child:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._value = 0.0

    @property
    def value(self) -> float:
        with self._lock:
            return self._value


class CounterChild(_Child):
    def inc(self, v: float = 1) -> None:
        if v < 0:
            raise ValueError("a counter cannot decrease")
        with self._lock:
            self._value += v


class GaugeChild(_Child):
    def set(self, v: float) -> None:
        with self._lock:
            self._value = float(v)

    def inc(self, v: float = 1) -> None:
        with self._lock:
            self._value += v

    def dec(self, v: float = 1) -> None:
        self.inc(-v)


class HistogramChild:
    def __init__(self, buckets: Sequence[float]) -> None:
        self._lock = threading.Lock()
        self.buckets = tuple(buckets)
        self._counts = [0] * len(self.buckets)  # per bucket, not cumulative
        self._sum = 0.0
        self._count = 0

    def observe(self, v: float) -> None:
        with self._lock:
            self._sum += v
            self._count += 1
            for i, ub in enumerate(self.buckets):
                if v <= ub:
                    self._counts[i] += 1
                    break

    def snapshot(self) -> tuple[list[int], float, int]:
        with self._lock:
            return list(self._counts), self._sum, self._count


class _Family:
    type_name = ""

    def __init__(self, name: str, help: str, labelnames: Sequence[str] = ()) -> None:
        self.name, self.help, self.labelnames = name, help, tuple(labelnames)
        self._children: dict[tuple, Any] = {}
        self._lock = threading.Lock()

    def _new_child(self) -> Any:
        raise NotImplementedError

    def labels(self, **kv: str) -> Any:
        if set(kv) != set(self.labelnames):
            raise ValueError(f"{self.name}: labels must be exactly {self.labelnames}, got {tuple(kv)}")
        key = tuple(str(kv[n]) for n in self.labelnames)
        with self._lock:
            child = self._children.get(key)
            if child is None:
                child = self._children[key] = self._new_child()
            return child

    def _default(self) -> Any:
        return self.labels()

    def children(self) -> list[tuple[tuple, Any]]:
        with self._lock:
            return sorted(self._children.items())

    def render(self) -> list[str]:
        lines = [f"# HELP {self.name} {_escape_help(self.help)}", f"# TYPE {self.name} {self.type_name}"]
        for key, child in self.children():
            lines.extend(self._render_child(key, child))
        return lines

    def _render_child(self, key: tuple, child: Any) -> list[str]:
        return [f"{self.name}{_labelstr(self.labelnames, key)} {_fmt(child.value)}"]


class Counter(_Family):
    type_name = "counter"

    def _new_child(self) -> CounterChild:
        return CounterChild()

    def inc(self, v: float = 1) -> None:
        self._default().inc(v)


class Gauge(_Family):
    type_name = "gauge"

    def _new_child(self) -> GaugeChild:
        return GaugeChild()

    def set(self, v: float) -> None:
        self._default().set(v)

    def inc(self, v: float = 1) -> None:
        self._default().inc(v)


class Histogram(_Family):
    type_name = "histogram"

    def __init__(self, name: str, help: str, labelnames: Sequence[str] = (),
                 buckets: Sequence[float] = DEFAULT_BUCKETS) -> None:
        super().__init__(name, help, labelnames)
        bs = sorted(float(b) for b in buckets if not math.isinf(b))
        if not bs:
            raise ValueError("a histogram needs at least one finite bucket")
        self.buckets = tuple(bs)

    def _new_child(self) -> HistogramChild:
        return HistogramChild(self.buckets)

    def observe(self, v: float) -> None:
        self._default().observe(v)

    def _render_child(self, key: tuple, child: HistogramChild) -> list[str]:
        counts, total, n = child.snapshot()
        out, cum = [], 0
        for ub, c in zip(self.buckets, counts):
            cum += c
            out.append(f"{self.name}_bucket{_labelstr(self.labelnames, key, 'le=' + chr(34) + _fmt(ub) + chr(34))} {cum}")
        out.append(f"{self.name}_bucket{_labelstr(self.labelnames, key, 'le=' + chr(34) + '+Inf' + chr(34))} {n}")
        out.append(f"{self.name}_sum{_labelstr(self.labelnames, key)} {_fmt(total)}")
        out.append(f"{self.name}_count{_labelstr(self.labelnames, key)} {n}")
        return out


class Registry:
    def __init__(self) -> None:
        self._families: list[_Family] = []
        self._names: set[str] = set()
        self._lock = threading.Lock()

    def _add(self, fam: _Family) -> Any:
        with self._lock:
            if fam.name in self._names:
                raise ValueError(f"metric {fam.name} already registered")
            self._names.add(fam.name)
            self._families.append(fam)
        return fam

    def counter(self, name: str, help: str, labelnames: Sequence[str] = ()) -> Counter:
        return self._add(Counter(name, help, labelnames))

    def gauge(self, name: str, help: str, labelnames: Sequence[str] = ()) -> Gauge:
        return self._add(Gauge(name, help, labelnames))

    def histogram(self, name: str, help: str, labelnames: Sequence[str] = (),
                  buckets: Sequence[float] = DEFAULT_BUCKETS) -> Histogram:
        return self._add(Histogram(name, help, labelnames, buckets))

    def render(self) -> str:
        with self._lock:
            families = list(self._families)
        lines: list[str] = []
        for fam in families:
            lines.extend(fam.render())
        return "\n".join(lines) + "\n" if lines else ""


class MetricsServer:
    """Serves registry.render() on GET /metrics from a daemon thread."""

    def __init__(self, registry: Registry, port: int, bind: str = "127.0.0.1") -> None:
        self.registry, self.bind, self.port = registry, bind, port
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        registry = self.registry

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path.split("?", 1)[0] != "/metrics":
                    self.send_error(404)
                    return
                body = registry.render().encode()
                self.send_response(200)
                self.send_header("Content-Type", CONTENT_TYPE)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:
                pass

        self._server = ThreadingHTTPServer((self.bind, self.port), Handler)
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, name="runner-metrics",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


def WorkloadLabels(workload: Any) -> dict[str, str]:
    """The label set of every per-workload metric (note the key "from": pass with **labels)."""
    return {
        "workload": workload.id,
        "kind": workload.kind,
        "role": workload.role,
        "tunnel": workload.tunnel.id,
        "from": workload.from_,
        "to": workload.to,
    }


@dataclass
class RunnerMetrics:
    registry: Registry
    experiment_name: str
    workload_state: Gauge
    workload_bytes: Counter
    workload_iterations: Counter
    workload_restarts: Counter
    verify: Counter
    iperf3_datagrams: Counter
    iperf3_lost_datagrams: Counter
    ping_rtt: Histogram
    ping_sent: Counter
    ping_received: Counter
    ping_jitter: Gauge
    reservations: Counter
    run_info: Gauge


def make_runner_registry(run_id: str, config_sha256: str, experiment_name: str) -> RunnerMetrics:
    r = Registry()
    wl = WORKLOAD_LABELS
    m = RunnerMetrics(
        registry=r,
        experiment_name=experiment_name,
        workload_state=r.gauge("wgexp_workload_state",
                               "Workload state: 0 pending, 1 running, 2 passed, 3 failed.", wl),
        workload_bytes=r.counter("wgexp_workload_bytes_total",
                                 "Payload bytes moved by the workload.", wl),
        workload_iterations=r.counter("wgexp_workload_iterations_total",
                                      "Completed iterations of the workload.", wl),
        workload_restarts=r.counter("wgexp_workload_restarts_total",
                                    "Restarts of the workload's processes.", wl),
        verify=r.counter("wgexp_verify_total", "Payload verifications by result.",
                         wl + ("result",)),
        iperf3_datagrams=r.counter("wgexp_iperf3_datagrams_total",
                                   "UDP datagrams reported by the iperf3 server.", wl),
        iperf3_lost_datagrams=r.counter("wgexp_iperf3_lost_datagrams_total",
                                        "UDP datagrams reported lost by the iperf3 server.", wl),
        ping_rtt=r.histogram("wgexp_ping_rtt_seconds", "Ping round-trip time.", wl, RTT_BUCKETS),
        ping_sent=r.counter("wgexp_ping_sent_total", "Ping requests sent (from sequence numbers).", wl),
        ping_received=r.counter("wgexp_ping_received_total", "Ping replies received.", wl),
        ping_jitter=r.gauge("wgexp_ping_jitter_seconds",
                            "Ping jitter, RFC 3550 smoothed mean deviation.", wl),
        reservations=r.counter("wgexp_reservations_total",
                               "Hummingbird reservations seen in the senders' logs.",
                               ("endpoint", "result")),
        run_info=r.gauge("wgexp_run_info", "Run identity, always 1.", ("run_id", "config_sha256")),
    )
    m.run_info.labels(run_id=run_id, config_sha256=config_sha256).set(1)
    return m
