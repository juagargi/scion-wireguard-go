"""results.json and the end-of-run summary (standard library only)."""

from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

# Regexes adapted from tests/scion-end2end.py and the lines of conn/scion_path_manager.go.
RESERVATION_IN_USE = re.compile(r"Hummingbird reservation for .* in use.*")
PURCHASE_FAILED = re.compile(r"Buying Hummingbird reservation for \S+ failed.*")
OVERRIDE_PURCHASE = re.compile(
    r"Hummingbird: buying the reservation for \S+ from the marketplace at (\S+), set by "
    r"HUMMINGBIRD_MARKETPLACE_ADDRESS"
)

STATES = ("passed", "failed", "stopped", "timeout")


@dataclass
class WorkloadOutcome:
    id: str
    kind: str
    role: str  # "primary" or "background"
    tunnel: str
    from_: str
    to: str
    state: str
    iterations: int = 0
    restarts: int = 0
    bytes: int = 0
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    duration_s: float = 0.0
    mean_goodput_bps: float = 0.0
    details: dict = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class SenderStats:
    endpoint: str
    reservations_bought: int = 0
    reservations_failed: int = 0
    handovers: int = 0
    marketplace_addresses: list = field(default_factory=list)


@dataclass
class RunResult:
    run_id: str
    config_path: str
    config_sha256: str
    deployment_kind: str
    name: str
    started_at: str
    ended_at: str
    interrupted: bool = False
    workloads: list = field(default_factory=list)
    senders: list = field(default_factory=list)
    prometheus: dict = field(default_factory=dict)
    grafana_url: Optional[str] = None

    @property
    def passed(self) -> bool:
        if self.interrupted:
            return False
        primary = [w for w in self.workloads if w.role == "primary"]
        return bool(primary) and all(w.state == "passed" for w in primary)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["passed"] = self.passed
        for w in data["workloads"]:
            w["from"] = w.pop("from_")
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "RunResult":
        workloads = []
        for w in data.get("workloads", []):
            w = dict(w)
            w["from_"] = w.pop("from")
            workloads.append(WorkloadOutcome(**w))
        senders = [SenderStats(**s) for s in data.get("senders", [])]
        keys = ("run_id", "config_path", "config_sha256", "deployment_kind", "name",
                "started_at", "ended_at", "interrupted", "prometheus", "grafana_url")
        return cls(workloads=workloads, senders=senders, **{k: data[k] for k in keys if k in data})


def parse_sender_log(text: str, endpoint: str = "") -> SenderStats:
    """Final statistics of one sender from its wireguard-go log text.

    reservations_bought counts the reservations the path manager started sending on
    ("in use" lines), handovers the switches between them, reservations_failed every
    "Buying Hummingbird reservation ... failed" line (retries and final failures).
    """
    in_use = len(RESERVATION_IN_USE.findall(text))
    addresses = sorted(set(OVERRIDE_PURCHASE.findall(text)))
    return SenderStats(
        endpoint=endpoint,
        reservations_bought=in_use,
        reservations_failed=len(PURCHASE_FAILED.findall(text)),
        handovers=max(in_use - 1, 0),
        marketplace_addresses=addresses,
    )


# name -> PromQL template; {w} is the run window in seconds. Evaluated at the end of the run.
PROMETHEUS_QUERIES = {
    "demoted_freshness": "sum(increase(router_humm_demoted_freshness_total[{w}s])) or on() vector(0)",
    "demoted_expired": "sum(increase(router_humm_demoted_expired_total[{w}s])) or on() vector(0)",
    "demoted_tokenbucket": "sum(increase(router_humm_demoted_tokenbucket_total[{w}s])) or on() vector(0)",
    "priority_drops": 'sum(increase(router_dropped_priority_pkts_total{{reason="busy_forwarder"}}[{w}s])) or on() vector(0)',
    "receive_overflows": "sum(increase(router_underlay_receive_overflow_pkts_total[{w}s])) or on() vector(0)",
}


def _instant_query(base_url: str, query: str, at: float, timeout: float) -> Any:
    url = base_url.rstrip("/") + "/api/v1/query?" + urllib.parse.urlencode({"query": query, "time": f"{at:.3f}"})
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        body = json.load(resp)
    if body.get("status") != "success":
        raise ValueError(body.get("error", "query failed"))
    result = body["data"]["result"]
    if not result:
        return None
    return float(result[0]["value"][1])


def query_prometheus(base_url: str, start: float, end: float, timeout: float = 3.0) -> dict:
    """Instant queries at `end` over [start, end] (epoch seconds). Never raises:
    a failing query maps to an error string."""
    window = max(int(round(end - start)), 1)
    out: dict = {"window_s": window}
    for name, template in PROMETHEUS_QUERIES.items():
        try:
            out[name] = _instant_query(base_url, template.format(w=window), end, timeout)
        except Exception as exc:  # noqa: BLE001 - recorded, never raised
            out[name] = f"error: {exc}"
    return out


def grafana_url(grafana_port: int, start: float, end: float, uid: str = "wgexp-overview",
                tunnel: Optional[str] = None) -> str:
    """Dashboard URL for the window; start/end are epoch seconds."""
    url = (f"http://127.0.0.1:{grafana_port}/d/{uid}/?orgId=1"
           f"&from={int(start * 1000)}&to={int(end * 1000)}&refresh=")
    if tunnel:
        url += "&var-tunnel=" + urllib.parse.quote(tunnel)
    return url


def write_results(path: Path, result: RunResult) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n")
    os.replace(tmp, path)


def read_results(path: Path) -> RunResult:
    return RunResult.from_dict(json.loads(Path(path).read_text()))


def exit_code(result: RunResult) -> int:
    return 0 if result.passed else 1


def _fmt_bps(bps: float) -> str:
    for unit, div in (("Gbps", 1e9), ("Mbps", 1e6), ("kbps", 1e3)):
        if bps >= div:
            return f"{bps / div:.2f} {unit}"
    return f"{bps:.0f} bps"


def render_summary(result: RunResult) -> str:
    rows = [("id", "kind", "role", "from->to", "state", "iter", "restarts", "bytes", "duration", "goodput")]
    for w in result.workloads:
        rows.append((w.id, w.kind, w.role, f"{w.from_}->{w.to}", w.state, str(w.iterations),
                     str(w.restarts), str(w.bytes), f"{w.duration_s:.1f}s", _fmt_bps(w.mean_goodput_bps)))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    lines = [f"Run {result.run_id} ({result.name}, {result.deployment_kind})",
             f"  {result.started_at} -> {result.ended_at}" + ("  [INTERRUPTED]" if result.interrupted else ""), ""]
    for r in rows:
        lines.append("  " + "  ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip())
    for w in result.workloads:
        if w.error:
            lines.append(f"  {w.id}: {w.error}")
    if result.senders:
        lines += ["", "Hummingbird senders:"]
        for s in result.senders:
            mp = ", ".join(s.marketplace_addresses) or "-"
            lines.append(f"  {s.endpoint}: bought {s.reservations_bought}, failed {s.reservations_failed}, "
                         f"handovers {s.handovers}, marketplace {mp}")
    if result.prometheus:
        lines += ["", "Router counters over the run window:"]
        for k, v in result.prometheus.items():
            if k == "window_s":
                continue
            lines.append(f"  {k}: {v if isinstance(v, str) or v is None else f'{v:.0f}'}")
    lines.append("")
    if result.grafana_url:
        lines.append(f"Grafana: {result.grafana_url}")
    lines.append("PASS" if result.passed else "FAIL")
    return "\n".join(lines)
