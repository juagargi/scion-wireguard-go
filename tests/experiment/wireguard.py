"""One wireguard-go instance of an experiment: keys, environment, start/stop, UAPI, readiness, log checks.

Generalised from the proven code of tests/scion-end2end.py (which stays unchanged): the fixed
wg0 / 32000 / 10.78.0.x became per-endpoint values from config.Endpoint, and every command goes
through the hosts.Host protocol instead of `docker compose exec`.

Layout on the host, for one instance of endpoint E, run <id>, run dir <run_dir>:

    <binary>                                the wireguard-go binary (Docker: /share/bin/wireguard-go,
                                            SSH: <run_dir>/setup/wireguard-go); the integrator installs it
    <run_dir>/runs/<id>/wg-<E>.log          stdout+stderr of wireguard-go (LOG_LEVEL=verbose)
    <run_dir>/runs/<id>/wg-<E>.pid          pid, as recorded by the launcher
    /var/run/wireguard/<interface>.sock     UAPI socket (created by wireguard-go)
    jwt_path                                the marketplace JWT, mode 600 (never in argv, see start())

Where the integrator has to be careful:

* The SCION daemon address is a constructor parameter (`sciond`): `host.sciond_address()` for both
  Docker (SCION_DAEMON of the tester) and SSH (the deployment host's `sciond`).
* The peer's SCION host for `scion_endpoint` comes from `configure(peer_address=...)`; with
  `bring_up_tunnel` it is the peer's `scion_host` (its Endpoint.host, else its host.address()).
* Instances of endpoints that share a container (B and D in the Docker example) are told apart by
  interface name, listen port and API port, all from the config.
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass
from typing import Callable

from config import Endpoint, Experiment, Tunnel
from hosts import Host, HostError


class WireguardError(RuntimeError):
    """A wireguard-go instance misbehaved or a check on it failed."""


# ---------------------------------------------------------------------------------------------
# Curve25519, so that nothing depends on `wg` being installed anywhere (RFC 7748, section 5)
# ---------------------------------------------------------------------------------------------

_P = 2**255 - 19
_A24 = 121665


def _x25519(scalar: int, u: int) -> int:
    """Montgomery ladder of RFC 7748, section 5 (the scalar must already be clamped)."""
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for bit in range(254, -1, -1):
        k_t = (scalar >> bit) & 1
        swap ^= k_t
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = pow(da + cb, 2, _P)
        z3 = x1 * pow(da - cb, 2, _P) % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return x2 * pow(z2, _P - 2, _P) % _P


def public_key(private_hex: str) -> str:
    """The public key (hex) of a private key (hex), clamping the scalar as WireGuard does."""
    private = bytearray(bytes.fromhex(private_hex))
    private[0] &= 248
    private[31] &= 127
    private[31] |= 64
    return _x25519(int.from_bytes(private, "little"), 9).to_bytes(32, "little").hex()


def generate_keypair() -> tuple[str, str]:
    """A fresh (private, public) key pair, both hex encoded: the encoding the UAPI wants."""
    private = bytearray(secrets.token_bytes(32))
    private[0] &= 248
    private[31] &= 127
    private[31] |= 64
    return bytes(private).hex(), public_key(bytes(private).hex())


# ---------------------------------------------------------------------------------------------
# UAPI
# ---------------------------------------------------------------------------------------------

UAPI_DIR = "/var/run/wireguard"

# The tester image carries neither socat nor nc (nor sh), but ships perl, whose IO::Socket::UNIX is
# a core module. The program is passed as `perl -e`, so there is no helper file to leave behind.
PERL_UAPI_CLIENT = r"""use strict;
use warnings;
use IO::Socket::UNIX;
my $socket = IO::Socket::UNIX->new(Peer => $ARGV[0], Type => SOCK_STREAM)
    or die "connecting to $ARGV[0]: $!\n";
local $/;
print $socket scalar <STDIN>;
$socket->shutdown(1);
print while <$socket>;
"""

# $1: socket. Prints the tool to use. Pure bash builtins plus `command -v` (no grep in the testers).
_PROBE_SCRIPT = r"""if command -v perl >/dev/null 2>&1 && perl -MIO::Socket::UNIX -e 1 >/dev/null 2>&1; then echo perl
elif command -v socat >/dev/null 2>&1; then echo socat
elif command -v nc >/dev/null 2>&1 && [[ "$(nc -h 2>&1)" == *-U* ]]; then echo nc
fi
"""

_CLIENTS = {
    "perl": lambda sock: ["perl", "-e", PERL_UAPI_CLIENT, sock],
    "socat": lambda sock: ["socat", "-", f"UNIX-CONNECT:{sock}"],
    "nc": lambda sock: ["nc", "-U", sock],
}


def redact(text: str) -> str:
    """Hide private keys, for error messages and logs."""
    return re.sub(r"(private_key=)\S+", r"\1<redacted>", text)


def peer_transaction(private_key: str, listen_port: int, peer_public_key: str, peer_tunnel_ip: str,
                     peer_isd_as: str, peer_host: str, peer_listen_port: int,
                     keepalive: int) -> str:
    """The UAPI `set` transaction that configures the device and its single peer."""
    return "\n".join([
        "set=1",
        f"private_key={private_key}",
        f"listen_port={listen_port}",
        f"public_key={peer_public_key}",
        f"allowed_ip={peer_tunnel_ip}/32",
        f"scion_endpoint={peer_isd_as},[{peer_host}]:{peer_listen_port}",
        f"persistent_keepalive_interval={keepalive}",
        "", ""])


def path_filter_request(peer_isd_as: str, sequence: str) -> str:
    return f"set=1\nscion_path_filter={peer_isd_as} {sequence}\n\n"


# ---------------------------------------------------------------------------------------------
# Log patterns (what the sender logs; see conn/scion_path_manager.go)
# ---------------------------------------------------------------------------------------------

# The path manager announces the reservation it starts sending on with this line. Without it the
# tunnel quietly falls back to a best-effort SCION path and a test that compares sums would pass
# without Hummingbird ever having been involved.
RESERVATION_IN_USE = re.compile(r"Hummingbird reservation for .* in use.*")
PURCHASE_FAILED = re.compile(r"Buying Hummingbird reservation for \S+ failed.*")
# Only logged with HUMMINGBIRD_MARKETPLACE_ADDRESS.
OVERRIDE_PURCHASE = re.compile(
    r"Hummingbird: buying the reservation for \S+ from the marketplace at (\S+), set by "
    r"HUMMINGBIRD_MARKETPLACE_ADDRESS")
PATH_FILTER = re.compile(r"Path filter for (\S+): (\d+) of (\d+) paths match .*")
CANNOT_LISTEN = re.compile(r"^.*cannot listen on.*$", re.MULTILINE)
# wireguard-go rejects scion_endpoint when its daemon has no path to the peer's AS at that moment.
# On SCIERA the daemon's segment lookups fail now and then, so configure() refreshes and retries.
NO_PATH = "no path found"
NO_PATH_RETRY_SECONDS = 90.0
NO_PATH_RETRY_INTERVAL = 5.0


def filter_matches(log: str, isd_as: str) -> int | None:
    """How many paths to isd_as the latest path filter matched, per the log; None if not logged."""
    found = [int(m.group(2)) for m in PATH_FILTER.finditer(log) if m.group(1) == isd_as]
    return found[-1] if found else None


def ping_is_iputils(host: Host) -> bool:
    """Whether the host's ping is iputils (with -I <address> and -D). GNU inetutils ping is not."""
    return "iputils" in host.run(["ping", "-V"], check=False, timeout=10).stdout


@dataclass(frozen=True)
class ReservationStats:
    """What a sender's log says about its reservations."""
    purchased: int            # reservations that went into use ("in use" lines)
    failed: int               # "Buying Hummingbird reservation ... failed" lines (attempts, not final)
    handovers: int            # purchased - 1: switches to a renewed reservation
    marketplaces: tuple       # distinct marketplace addresses announced (override only)


def parse_reservation_stats(log: str) -> ReservationStats:
    in_use = len(RESERVATION_IN_USE.findall(log))
    return ReservationStats(
        purchased=in_use, failed=len(PURCHASE_FAILED.findall(log)),
        handovers=max(in_use - 1, 0),
        marketplaces=tuple(sorted(set(OVERRIDE_PURCHASE.findall(log)))))


def metrics_status_line(text: str) -> str:
    return text.strip().splitlines()[0] if text.strip() else ""


# ---------------------------------------------------------------------------------------------
# The instance
# ---------------------------------------------------------------------------------------------

_METRICS_SCRIPT = r"""exec 3<>"/dev/tcp/$1/$2" || exit 1
printf 'GET /metrics HTTP/1.0\r\n\r\n' >&3
head -n 1 <&3
"""


class WireguardInstance:
    """One wireguard-go process on one host for one endpoint. Fresh keys per instance."""

    def __init__(self, experiment: Experiment, endpoint: Endpoint, host: Host, binary: str,
                 run_dir: str, run_id: str, jwt_path: str | None, sciond: str):
        self.experiment = experiment
        self.endpoint = endpoint
        self.host = host
        self.binary = binary
        self.run_dir = run_dir.rstrip("/") or "/"
        self.run_id = run_id
        self.jwt_path = jwt_path
        self.sciond = sciond
        self.tunnel: Tunnel = experiment.tunnel_of(endpoint.name)
        self.peer: Endpoint = experiment.peer_of(endpoint.name)
        self.private_key, self.public_key = generate_keypair()
        self.socket_path = f"{UAPI_DIR}/{endpoint.interface}.sock"
        self._local_address: str | None = None
        self._uapi_client: list[str] | None = None
        self._started = False

    # -- paths ---------------------------------------------------------------------------------
    @property
    def run_path(self) -> str:
        return f"{self.run_dir}/runs/{self.run_id}"

    @property
    def log_path(self) -> str:
        return f"{self.run_path}/wg-{self.endpoint.name}.log"

    @property
    def pid_path(self) -> str:
        return f"{self.run_path}/wg-{self.endpoint.name}.pid"

    @property
    def scion_host(self) -> str:
        """The SCION host address of this endpoint: Endpoint.host if configured, else the host's own."""
        if self._local_address is None:
            self._local_address = self.endpoint.host or self.host.address()
        return self._local_address

    # -- environment ---------------------------------------------------------------------------
    def env(self) -> dict[str, str]:
        """The variables of "Starting one instance", in that order; endpoint.env last overrides.

        SCION_MARKETPLACE_JWT is deliberately absent: start() has the host read it from jwt_path.
        """
        ep, tunnel = self.endpoint, self.tunnel
        env = {
            "USE_SCION": "1",
            "USE_BATCH": "1" if tunnel.use_batch else "0",
            "LOG_LEVEL": "verbose",
            "WG_PROCESS_FOREGROUND": "1",
            "SCION_DAEMON_ADDRESS": self.sciond,
            "SCION_LOCAL_IA": f"{ep.isd_as},{self.scion_host}",
            "SCION_PATH_API_ADDRESS": ep.api_address,
        }
        if ep.path_policy:
            env["SCION_PATH_POLICY"] = ep.path_policy
        env.update(self.experiment.hummingbird_env(ep))
        env.update(ep.env)
        return env

    # -- lifecycle -----------------------------------------------------------------------------
    def start(self) -> int:
        """Start wireguard-go detached as root. Returns its pid. The JWT never touches an argv:
        the launcher shell on the host reads it from jwt_path (`env_from_files`)."""
        ep = self.endpoint
        if self.host.run(["ip", "link", "show", "dev", ep.interface], check=False,
                         root=True).returncode == 0:
            raise WireguardError(
                f"{self.host.name}: interface {ep.interface} already exists; it is not ours "
                f"(or a leftover: cleanup_leftovers removes wgx-* devices)")
        if self.host.path_exists(self.socket_path):
            raise WireguardError(f"{self.host.name}: {self.socket_path} already exists")
        files = {}
        if ep.hummingbird is not None:
            if not self.jwt_path:
                raise WireguardError(f"endpoint {ep.name} has a reservation but no JWT file was given")
            files["SCION_MARKETPLACE_JWT"] = self.jwt_path
        pid = self.host.start_daemon(
            [self.binary, "-f", ep.interface], env=self.env(), env_from_files=files,
            log_path=self.log_path, pid_path=self.pid_path, root=True)
        self._started = True
        return pid

    def alive(self) -> bool:
        return self.host.daemon_alive(self.pid_path, root=True)

    def log_text(self) -> str:
        try:
            return self.host.read_text(self.log_path)
        except HostError:
            return ""

    def log_tail(self, lines: int = 15) -> str:
        return "\n".join(self.log_text().splitlines()[-lines:])

    def wait_uapi(self, timeout: float = 60.0) -> None:
        """The UAPI socket appears once the device is up, so it doubles as the readiness signal."""
        deadline = time.monotonic() + timeout
        while True:
            if not self.alive():
                raise WireguardError(f"wireguard-go for {self.endpoint.name} on {self.host.name} "
                                     f"exited before it was ready; log {self.log_path}:\n"
                                     f"{self.log_tail()}")
            if self.host.run(["test", "-S", self.socket_path], check=False, root=True).returncode == 0:
                return
            if time.monotonic() >= deadline:
                raise WireguardError(f"wireguard-go for {self.endpoint.name} on {self.host.name} "
                                     f"did not open {self.socket_path} within {timeout:.0f}s:\n"
                                     f"{self.log_tail()}")
            time.sleep(0.5)

    def uapi(self, request: str) -> str:
        """One UAPI transaction. Raises WireguardError unless the answer has errno=0."""
        if self._uapi_client is None:
            tool = self.host.run(_bash_script(_PROBE_SCRIPT), check=False).stdout.strip()
            if tool not in _CLIENTS:
                raise WireguardError(f"{self.host.name} has no way to reach {self.socket_path} "
                                     f"(needs perl with IO::Socket::UNIX, socat or nc -U)")
            self._uapi_client = _CLIENTS[tool](self.socket_path)
        result = self.host.run(self._uapi_client, input=request, check=False, root=True)
        if result.returncode != 0:
            raise WireguardError(f"UAPI request to {self.endpoint.name} on {self.host.name} failed: "
                                 f"{(result.stderr or result.stdout).strip()}")
        errno = re.search(r"^errno=(-?\d+)", result.stdout, re.MULTILINE)
        if errno is None:
            raise WireguardError(f"UAPI request to {self.endpoint.name} got no errno back:\n"
                                 f"{result.stdout}")
        if errno.group(1) != "0":
            raise WireguardError(f"UAPI request to {self.endpoint.name} was rejected with "
                                 f"errno={errno.group(1)}:\n{redact(request)}\nlog tail:\n"
                                 f"{self.log_tail()}")
        return result.stdout

    def configure(self, peer_public_key: str, peer_address: str | None = None) -> None:
        """private key, listen port and the single peer, in one transaction.

        peer_address is the peer's SCION host (the `[host]` of scion_endpoint); default the peer's
        configured Endpoint.host.
        """
        peer_host = peer_address or self.peer.host
        if not peer_host:
            raise WireguardError(f"the SCION host of peer {self.peer.name} is unknown: pass peer_address")
        request = peer_transaction(
            self.private_key, self.endpoint.listen_port, peer_public_key, self.peer.tunnel_ip,
            self.peer.isd_as, peer_host, self.peer.listen_port, self.tunnel.persistent_keepalive)
        deadline = time.monotonic() + NO_PATH_RETRY_SECONDS
        while True:
            try:
                self.uapi(request)
                return
            except WireguardError as err:
                if NO_PATH not in str(err) or time.monotonic() >= deadline:
                    raise
            # The transaction is idempotent: the same key, port and peer are set again.
            self.refresh_paths()
            time.sleep(NO_PATH_RETRY_INTERVAL)

    def refresh_paths(self) -> None:
        """Make the daemon fetch fresh paths to the peer's AS (best effort: `scion` may be absent)."""
        self.host.run(["scion", "showpaths", self.peer.isd_as, "--sciond", self.sciond, "--refresh"],
                      check=False, timeout=30)

    def set_path_filter(self) -> bool:
        """Restrict the paths to the peer's AS to endpoint.path_filter, and read it back. False if none."""
        sequence = self.endpoint.path_filter
        if sequence is None:
            return False
        self.uapi(path_filter_request(self.peer.isd_as, sequence))
        # wireguard-go does not look for paths again until the filter is re-applied (or its 5-minute
        # refresh) when its daemon had none at this moment: refresh the daemon and re-apply.
        deadline = time.monotonic() + NO_PATH_RETRY_SECONDS
        while filter_matches(self.log_text(), self.peer.isd_as) == 0 and time.monotonic() < deadline:
            self.refresh_paths()
            time.sleep(NO_PATH_RETRY_INTERVAL)
            self.uapi(path_filter_request(self.peer.isd_as, sequence))
        expected = f"scion_path_filter={self.peer.isd_as} {sequence}"
        status = self.uapi("get=1\n\n")
        if expected not in status.splitlines():
            raise WireguardError(f"{self.endpoint.name} does not report the path filter back; "
                                 f"expected {expected!r} in:\n{redact(status)}")
        return True

    def bring_up(self) -> None:
        """Address, MTU, link up."""
        ep, tunnel = self.endpoint, self.tunnel
        self.host.run(["ip", "address", "add", f"{ep.tunnel_ip}/{tunnel.prefix_len}",
                       "dev", ep.interface], root=True)
        self.host.run(["ip", "link", "set", "mtu", str(tunnel.mtu), "dev", ep.interface], root=True)
        self.host.run(["ip", "link", "set", "up", "dev", ep.interface], root=True)

    # -- checks --------------------------------------------------------------------------------
    def metrics_answer(self, address: str | None = None) -> str:
        """The first line the path-manager API answers to GET /metrics ('' if it does not)."""
        host, _, port = (address or self.endpoint.api_address).rpartition(":")
        host = host.strip("[]")
        if host in ("", "0.0.0.0", "::"):
            host = "127.0.0.1"
        result = self.host.run(_bash_script(_METRICS_SCRIPT, host, port), check=False, timeout=15)
        return metrics_status_line(result.stdout)

    def check_api(self) -> str:
        """Fail unless /metrics answers exactly on endpoint.api_address (no fallback ports exist).

        A taken or invalid SCION_PATH_API_ADDRESS makes the SCION bind fail to open without
        necessarily stopping the process: the log line with 'cannot listen on' is reported.
        """
        address = self.endpoint.api_address
        answer = self.metrics_answer()
        if " 200 " not in answer:
            reason = CANNOT_LISTEN.search(self.log_text())
            raise WireguardError(
                f"{self.endpoint.name} on {self.host.name} does not serve /metrics on {address}; "
                f"it answered {answer!r}"
                + (f"; the log says: {reason.group(0).strip()}" if reason else
                   f"; log tail:\n{self.log_tail()}"))
        return answer

    def wait_for_reservation(self, timeout: float = 60.0) -> str | None:
        """Fail unless the sender bought a reservation and started sending on it.
        Returns the log line, or None for an endpoint without a reservation."""
        if self.endpoint.hummingbird is None:
            return None
        deadline = time.monotonic() + timeout
        while True:
            text = self.log_text()
            found = RESERVATION_IN_USE.search(text)
            if found:
                return found.group(0).strip()
            if not self.alive():
                raise WireguardError(f"wireguard-go for {self.endpoint.name} died while waiting "
                                     f"for its reservation:\n{self.log_tail()}")
            if time.monotonic() >= deadline:
                break
            time.sleep(1)
        reported = [ln for ln in text.splitlines() if "ummingbird" in ln or "eservation" in ln]
        raise WireguardError(
            f"{self.endpoint.name} never started using a Hummingbird reservation within "
            f"{timeout:.0f}s, so its traffic would have run on a best-effort path.\n"
            f"'no assets found' means no asset covers the bandwidth on some hop (an AS of the "
            f"generated topology sells at most 950 Mbps per interface pair). "
            f"'wrong number of reservations {{actual=0}}' usually means the marketplace account "
            f"cannot pay any more.\nThe marketplace exchange said:\n  "
            + "\n  ".join(reported[-10:] or ["(nothing about Hummingbird at all)"]))

    def check_marketplace_override(self) -> str | None:
        """With location_override: fail unless the sender bought from the overridden marketplace,
        and only from it. Returns the address, or None when there is no override / no reservation."""
        mp = self.experiment.marketplace
        if mp is None or not mp.location_override or self.endpoint.hummingbird is None:
            return None
        address = mp.scion_address
        purchases = set(OVERRIDE_PURCHASE.findall(self.log_text()))
        if not purchases:
            raise WireguardError(f"{self.endpoint.name} never logged buying from the marketplace "
                                 f"at {address} (HUMMINGBIRD_MARKETPLACE_ADDRESS); see {self.log_path}")
        if purchases != {address}:
            raise WireguardError(f"{self.endpoint.name} bought from {sorted(purchases)}, "
                                 f"expected only {address}")
        return address

    def reservation_log_stats(self) -> ReservationStats:
        return parse_reservation_stats(self.log_text())

    def uapi_state(self) -> str:
        """`get=1`, for diagnostics; never raises."""
        try:
            return redact(self.uapi("get=1\n\n"))
        except (WireguardError, HostError) as e:
            return f"(unavailable: {e})"

    # -- teardown ------------------------------------------------------------------------------
    def stop(self) -> bool:
        """Stop by pidfile only; delete only this instance's interface and socket. True if it ran."""
        ran = self.host.stop_daemon(self.pid_path, root=True)
        if self._started or ran:
            self.host.run(["ip", "link", "del", "dev", self.endpoint.interface], check=False, root=True)
            self.host.run(["rm", "-f", "--", self.socket_path], check=False, root=True)
        self._started = False
        return ran


def _bash_script(script: str, *args: str) -> list[str]:
    return ["bash", "-c", script, "bash", *args]


# ---------------------------------------------------------------------------------------------
# Helpers over several instances
# ---------------------------------------------------------------------------------------------

def wait_for_tunnel(host: Host, src_ip: str, dst_ip: str, timeout: float,
                    diagnostics: Callable[[], str] | None = None) -> int:
    """Block until a ping from src_ip to dst_ip passes through the tunnel. Returns the attempts."""
    deadline = time.monotonic() + timeout
    attempt = 0
    # GNU inetutils ping (e.g. on SCIERA's ufes) has no -I <address>; the route to dst_ip leaves
    # through the tunnel device anyway, with src_ip as its source.
    source = ["-I", src_ip] if ping_is_iputils(host) else []
    while time.monotonic() < deadline:
        attempt += 1
        if host.run(["ping", "-c", "1", "-W", "2", *source, dst_ip], check=False,
                    timeout=10).returncode == 0:
            return attempt
        time.sleep(2)
    raise WireguardError(
        f"no traffic passed from {src_ip} to {dst_ip} on {host.name} within {timeout:.0f}s"
        + (f"; the WireGuard state was:\n{diagnostics()}" if diagnostics else ""))


def bring_up_tunnel(a: WireguardInstance, b: WireguardInstance, timeout: float = 60.0,
                    reservation_timeout: float = 60.0) -> dict[str, str | None]:
    """Both instances already started: wait for UAPI, exchange keys, configure, filter, bring up,
    check the APIs, ping both ways, and wait for the reservations of Hummingbird senders.

    Returns {endpoint name: its 'in use' reservation log line or None}.
    """
    for inst in (a, b):
        inst.wait_uapi(timeout)
    a.configure(b.public_key, b.scion_host)
    b.configure(a.public_key, a.scion_host)
    for inst in (a, b):
        inst.set_path_filter()
        inst.bring_up()
    for inst in (a, b):
        inst.check_api()
    wait_for_tunnel(a.host, a.endpoint.tunnel_ip, b.endpoint.tunnel_ip, timeout, a.uapi_state)
    wait_for_tunnel(b.host, b.endpoint.tunnel_ip, a.endpoint.tunnel_ip, timeout, b.uapi_state)
    lines = {}
    for inst in (a, b):
        lines[inst.endpoint.name] = inst.wait_for_reservation(reservation_timeout)
        inst.check_marketplace_override()
    return lines


def cleanup_leftovers(host: Host, run_dir: str, interfaces: list[str]) -> list[str]:
    """Stop leftovers of earlier runs, and only ours: the daemons recorded in
    <run_dir>/runs/*/wg-*.pid, and the listed interfaces if their names start with `wgx-`.
    Returns what was stopped/removed."""
    done: list[str] = []
    found = host.run(["bash", "-c", 'compgen -G "$1/runs/*/wg-*.pid" || true', "bash", run_dir.rstrip("/")],
                     check=False, root=True).stdout.split()
    for pid_path in found:
        if host.stop_daemon(pid_path, root=True):
            done.append(pid_path)
    for interface in interfaces:
        if not interface.startswith("wgx-"):
            continue
        if host.run(["ip", "link", "del", "dev", interface], check=False, root=True).returncode == 0:
            done.append(interface)
        host.run(["rm", "-f", "--", f"{UAPI_DIR}/{interface}.sock"], check=False, root=True)
    return done
