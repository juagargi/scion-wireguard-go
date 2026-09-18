#!/usr/bin/env python3
"""Integration test: a WireGuard tunnel over SCION/Hummingbird on a Docker tiny topology.

The test assumes a SCION *tiny* topology that is already generated and running as
Docker containers, the way the Hummingbird end2end test expects it:

    cd <scion-dir>
    ./scion.sh topology -d -c topology/tiny.topo -m 1-ff00:0:111
    ./scion.sh start

It then

  1. builds ``wireguard-go`` with ``make``,
  2. copies the binary into the tester containers of the source and the destination AS,
  3. creates a file of pseudo-random data in the source container,
  4. starts one ``wireguard-go`` instance in each container and wires them together
     over SCION (buying Hummingbird reservations on the sending side),
  5. pushes the file through the tunnel with ``rsync``,
  6. waits for the transfer to finish and compares the md5 sums of both ends.

Everything the test creates (the tunnel devices, the daemons and the payload files)
is removed again on the way out, including after a failure or a Ctrl-C.

The payload exists twice, once on each side, so the filesystem behind Docker needs a
multiple of --size free.
Watch out for the border routers: they log at debug level, and
unless gen/scion-dc.yml bounds their Docker log a 10 GiB transfer leaves about 8 GiB of
logs behind per router, which fills a disk quickly.
The run refuses to start when the space does not add up; see check_disk_space.

Usage:
    ./tests/scion-integration.py --scion-dir ~/devel/ETH/scion.workinprogress
    ./tests/scion-integration.py --size 1G --no-hummingbird      # quick smoke run
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

REPO = Path(__file__).resolve().parent.parent

# The tester containers of the tiny topology. 1-ff00:0:111 and 1-ff00:0:112 are the
# two leaf ASes, so their path crosses the core AS 1-ff00:0:110 and has flyovers to
# buy on three ASes. This is the same pair the Hummingbird end2end test uses.
DEFAULT_SOURCE_IA = "1-ff00:0:111"
DEFAULT_DEST_IA = "1-ff00:0:112"

# Addresses inside the tunnel. They are private to the test and never leave it.
SOURCE_TUNNEL_IP = "10.78.0.1"
DEST_TUNNEL_IP = "10.78.0.2"
TUNNEL_PREFIX_LEN = 24

INTERFACE = "wg0"
UAPI_SOCKET = f"/var/run/wireguard/{INTERFACE}.sock"

# WireGuard has to listen inside SCION's dispatch range (31000-32767), otherwise the
# border router will not deliver the packets to the end host.
WIREGUARD_PORT = 32000

# The rsync daemon on the receiving side. It is bound to the tunnel address only, so
# a transfer can only ever arrive through WireGuard.
RSYNC_PORT = 8730

# Where the payload lives inside the containers.
SOURCE_DIR = "/tmp/wg-scion-src"
DEST_DIR = "/tmp/wg-scion-dst"
PAYLOAD = "payload.bin"

# The 1-ff00:0:110 <-> 1-ff00:0:111 link of tiny.topo has an MTU of 1280, which the
# SCION header, the UDP header and WireGuard's own 32 bytes of framing all have to fit
# into. 1000 leaves room for the longest Hummingbird header the topology can produce;
# raise it with --mtu once a path is known to be shorter.
DEFAULT_MTU = 1000

# Hummingbird defaults. The assets of the generated topology sell from 10 kbps up to
# 950 Mbps per interface pair; asking for more than one asset holds fails the purchase
# with "no assets found". The short reservation lifetime is deliberate: a transfer of any
# size then spans many renewals.
DEFAULT_BANDWIDTH = "80mbps"
DEFAULT_REVERSE_BANDWIDTH = "10mbps"  # only rsync's acknowledgements travel back
DEFAULT_DURATION = "60s"

# A run needs room for both copies of the payload and a margin for everything else it
# touches. Starting a run that cannot fit wastes twenty minutes and then dies half way
# through the verification, so the space is checked up front.
DISK_SPACE_FACTOR = 2.5

# What the border routers add on top when nothing bounds their Docker log. They log at
# debug level, and a 10 GiB transfer was measured to leave about 8 GiB behind per router,
# which is what fills the disk rather than the payload itself. Give the routers a
# `logging: {driver: json-file, options: {max-size: ...}}` in gen/scion-dc.yml and this
# stops applying.
UNCAPPED_ROUTER_LOG_FACTOR = 3.0

DEFAULT_MARKETPLACE_USER = "alice"
DEFAULT_MARKETPLACE_PASSWORD = "1234"


class TestFailure(RuntimeError):
    """A condition that makes the integration test fail or impossible to run."""


# --------------------------------------------------------------------------------------
# Curve25519, so that the test does not depend on `wg` being installed anywhere
# --------------------------------------------------------------------------------------

_P = 2**255 - 19
_A24 = 121665


def _x25519(scalar: int, u: int) -> int:
    """Montgomery ladder of RFC 7748, section 5."""
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


def generate_keypair() -> tuple[str, str]:
    """Return a fresh (private, public) WireGuard key pair, both hex encoded."""
    private = bytearray(os.urandom(32))
    private[0] &= 248
    private[31] &= 127
    private[31] |= 64
    public = _x25519(int.from_bytes(private, "little"), 9)
    return bytes(private).hex(), public.to_bytes(32, "little").hex()


# --------------------------------------------------------------------------------------
# Running commands, locally and in the containers
# --------------------------------------------------------------------------------------


def run(command: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
    """Print and run a command so that a failing step can be reproduced by hand."""
    print("+", shlex.join(command), flush=True)
    return subprocess.run(list(command), text=True, **kwargs)


@dataclass
class Endpoint:
    """One side of the tunnel: a tester container and the SCION address it listens on."""

    ia: str
    tunnel_ip: str
    service: str
    scion_ip: str = ""  # filled in by discover_scion_address
    daemon: str = ""

    @property
    def scion_address(self) -> str:
        """The `ISD-AS,IP` address the SCION bind has to be told to use."""
        return f"{self.ia},{self.scion_ip}"

    @property
    def scion_endpoint(self) -> str:
        """The `ISD-AS,[IP]:port` endpoint a peer has to send to."""
        return f"{self.ia},[{self.scion_ip}]:{WIREGUARD_PORT}"


def tester_service(ia: str) -> str:
    """Name of the Compose service running the tester of an AS."""
    return "tester_" + ia.replace(":", "_")


class Topology:
    """The generated Docker topology the test runs on top of."""

    def __init__(self, scion_dir: Path) -> None:
        self.root = scion_dir
        self.compose = scion_dir / "gen" / "scion-dc.yml"
        if not self.compose.is_file():
            raise TestFailure(
                f"{self.compose} is missing; generate the topology first with\n"
                f"    cd {scion_dir} && ./scion.sh topology -d -c topology/tiny.topo "
                f"-m 1-ff00:0:111 && ./scion.sh start"
            )

    def compose_args(self, *args: str) -> list[str]:
        return ["docker", "compose", "-f", str(self.compose), *args]

    def container_id(self, service: str) -> str:
        """The id of the running container of a service, or fail if it is not up."""
        result = run(self.compose_args("ps", "-q", service), capture_output=True)
        container = result.stdout.strip()
        if result.returncode != 0 or not container:
            raise TestFailure(
                f"the container of {service} is not running; "
                f"start the topology with `cd {self.root} && ./scion.sh start`"
            )
        return container.splitlines()[0]

    def exec(
        self,
        service: str,
        command: Sequence[str],
        env: dict[str, str] | None = None,
        **kwargs,
    ) -> subprocess.CompletedProcess:
        """Run a command in a container and wait for it."""
        env_args: list[str] = []
        for key, value in (env or {}).items():
            env_args += ["-e", f"{key}={value}"]
        return run(self.compose_args("exec", "-T", *env_args, service, *command), **kwargs)

    def exec_background(
        self,
        service: str,
        command: Sequence[str],
        env: dict[str, str] | None = None,
        log: Path | None = None,
    ) -> subprocess.Popen:
        """Start a command in a container without waiting for it to finish."""
        env_args: list[str] = []
        for key, value in (env or {}).items():
            env_args += ["-e", f"{key}={value}"]
        args = self.compose_args("exec", "-T", *env_args, service, *command)
        print("+", shlex.join(args), "&", flush=True)
        stream = log.open("wb") if log is not None else subprocess.DEVNULL
        return subprocess.Popen(args, stdout=stream, stderr=subprocess.STDOUT)

    def output(self, service: str, command: Sequence[str]) -> str:
        """Run a command in a container and return its standard output."""
        result = self.exec(service, command, capture_output=True)
        if result.returncode != 0:
            raise TestFailure(
                f"`{shlex.join(command)}` failed in {service}: "
                f"{(result.stderr or result.stdout).strip()}"
            )
        return result.stdout.strip()

    def shell(self, service: str, script: str, **kwargs) -> subprocess.CompletedProcess:
        """Run a shell snippet in a container."""
        return self.exec(service, ["bash", "-c", script], **kwargs)


# --------------------------------------------------------------------------------------
# Preparing the endpoints
# --------------------------------------------------------------------------------------


def discover_scion_address(topology: Topology, endpoint: Endpoint) -> None:
    """Ask the tester for the SCION address and daemon of its AS."""
    # `scion address` reports the local address the daemon of this AS hands out, which
    # is exactly the address the SCION bind would pick for itself.
    address = topology.output(endpoint.service, ["scion", "address"])
    ia, _, ip = address.partition(",")
    if not ip or ia != endpoint.ia:
        raise TestFailure(
            f"{endpoint.service} reports the SCION address {address!r}, "
            f"which is not an address of {endpoint.ia}"
        )
    endpoint.scion_ip = ip
    endpoint.daemon = topology.output(endpoint.service, ["printenv", "SCION_DAEMON"])
    print(f"    {endpoint.ia}: {endpoint.scion_endpoint} via sciond {endpoint.daemon}")


def check_prerequisites(topology: Topology, endpoints: Sequence[Endpoint]) -> None:
    """Fail early and with a clear message if a container cannot run the test."""
    for endpoint in endpoints:
        topology.container_id(endpoint.service)
        missing = topology.output(
            endpoint.service,
            [
                "bash",
                "-c",
                "for t in ip rsync md5sum dd; do command -v $t >/dev/null || echo $t; done",
            ],
        )
        if missing:
            raise TestFailure(
                f"{endpoint.service} is missing the tools: {', '.join(missing.split())}"
            )
        if uapi_client(topology, endpoint) is None:
            raise TestFailure(
                f"{endpoint.service} has none of `socat`, an OpenBSD `nc` or a perl with "
                f"IO::Socket::UNIX, so the WireGuard UAPI socket cannot be configured"
            )
        result = topology.shell(endpoint.service, "test -c /dev/net/tun", check=False)
        if result.returncode != 0:
            raise TestFailure(
                f"{endpoint.service} has no /dev/net/tun; the tester service has to run "
                f"privileged for WireGuard to create a TUN device"
            )


# The UAPI is a plain-text protocol over a unix socket, and `wg` can speak neither it
# nor the scion_* keys this fork adds. The SCION tester image carries no socat and no
# OpenBSD nc either, but it does ship perl, whose IO::Socket::UNIX is a core module.
# Richer images are still used with their own tools when they have them.
UAPI_HELPER = "/tmp/wg-scion-uapi.pl"

PERL_UAPI_CLIENT = r"""use strict;
use warnings;
use IO::Socket::UNIX;

# Forward everything on stdin to the UAPI socket named by the first argument, then
# half-close so the device knows the request is over, and copy the reply to stdout.
my $socket = IO::Socket::UNIX->new(Peer => $ARGV[0], Type => SOCK_STREAM)
    or die "connecting to $ARGV[0]: $!\n";
local $/;
print $socket scalar <STDIN>;
$socket->shutdown(1);
print while <$socket>;
"""

_UAPI_CLIENTS: dict[str, list[str]] = {}


def uapi_client(topology: Topology, endpoint: Endpoint) -> list[str] | None:
    """The command a container uses to talk to a unix socket, probed once per service."""
    if endpoint.service not in _UAPI_CLIENTS:
        probe = topology.shell(
            endpoint.service,
            "if command -v socat >/dev/null; then echo socat;"
            " elif command -v nc >/dev/null && nc -h 2>&1 | grep -q -- -U; then echo nc;"
            " elif perl -MIO::Socket::UNIX -e 1 >/dev/null 2>&1; then echo perl; fi",
            capture_output=True,
            check=False,
        )
        tool = probe.stdout.strip()
        if tool == "perl":
            # The helper has to exist before the first request; installing it here keeps
            # the probe and its consequence in one place.
            topology.exec(
                endpoint.service,
                ["bash", "-c", f"cat > {UAPI_HELPER}"],
                input=PERL_UAPI_CLIENT,
                check=True,
            )
        _UAPI_CLIENTS[endpoint.service] = {
            "socat": ["socat", "-", f"UNIX-CONNECT:{UAPI_SOCKET}"],
            "nc": ["nc", "-U", UAPI_SOCKET],
            "perl": ["perl", UAPI_HELPER, UAPI_SOCKET],
        }.get(tool, [])
    return _UAPI_CLIENTS[endpoint.service] or None


def uapi(topology: Topology, endpoint: Endpoint, request: str) -> str:
    """Send one UAPI transaction to the WireGuard instance of an endpoint."""
    client = uapi_client(topology, endpoint)
    if client is None:
        raise TestFailure(f"{endpoint.service} cannot reach {UAPI_SOCKET}")
    result = topology.exec(
        endpoint.service, client, input=request, capture_output=True, check=False
    )
    if result.returncode != 0:
        raise TestFailure(
            f"UAPI request to {endpoint.service} failed: "
            f"{(result.stderr or result.stdout).strip()}"
        )
    errno = re.search(r"^errno=(-?\d+)", result.stdout, re.MULTILINE)
    if errno is None:
        raise TestFailure(
            f"UAPI request to {endpoint.service} got no errno back:\n{result.stdout}"
        )
    if errno.group(1) != "0":
        raise TestFailure(
            f"UAPI request to {endpoint.service} was rejected with errno={errno.group(1)}:\n"
            f"{request}"
        )
    return result.stdout


def kill_wireguard(topology: Topology, endpoint: Endpoint) -> None:
    """Stop any WireGuard instance left behind in a container and drop its device."""
    # -x matches the process name rather than the command line. `pkill -f wireguard-go`
    # would also match this very shell, whose own command line contains that string, and
    # kill it before any of the commands after it could run.
    topology.shell(
        endpoint.service,
        f"pkill -x wireguard-go >/dev/null 2>&1;"
        f" ip link del dev {INTERFACE} >/dev/null 2>&1;"
        f" rm -f {UAPI_SOCKET} {UAPI_HELPER}; true",
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # The UAPI helper goes with the socket it talks to. Forgetting the probed client keeps
    # the cache honest: the next request reinstalls the helper instead of calling a file
    # that is no longer there.
    _UAPI_CLIENTS.pop(endpoint.service, None)


def wireguard_log(log_dir: Path, endpoint: Endpoint) -> Path:
    """Where the output of the WireGuard instance of an endpoint is collected."""
    return log_dir / f"wireguard-{endpoint.ia.replace(':', '_')}.log"


def start_wireguard(
    topology: Topology,
    endpoint: Endpoint,
    env: dict[str, str],
    mtu: int,
    log_dir: Path,
) -> subprocess.Popen:
    """Start one WireGuard instance and bring up its tunnel device."""
    log = wireguard_log(log_dir, endpoint)
    process = topology.exec_background(
        endpoint.service,
        ["/share/bin/wireguard-go", "-f", INTERFACE],
        env=env,
        log=log,
    )
    print(f"    logging {endpoint.ia} to {log}")

    # The UAPI socket appears once the device is up, so it doubles as the readiness signal.
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise TestFailure(
                f"wireguard-go exited on {endpoint.service} before it was ready; see {log}"
            )
        probe = topology.shell(
            endpoint.service,
            f"test -S {UAPI_SOCKET}",
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if probe.returncode == 0:
            break
        time.sleep(0.5)
    else:
        raise TestFailure(f"wireguard-go on {endpoint.service} did not open {UAPI_SOCKET}")

    topology.shell(
        endpoint.service,
        f"set -e;"
        f" ip address add {endpoint.tunnel_ip}/{TUNNEL_PREFIX_LEN} dev {INTERFACE};"
        f" ip link set mtu {mtu} dev {INTERFACE};"
        f" ip link set up dev {INTERFACE}",
        check=True,
    )
    return process


def configure_peer(
    topology: Topology,
    endpoint: Endpoint,
    private_key: str,
    peer_public_key: str,
    peer: Endpoint,
) -> None:
    """Write the private key, the listen port and the single peer into one transaction."""
    uapi(
        topology,
        endpoint,
        "\n".join(
            [
                "set=1",
                f"private_key={private_key}",
                f"listen_port={WIREGUARD_PORT}",
                f"public_key={peer_public_key}",
                f"allowed_ip={peer.tunnel_ip}/32",
                f"scion_endpoint={peer.scion_endpoint}",
                "persistent_keepalive_interval=25",
                "",
            ]
        ),
    )


def wait_for_tunnel(topology: Topology, source: Endpoint, dest: Endpoint, timeout: float) -> None:
    """Block until a packet makes it through the tunnel, or give up."""
    deadline = time.monotonic() + timeout
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        result = topology.exec(
            source.service,
            ["ping", "-c", "1", "-W", "2", dest.tunnel_ip],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            print(f"    tunnel up after {attempt} attempt(s)")
            return
        time.sleep(2)
    handshake = uapi(topology, source, "get=1\n")
    raise TestFailure(
        f"no traffic passed between {source.tunnel_ip} and {dest.tunnel_ip} within "
        f"{timeout:.0f}s; the WireGuard state of the source was:\n{handshake}"
    )


# --------------------------------------------------------------------------------------
# Hummingbird
# --------------------------------------------------------------------------------------


# The path manager announces the reservation it starts sending on with this line. Without
# it the tunnel quietly falls back to a best-effort SCION path, and a test that only
# compares md5 sums would pass without Hummingbird ever having been involved.
RESERVATION_IN_USE = re.compile(r"Hummingbird reservation for .* in use.*")


def wait_for_reservation(log: Path, timeout: float, buyer: str) -> None:
    """Fail unless the sender bought a reservation and started sending traffic on it."""
    deadline = time.monotonic() + timeout
    while True:
        text = log.read_text(errors="replace")
        found = RESERVATION_IN_USE.search(text)
        if found:
            print(f"    {found.group(0).strip()}")
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(1)
    reported = [
        line for line in text.splitlines() if "ummingbird" in line or "eservation" in line
    ]
    raise TestFailure(
        f"the sender never started using a Hummingbird reservation within {timeout:.0f}s, so "
        f"the transfer would have run on a best-effort path.\n"
        f"'no assets found' means no asset covers --bandwidth on some hop: an AS of the "
        f"generated topology sells at most 950 Mbps per interface pair, so ask for less.\n"
        f"'wrong number of reservations {{actual=0}}' usually means {buyer} cannot pay for "
        f"them any more. Reservations are not free and every run spends some, so an account "
        f"drains over time; try another --marketplace-user, or regenerate the topology to "
        f"reset the balances.\nThe marketplace exchange said:\n  "
        + "\n  ".join(reported[-10:] or ["(nothing about Hummingbird at all)"])
    )


def marketplace_website(topology: Topology) -> str:
    """The registration web app of the marketplace the generated topology advertises."""
    websites: set[str] = set()
    for path in sorted((topology.root / "gen").glob("AS*/staticInfoConfig.json")):
        try:
            note = json.loads(json.loads(path.read_text()).get("note", "{}"))
        except (OSError, json.JSONDecodeError, TypeError) as err:
            raise TestFailure(f"reading the marketplace advertisement {path}: {err}") from err
        for entry in note.get("hummingbird", []):
            # The web app is only reachable over TCP; the QUIC/SCION entry is the API.
            if "TLS/TCP" not in str(entry.get("api_protocol", "")):
                continue
            website = entry.get("client_registration_website") or entry.get("website")
            if website:
                websites.add(website)
    if not websites:
        raise TestFailure(
            "no marketplace is advertised in gen/AS*/staticInfoConfig.json; regenerate "
            "the topology with `./scion.sh topology -d -c topology/tiny.topo -m 1-ff00:0:111`"
        )
    if len(websites) > 1:
        raise TestFailure("several marketplaces are advertised: " + ", ".join(sorted(websites)))
    return next(iter(websites))


def marketplace_jwt(topology: Topology, user: str, password: str) -> str:
    """Log in at the marketplace of the topology and return a token for the buyer."""
    website = marketplace_website(topology)
    print(f"    requesting a JWT for {user} at {website}")
    script = topology.root / "marketplace" / "tools" / "get-jwt.sh"
    if not script.is_file():
        raise TestFailure(f"{script} is missing; is --scion-dir a Hummingbird checkout?")
    result = run(
        [str(script), user, password, website],
        cwd=topology.root,
        capture_output=True,
        check=False,
    )
    token = result.stdout.strip()
    if result.returncode != 0 or not token:
        raise TestFailure(f"the marketplace login failed: {result.stderr.strip()}")
    return token


# --------------------------------------------------------------------------------------
# The payload and its transfer
# --------------------------------------------------------------------------------------


def docker_root() -> Path:
    """The directory Docker stores container filesystems in, where the payload lands."""
    result = run(
        ["docker", "info", "--format", "{{.DockerRootDir}}"], capture_output=True, check=False
    )
    root = Path(result.stdout.strip() or "/")
    # /var/lib/docker is usually unreadable for the calling user; statvfs then fails and
    # the filesystem containing it is the best available answer.
    while not os.access(root, os.X_OK) and root != root.parent:
        root = root.parent
    return root


def routers_bound_their_logs(topology: Topology) -> bool:
    """Whether every border router limits how large its Docker log may grow."""
    listing = run(
        topology.compose_args("ps", "--format", "{{.Service}}"), capture_output=True, check=False
    )
    routers = [service for service in listing.stdout.split() if service.startswith("br")]
    if not routers:
        return False
    containers = run(
        topology.compose_args("ps", "-q", *routers), capture_output=True, check=False
    ).stdout.split()
    if len(containers) != len(routers):
        return False
    caps = run(
        [
            "docker",
            "inspect",
            "--format",
            '{{index .HostConfig.LogConfig.Config "max-size"}}',
            *containers,
        ],
        capture_output=True,
        check=False,
    )
    # A router without a max-size prints an empty line, so every line has to carry a value.
    values = [line.strip() for line in caps.stdout.splitlines()]
    return len(values) == len(containers) and all(
        value and value != "<no value>" for value in values
    )


def check_disk_space(topology: Topology, mebibytes: int) -> None:
    """Refuse to start a run the filesystem behind Docker cannot hold."""
    root = docker_root()
    factor = DISK_SPACE_FACTOR
    note = ""
    if not routers_bound_their_logs(topology):
        factor += UNCAPPED_ROUTER_LOG_FACTOR
        note = (
            "\nMost of that is border-router logs rather than the payload: this topology "
            "logs at debug level into an unbounded Docker json-file. Capping them with\n"
            "    logging: {driver: json-file, options: {max-size: 100m, max-file: '3'}}\n"
            "on the br* services of gen/scion-dc.yml brings the requirement down to "
            f"{mebibytes * DISK_SPACE_FACTOR / 1024:.1f} GiB.\n"
            "Logs already written can be reclaimed with:\n"
            "    sudo sh -c 'truncate -s 0 /var/lib/docker/containers/*/*-json.log'"
        )
    needed = int(mebibytes * factor) * 1024 * 1024
    free = shutil.disk_usage(root).free
    if free >= needed:
        return
    raise TestFailure(
        f"{root} has {free / 1e9:.1f} GB free but a {mebibytes} MiB payload needs about "
        f"{needed / 1e9:.1f} GB, one copy on each side. Free some space, run a smaller "
        f"--size, or pass --skip-space-check if you know better.{note}"
    )


def parse_size(value: str) -> int:
    """Turn a size such as `10G`, `512M` or `1024` into a whole number of mebibytes."""
    match = re.fullmatch(r"(\d+)\s*([kKmMgGtT]?)i?[bB]?", value.strip())
    if not match:
        raise argparse.ArgumentTypeError(f"{value!r} is not a size such as 10G or 512M")
    amount, unit = int(match.group(1)), match.group(2).lower()
    mebibytes = {"": amount // (1024 * 1024), "k": amount // 1024, "m": amount,
                 "g": amount * 1024, "t": amount * 1024 * 1024}[unit]
    if mebibytes < 1:
        raise argparse.ArgumentTypeError(f"{value!r} is smaller than one mebibyte")
    return mebibytes


def parse_bandwidth(value: str) -> float:
    """Turn a Hummingbird bandwidth such as `100kbps` or `1.5mbps` into bits per second."""
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([kmg])bps", value.strip(), re.IGNORECASE)
    if not match:
        raise argparse.ArgumentTypeError(
            f"{value!r} is not a bandwidth such as 100kbps, 5mbps or 1gbps"
        )
    return float(match.group(1)) * {"k": 1e3, "m": 1e6, "g": 1e9}[match.group(2).lower()]


def resolve_bwlimit(requested: str | None, bandwidth: str, hummingbird: bool) -> str:
    """Decide the rate the sender is shaped to.

    The transfer is always shaped. WireGuard itself cannot be told to send at a given
    rate: wireguard-go has no shaping of any kind, and its only rate limiter guards the
    handshake against floods. Keeping a transfer inside its reservation therefore has to
    happen above WireGuard (rsync's own limit, used here) or below it (a tc qdisc on the
    tunnel device). Left unshaped the traffic would simply outrun the reservation, and
    since the border router demotes the excess to best-effort rather than dropping it,
    the run would still pass while testing the reservation for barely any of its packets.
    """
    if requested is None:
        # Without Hummingbird no reservation exists to follow, so the default reservation
        # bandwidth stands in and the two modes stay comparable.
        return bandwidth if hummingbird else DEFAULT_BANDWIDTH
    if requested == "reservation":
        if not hummingbird:
            raise TestFailure("--bwlimit=reservation needs Hummingbird to be enabled")
        return bandwidth
    return requested


def bwlimit_args(rate: str) -> list[str]:
    """Translate a sending rate into rsync's --bwlimit flag."""
    # rsync reads a bare --bwlimit as KiB/s, so the rate is converted and marked as such.
    return [f"--bwlimit={parse_bandwidth(rate) / 8 / 1024:.3f}K"]


def create_payload(topology: Topology, source: Endpoint, mebibytes: int) -> None:
    """Fill a file in the source container with pseudo-random data."""
    started = time.monotonic()
    result = topology.shell(
        source.service,
        f"set -e; rm -rf {SOURCE_DIR}; mkdir -p {SOURCE_DIR};"
        f" dd if=/dev/urandom of={SOURCE_DIR}/{PAYLOAD} bs=1M count={mebibytes}"
        f" iflag=fullblock status=none",
        check=False,
    )
    if result.returncode != 0:
        raise TestFailure(
            f"could not create a {mebibytes} MiB payload in {source.service}; "
            f"is there enough space on the Docker filesystem?"
        )
    elapsed = time.monotonic() - started
    print(f"    wrote {mebibytes} MiB of pseudo-random data in {elapsed:.0f}s")


def start_rsync_daemon(topology: Topology, dest: Endpoint) -> None:
    """Run an rsync daemon in the destination container, bound to the tunnel address."""
    # A daemon rather than rsync-over-ssh, so that the test needs no key exchange. The
    # daemon only listens on the tunnel address, so nothing can reach it off-tunnel.
    config = "\n".join(
        [
            "uid = root",
            "gid = root",
            "use chroot = no",
            "max connections = 4",
            "pid file = /tmp/wg-scion-rsyncd.pid",
            "lock file = /tmp/wg-scion-rsyncd.lock",
            "log file = /tmp/wg-scion-rsyncd.log",
            f"address = {dest.tunnel_ip}",
            f"port = {RSYNC_PORT}",
            "",
            "[payload]",
            f"path = {DEST_DIR}",
            "read only = false",
            "",
        ]
    )
    topology.shell(
        dest.service,
        f"set -e; rm -rf {DEST_DIR}; mkdir -p {DEST_DIR};"
        f" cat > /tmp/wg-scion-rsyncd.conf <<'CONF_EOF'\n{config}CONF_EOF\n"
        f" rsync --daemon --config=/tmp/wg-scion-rsyncd.conf",
        check=True,
    )

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        probe = topology.shell(
            dest.service,
            f"test -s /tmp/wg-scion-rsyncd.pid",
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if probe.returncode == 0:
            return
        time.sleep(0.5)
    raise TestFailure(f"the rsync daemon did not come up in {dest.service}")


def stop_rsync_daemon(topology: Topology, dest: Endpoint) -> None:
    # The bracket keeps the pattern from matching the command line of this shell: it
    # contains "[r]sync --daemon", which the regex "rsync --daemon" does not match.
    topology.shell(
        dest.service,
        # The daemon writes a last line to its log while shutting down, so the files can
        # only be removed once it is really gone, not merely signalled.
        "pkill -f '[r]sync --daemon' >/dev/null 2>&1;"
        " for _ in $(seq 25); do"
        "   pgrep -f '[r]sync --daemon' >/dev/null 2>&1 || break; sleep 0.2;"
        " done;"
        " rm -f /tmp/wg-scion-rsyncd.pid /tmp/wg-scion-rsyncd.lock"
        " /tmp/wg-scion-rsyncd.conf /tmp/wg-scion-rsyncd.log; true",
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def transfer(
    topology: Topology,
    source: Endpoint,
    dest: Endpoint,
    timeout: float,
    bwlimit: Sequence[str] = (),
) -> float:
    """Push the payload through the tunnel and return how long it took."""
    started = time.monotonic()
    try:
        result = topology.exec(
            source.service,
            [
                "rsync",
                "--archive",
                "--whole-file",  # the destination starts out empty, so skip the delta pass
                "--stats",
                "--human-readable",
                *bwlimit,
                f"--port={RSYNC_PORT}",
                f"{SOURCE_DIR}/{PAYLOAD}",
                f"rsync://{dest.tunnel_ip}/payload/",
            ],
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as err:
        raise TestFailure(f"the transfer did not finish within {timeout:.0f}s") from err
    if result.returncode != 0:
        raise TestFailure(f"rsync failed with exit code {result.returncode}")
    return time.monotonic() - started


def md5(topology: Topology, endpoint: Endpoint, path: str) -> str:
    """The md5 sum of a file in a container."""
    return topology.output(endpoint.service, ["md5sum", path]).split()[0]


def size_of(topology: Topology, endpoint: Endpoint, path: str) -> int:
    """The size in bytes of a file in a container."""
    return int(topology.output(endpoint.service, ["stat", "-c", "%s", path]))


def remove_payload(topology: Topology, endpoint: Endpoint, directory: str) -> None:
    topology.shell(
        endpoint.service,
        f"rm -rf {directory}",
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# --------------------------------------------------------------------------------------
# The test itself
# --------------------------------------------------------------------------------------


def build(repo: Path) -> Path:
    """Build wireguard-go and return the binary."""
    result = run(["make"], cwd=repo, check=False)
    if result.returncode != 0:
        raise TestFailure("`make` failed")
    binary = repo / "wireguard-go"
    if not binary.is_file():
        raise TestFailure(f"`make` did not produce {binary}")
    return binary


def install_binary(topology: Topology, endpoint: Endpoint, binary: Path) -> None:
    """Copy the freshly built binary into the tester container."""
    container = topology.container_id(endpoint.service)
    result = run(
        ["docker", "cp", str(binary), f"{container}:/share/bin/wireguard-go"],
        check=False,
    )
    if result.returncode != 0:
        raise TestFailure(f"could not copy {binary} into {endpoint.service}")
    topology.shell(endpoint.service, "chmod 0755 /share/bin/wireguard-go", check=True)


def wireguard_env(endpoint: Endpoint, hummingbird: dict[str, str] | None) -> dict[str, str]:
    """The environment one WireGuard instance is started with."""
    env = {
        "USE_SCION": "1",
        "USE_BATCH": "1",
        "LOG_LEVEL": "verbose",
        "SCION_DAEMON_ADDRESS": endpoint.daemon,
        # The SCION bind wants `ISD-AS,IP`, not a bare ISD-AS.
        "SCION_LOCAL_IA": endpoint.scion_address,
        "WG_PROCESS_FOREGROUND": "1",
    }
    env.update(hummingbird or {})
    return env


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--scion-dir",
        type=Path,
        default=Path(os.environ.get("SCION_DIR", REPO.parent / "scion")),
        help="checkout of the Hummingbird SCION fork whose gen/ holds the running topology",
    )
    parser.add_argument("--source-ia", default=DEFAULT_SOURCE_IA, help="AS that sends the file")
    parser.add_argument("--dest-ia", default=DEFAULT_DEST_IA, help="AS that receives the file")
    parser.add_argument(
        "--size",
        type=parse_size,
        default=parse_size("100M"),
        metavar="SIZE",
        help="size of the pseudo-random payload, e.g. 10G or 512M (default: 100M)",
    )
    parser.add_argument("--mtu", type=int, default=DEFAULT_MTU, help="MTU of the tunnel device")
    parser.add_argument(
        "--bandwidth", default=DEFAULT_BANDWIDTH, help="Hummingbird bandwidth towards the receiver"
    )
    parser.add_argument(
        "--reverse-bandwidth",
        default=DEFAULT_REVERSE_BANDWIDTH,
        help="Hummingbird bandwidth of the reverse direction ('' for best effort)",
    )
    parser.add_argument(
        "--duration", default=DEFAULT_DURATION, help="lifetime of a single reservation"
    )
    parser.add_argument(
        "--bwlimit",
        default=None,
        metavar="RATE",
        help="rate the sender is shaped to, as a bandwidth like 20mbps. Defaults to "
        "--bandwidth, or to the default reservation bandwidth when --no-hummingbird "
        "leaves no reservation to follow, so a transfer never outruns what it reserved. "
        "WireGuard cannot be rate limited itself, so this is rsync's own limit",
    )
    parser.add_argument(
        "--no-hummingbird",
        action="store_true",
        help="send over best-effort SCION paths and buy no reservations",
    )
    parser.add_argument("--marketplace-user", default=DEFAULT_MARKETPLACE_USER)
    parser.add_argument("--marketplace-password", default=DEFAULT_MARKETPLACE_PASSWORD)
    parser.add_argument(
        "--handshake-timeout",
        type=float,
        default=120,
        help="seconds to wait for the first packet through the tunnel",
    )
    parser.add_argument(
        "--reservation-timeout",
        type=float,
        default=60,
        help="seconds to wait for the first Hummingbird reservation to carry traffic",
    )
    parser.add_argument(
        "--transfer-timeout",
        type=float,
        default=7200,
        help="seconds to wait for the transfer to finish",
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=None,
        help="where to put the WireGuard logs (default: a fresh temporary directory)",
    )
    parser.add_argument(
        "--skip-space-check",
        action="store_true",
        help="start even when the filesystem looks too small for the payload and the logs",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="leave the tunnels, the daemons and the payload files in place afterwards",
    )
    args = parser.parse_args(argv)

    log_dir = args.log_dir or Path(tempfile.mkdtemp(prefix="wg-scion-"))
    log_dir.mkdir(parents=True, exist_ok=True)

    topology = Topology(args.scion_dir.expanduser().resolve())
    source = Endpoint(args.source_ia, SOURCE_TUNNEL_IP, tester_service(args.source_ia))
    dest = Endpoint(args.dest_ia, DEST_TUNNEL_IP, tester_service(args.dest_ia))

    print(f"== topology at {topology.root}, logs in {log_dir}")
    if not args.skip_space_check:
        check_disk_space(topology, args.size)
    check_prerequisites(topology, [source, dest])

    print("== discovering the SCION addresses")
    for endpoint in (source, dest):
        discover_scion_address(topology, endpoint)

    print("== building wireguard-go")
    binary = build(REPO)

    print("== copying the binary into the tester containers")
    for endpoint in (source, dest):
        install_binary(topology, endpoint, binary)

    hummingbird: dict[str, str] | None = None
    if not args.no_hummingbird:
        print("== buying Hummingbird reservations for the sending side")
        hummingbird = {
            "HUMMINGBIRD_BANDWIDTH": args.bandwidth,
            "HUMMINGBIRD_DURATION": args.duration,
            "SCION_MARKETPLACE_JWT": marketplace_jwt(
                topology, args.marketplace_user, args.marketplace_password
            ),
            # The marketplaces of a local topology serve a self-signed certificate.
            "HUMMINGBIRD_MARKETPLACE_INSECURE": "1",
        }
        if args.reverse_bandwidth:
            hummingbird["HUMMINGBIRD_REVERSE_BANDWIDTH"] = args.reverse_bandwidth

    processes: list[subprocess.Popen] = []
    try:
        print(f"== creating a {args.size} MiB payload in {source.service}")
        create_payload(topology, source, args.size)
        source_md5 = md5(topology, source, f"{SOURCE_DIR}/{PAYLOAD}")
        source_size = size_of(topology, source, f"{SOURCE_DIR}/{PAYLOAD}")
        print(f"    {source_size} bytes, md5 {source_md5}")

        print("== starting both WireGuard instances")
        for endpoint in (source, dest):
            kill_wireguard(topology, endpoint)
        source_private, source_public = generate_keypair()
        dest_private, dest_public = generate_keypair()
        processes.append(
            start_wireguard(topology, source, wireguard_env(source, hummingbird), args.mtu, log_dir)
        )
        processes.append(
            start_wireguard(topology, dest, wireguard_env(dest, None), args.mtu, log_dir)
        )
        configure_peer(topology, source, source_private, dest_public, dest)
        configure_peer(topology, dest, dest_private, source_public, source)

        print("== waiting for the tunnel to carry traffic")
        wait_for_tunnel(topology, source, dest, args.handshake_timeout)

        if hummingbird is not None:
            print("== checking that the traffic really rides on a reservation")
            wait_for_reservation(
                wireguard_log(log_dir, source),
                args.reservation_timeout,
                args.marketplace_user,
            )

        print("== transferring the payload through the tunnel")
        rate = resolve_bwlimit(args.bwlimit, args.bandwidth, hummingbird is not None)
        bwlimit = bwlimit_args(rate)
        # The shaping fixes how long the run has to take, so the arithmetic is worth
        # stating up front, along with whether --transfer-timeout can accommodate it.
        expected = source_size * 8 / parse_bandwidth(rate)
        print(f"    shaped to {rate} ({bwlimit[0].split('=')[1]}iB/s), at least {expected:.0f}s")
        if expected > args.transfer_timeout:
            raise TestFailure(
                f"sending {source_size} bytes at {rate} takes at least "
                f"{expected / 3600:.1f} h, which --transfer-timeout of "
                f"{args.transfer_timeout:.0f}s would abort. Raise the timeout, lower "
                f"--size, or shape less with --bwlimit."
            )
        start_rsync_daemon(topology, dest)
        elapsed = transfer(topology, source, dest, args.transfer_timeout, bwlimit)
        throughput = source_size * 8 / elapsed / 1e6
        print(f"    transferred in {elapsed:.0f}s ({throughput:.1f} Mbps)")

        print("== verifying the copy")
        dest_size = size_of(topology, dest, f"{DEST_DIR}/{PAYLOAD}")
        if dest_size != source_size:
            raise TestFailure(
                f"the copy is {dest_size} bytes long, the original is {source_size}"
            )
        dest_md5 = md5(topology, dest, f"{DEST_DIR}/{PAYLOAD}")
        if dest_md5 != source_md5:
            raise TestFailure(f"md5 mismatch: source {source_md5}, destination {dest_md5}")
        print(f"    {dest_size} bytes, md5 {dest_md5} — identical")
    finally:
        if args.keep:
            print(f"== leaving the tunnel and the payload in place (--keep); logs in {log_dir}")
        else:
            print("== cleaning up")
            stop_rsync_daemon(topology, dest)
            # A transfer that ran into --transfer-timeout is still going in the container.
            topology.shell(
                source.service,
                "pkill -f '[r]sync://' >/dev/null 2>&1; true",
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            for endpoint in (source, dest):
                kill_wireguard(topology, endpoint)
            for process in processes:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
            remove_payload(topology, source, SOURCE_DIR)
            remove_payload(topology, dest, DEST_DIR)

    print("\nPASS: the file arrived unchanged through the SCION WireGuard tunnel.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TestFailure as failure:
        print(f"\nFAIL: {failure}", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as failure:
        print(f"\nFAIL: `{shlex.join(failure.cmd)}` exited with {failure.returncode}",
              file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
