#!/usr/bin/env python3
"""Integration tests: WireGuard over SCION/Hummingbird on a Docker tiny topology.

Checks that the SCION *tiny* topology is generated and running in --scion-dir, and then
runs tests/scion-end2end.py once per selected test, each with the options of its case.
The topology has to be up already:

    cd <scion-dir>
    ./scion.sh topology -d -c topology/tiny.topo -m 1-ff00:0:111
    ./scion.sh start

Select the tests with one --test-<name> flag each, or all of them with --test-all.
Every selected test runs even when an earlier one failed; the exit status is non-zero
if any of them did.

Usage:
    ./tests/scion-integration.py --scion-dir ~/devel/ETH/scion.workinprogress --test-all
    ./tests/scion-integration.py --test-smoke
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

REPO = Path(__file__).resolve().parent.parent
END2END = Path(__file__).resolve().parent / "scion-end2end.py"

# The ASes of topology/tiny.topo, as they are named in gen/.
TINY_ASES = {"ASff00_0_110", "ASff00_0_111", "ASff00_0_112"}


@dataclass
class Case:
    """One run of scion-end2end.py."""

    help: str
    args: list[str]


TESTS: dict[str, Case] = {
    "smoke": Case(
        help="a small transfer over best-effort SCION paths, without Hummingbird",
        args=["--size", "10M"],
    ),
    "no-peer-path": Case(
        help="a path filter that excludes every path to the peer keeps it from being set up",
        args=["--path-filter", "1-ff00:0:111#7 0*", "--expect", "peer-unreachable"],
    ),
    "no-marketplace-path": Case(
        # The marketplace of the tiny topology runs in 1-ff00:0:111, so only a sender
        # in another AS needs a path to it.
        help="a marketplace filter that excludes every path to the marketplace keeps "
        "the sender from buying reservations",
        args=[
            "--hummingbird",
            "--source-ia", "1-ff00:0:112",
            "--dest-ia", "1-ff00:0:111",
            "--path-to-marketplace-filter", "1-ff00:0:112#7 0*",
            "--expect", "marketplace-unreachable",
        ],
    ),
    "hummingbird": Case(
        # The sender shares its AS with the marketplace, which it reaches without a path.
        help="a small transfer on a Hummingbird reservation bought without any filter",
        args=["--hummingbird", "--size", "10M"],
    ),
    "filters": Case(
        # From 1-ff00:0:112 the marketplace in 1-ff00:0:111 is remote, so both filters
        # apply: each names every hop of the only path through the core AS.
        # Short reservations hand over about every 11 s (the 20 s lifetime minus the
        # 8 s overlap and the 1 s start offset). At the default 80 Mbps 224 MiB take
        # about 23 s, enough for two handovers, each of them a purchase that has to
        # find its path to the marketplace through the filter again. The 12 s ahead
        # covers the 10 s purchase timeout of wireguard-go.
        help="traffic, reservations and their renewals on the paths that "
        "scion_path_filter and HUMMINGBIRD_PATH_TO_MARKETPLACE_FILTER allow",
        args=[
            "--hummingbird",
            "--source-ia", "1-ff00:0:112",
            "--dest-ia", "1-ff00:0:111",
            "--size", "224M",
            "--duration", "20s",
            "--renewal-ahead", "12s",
            "--overlap", "8s",
            "--min-handovers", "2",
            "--path-filter", "1-ff00:0:112#1 1-ff00:0:110#2,1 1-ff00:0:111#41",
            "--path-to-marketplace-filter",
            "1-ff00:0:112#1 1-ff00:0:110#2,1 1-ff00:0:111#41",
        ],
    ),
}


class TestFailure(RuntimeError):
    """A failure with an explanation meant for the person running the tests."""


def run(command: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
    """Print and run a command so that a failing step can be reproduced by hand."""
    print("+", shlex.join(command), flush=True)
    return subprocess.run(list(command), text=True, **kwargs)


def check_topology(scion_dir: Path) -> None:
    """Fail unless the tiny topology is generated in scion_dir and all its services run."""
    start = (
        f"    cd {scion_dir} && ./scion.sh topology -d -c topology/tiny.topo "
        f"-m 1-ff00:0:111 && ./scion.sh start"
    )
    compose = scion_dir / "gen" / "scion-dc.yml"
    if not compose.is_file():
        raise TestFailure(f"{compose} is missing; generate and start the topology with\n{start}")

    ases = {path.name for path in (scion_dir / "gen").glob("AS*") if path.is_dir()}
    if ases != TINY_ASES:
        raise TestFailure(
            f"{scion_dir / 'gen'} holds the ASes {', '.join(sorted(ases)) or 'none'}, "
            f"not those of the tiny topology; regenerate it with\n{start}"
        )

    def services(*args: str) -> set[str]:
        result = run(
            ["docker", "compose", "-f", str(compose), *args, "--services"],
            capture_output=True,
        )
        if result.returncode != 0:
            raise TestFailure(f"asking Docker Compose for the services: {result.stderr.strip()}")
        return set(result.stdout.split())

    stopped = services("config") - services("ps", "--status", "running")
    if stopped:
        raise TestFailure(
            f"the services {', '.join(sorted(stopped))} are not running; start them with\n"
            f"    cd {scion_dir} && ./scion.sh start"
        )


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
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=None,
        help="where to put the logs, one directory per test "
        "(default: a fresh temporary directory)",
    )
    tests = parser.add_argument_group("tests")
    for name, case in TESTS.items():
        tests.add_argument(f"--test-{name}", action="store_true", help=case.help)
    tests.add_argument("--test-all", action="store_true", help="run every test above")
    args = parser.parse_args(argv)

    selected = [
        name for name in TESTS if args.test_all or getattr(args, f"test_{name.replace('-', '_')}")
    ]
    if not selected:
        parser.error("select at least one test: " + ", ".join(
            [f"--test-{name}" for name in TESTS] + ["--test-all"]))

    scion_dir = args.scion_dir.expanduser().resolve()
    log_dir = args.log_dir or Path(tempfile.mkdtemp(prefix="wg-scion-integration-"))
    log_dir.mkdir(parents=True, exist_ok=True)

    print(f"== checking the tiny topology at {scion_dir}")
    check_topology(scion_dir)

    results: dict[str, tuple[bool, float]] = {}
    for name in selected:
        print(f"\n==== test {name}: {TESTS[name].help}", flush=True)
        started = time.monotonic()
        result = run(
            [
                sys.executable,
                str(END2END),
                "--scion-dir",
                str(scion_dir),
                "--log-dir",
                str(log_dir / name),
                *TESTS[name].args,
            ],
            check=False,
        )
        results[name] = (result.returncode == 0, time.monotonic() - started)

    print(f"\n==== summary (logs in {log_dir})")
    for name, (passed, elapsed) in results.items():
        print(f"    {'PASS' if passed else 'FAIL'}  {name}  ({elapsed:.0f}s)")
    failed = [name for name, (passed, _) in results.items() if not passed]
    if failed:
        print(f"\nFAIL: {len(failed)} of {len(results)} tests failed", file=sys.stderr)
        return 1
    print(f"\nPASS: all {len(results)} tests passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TestFailure as failure:
        print(f"\nFAIL: {failure}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
