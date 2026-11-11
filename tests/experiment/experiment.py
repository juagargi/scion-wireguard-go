#!/usr/bin/env python3
"""Experiment runner for wireguard-go over SCION/Hummingbird: setup | run | teardown.

    tests/experiment/experiment.py setup    --config tests/experiment/experiment-docker.json --scion-dir $SCION
    tests/experiment/experiment.py run      --config tests/experiment/experiment-docker.json --scion-dir $SCION
    tests/experiment/experiment.py teardown --config tests/experiment/experiment-docker.json --scion-dir $SCION

The semantics:

* setup is idempotent, prints the config's `informative` lines first and ends with
  `setup: done.` or `setup: FAILED.` (with --dry-run nothing is changed and every step is listed).
* run starts from a clean slate (only OUR leftovers: pidfiles under <run_dir>/runs and wgx-*
  devices), brings the tunnels up, runs the workloads, collects the logs into
  tests/experiment/logs/<run_id>/, writes results.json and cleans up what it created, also on
  Ctrl-C or an exception (SIGINT is ignored during the cleanup). The exit status is 0 if and only
  if every primary workload passed, including its verification.
* teardown reverses setup, continues past failures and reports them at the end.

Needs PyYAML (hummbwtester); on SSH also bcrypt.
"""

from __future__ import annotations

import argparse
import datetime
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Optional

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:  # flat imports, as in the other modules
    sys.path.insert(0, str(HERE))

import config as config_mod  # noqa: E402
import results as results_mod  # noqa: E402
import runner_metrics  # noqa: E402
import workloads as workloads_mod  # noqa: E402
import wireguard  # noqa: E402
from config import ConfigError, Experiment  # noqa: E402

REPO_ROOT = HERE.parent.parent
LOGS_DIR = HERE / "logs"
BINARY = REPO_ROOT / "wireguard-go"

POLL_INTERVAL = 0.5          # seconds between looks at the workloads
PROGRESS_INTERVAL = 30.0     # seconds between progress lines
RESERVATION_POLL_INTERVAL = 15.0   # seconds between reads of the senders' logs for the counters


class RunnerError(RuntimeError):
    """The run cannot continue (a tunnel did not come up, an instance died, ...)."""


# ---------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------

def say(message: str = "") -> None:
    print(message, flush=True)


def iso(epoch: Optional[float]) -> Optional[str]:
    if epoch is None:
        return None
    return datetime.datetime.fromtimestamp(epoch).astimezone().isoformat(timespec="seconds")


def make_run_id(experiment: Experiment, now: Optional[datetime.datetime] = None) -> str:
    stamp = (now or datetime.datetime.now()).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{experiment.name}"


def resolve_scion_dir(value: Optional[str]) -> Path:
    value = value or os.environ.get("SCION_DIR")
    if not value:
        raise ConfigError("--scion-dir (or $SCION_DIR) is required: the SCION checkout that holds "
                          "the topology and tools/hummbwtester")
    path = Path(value).expanduser()
    if not path.is_dir():
        raise ConfigError(f"--scion-dir {path} is not a directory")
    return path


def build_binary(dry_run: bool = False, runner: Callable[..., Any] = subprocess.run) -> Path:
    """Build wireguard-go with `make` (make itself skips an up-to-date binary)."""
    if dry_run:
        say(f"dry-run: would run `make` in {REPO_ROOT}")
        if not BINARY.is_file():
            raise RunnerError(f"{BINARY} does not exist yet; run setup without --dry-run to build it")
        return BINARY
    say(f"building wireguard-go: make (in {REPO_ROOT})")
    result = runner(["make"], cwd=REPO_ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        raise RunnerError(f"make failed:\n{result.stdout}{result.stderr}")
    if not BINARY.is_file():
        raise RunnerError(f"make did not produce {BINARY}")
    return BINARY


def new_infra(experiment: Experiment, scion_dir: Path, dry_run: bool = False) -> Any:
    import infra as infra_mod
    return infra_mod.Infra.for_experiment(experiment, scion_dir, dry_run)


# ---------------------------------------------------------------------------------------------
# setup
# ---------------------------------------------------------------------------------------------

def cmd_setup(experiment: Experiment, scion_dir: Path, *, dry_run: bool = False,
              infra_factory: Callable[..., Any] = new_infra,
              builder: Callable[..., Path] = build_binary) -> int:
    for line in experiment.informative:
        say(line)
    if experiment.informative:
        say()
    failures: list[str] = []
    try:
        config_mod.check_environment(experiment)
        say(f"config {experiment.path} is valid ({experiment.kind} deployment, "
            f"{len(experiment.tunnels)} tunnels, {len(experiment.workloads)} workloads)")
        binary = builder(dry_run)
        infra = infra_factory(experiment, scion_dir, dry_run)
        failures += infra.check_clocks()
        failures += infra.setup_infrastructure()
        failures += infra.preflight()
        infra.install_binary(binary)
        infra.install_jwt()
        failures += infra.setup_monitoring()
    except Exception as err:  # noqa: BLE001 - every failure ends in "setup: FAILED."
        say(f"setup: error: {err}")
        failures.append(str(err))
    if failures:
        for failure in failures:
            say(f"setup: problem: {failure}")
        say("setup: FAILED.")
        return 1
    if dry_run:
        say("dry-run: nothing was changed")
    say("setup: done.")
    return 0


# ---------------------------------------------------------------------------------------------
# teardown
# ---------------------------------------------------------------------------------------------

def remove_leftovers(infra: Any, experiment: Experiment, run_dir_cleanup: bool = False) -> list[str]:
    """Stop our wireguard-go instances and workload daemons recorded under <run_dir>/runs and
    delete our wgx-* devices, on every host. Returns the problems (never raises)."""
    problems: list[str] = []
    for key, host in infra.hosts().items():
        run_dir = infra.run_dir(key)
        interfaces = [e.interface for e in experiment.endpoints if e.host_key == key]
        try:
            for what in wireguard.cleanup_leftovers(host, run_dir, interfaces):
                say(f"cleanup: {host.name}: stopped {what}")
            found = host.run(["bash", "-c", 'compgen -G "$1/runs/*/work/*/rsyncd.pid" || true',
                              "bash", run_dir.rstrip("/")], check=False).stdout.split()
            for pid_path in found:
                if host.stop_daemon(pid_path):
                    say(f"cleanup: {host.name}: stopped {pid_path}")
            host.run(["rm", "-rf", "--", f"{run_dir.rstrip('/')}/runs"], check=False)
            if run_dir_cleanup:
                host.run(["rm", "-rf", "--", run_dir], check=False)
        except Exception as err:  # noqa: BLE001
            problems.append(f"{key}: {err}")
            say(f"cleanup: {key}: {err}")
    return problems


def cmd_teardown(experiment: Experiment, scion_dir: Path, *,
                 infra_factory: Callable[..., Any] = new_infra) -> int:
    errors: list[str] = []
    try:
        infra = infra_factory(experiment, scion_dir, False)
    except Exception as err:  # noqa: BLE001
        say(f"teardown: cannot reach the infrastructure: {err}")
        say("teardown: FAILED.")
        return 1
    errors += remove_leftovers(infra, experiment, run_dir_cleanup=(experiment.kind == "docker"))
    try:
        errors += infra.teardown_infrastructure()
    except Exception as err:  # noqa: BLE001
        errors.append(str(err))
        say(f"teardown: {err}")
    if errors:
        say("teardown: finished with errors:")
        for error in errors:
            say(f"  {error}")
        say("teardown: FAILED.")
        return 1
    say("teardown: done.")
    return 0


# ---------------------------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------------------------

def to_outcome(res: Any, workload: Any, *, interrupted: bool, timed_out: bool) -> results_mod.WorkloadOutcome:
    """workloads.WorkloadResult -> results.WorkloadOutcome."""
    state = res.state
    if res.state == workloads_mod.PASSED:
        state = "passed"
    elif timed_out or (res.error and res.error.startswith("timed out")):
        state = "timeout"
    elif interrupted:
        state = "stopped"
    else:
        state = "failed"
    return results_mod.WorkloadOutcome(
        id=res.id, kind=res.kind, role=res.role, tunnel=workload.tunnel.id,
        from_=workload.from_, to=workload.to, state=state, iterations=res.iterations,
        restarts=res.restarts, bytes=res.bytes, started_at=iso(res.started_at),
        ended_at=iso(res.ended_at), duration_s=round(res.duration or 0.0, 3),
        mean_goodput_bps=res.mean_goodput_bps or 0.0, details=res.details, error=res.error)


def missing_outcome(workload: Any, reason: str, interrupted: bool) -> results_mod.WorkloadOutcome:
    return results_mod.WorkloadOutcome(
        id=workload.id, kind=workload.kind, role=workload.role, tunnel=workload.tunnel.id,
        from_=workload.from_, to=workload.to, state="stopped" if interrupted else "failed",
        error=reason)


class Run:
    """One run of the experiment. All the fakes of the unit tests plug in through the factories."""

    def __init__(self, experiment: Experiment, infra: Any, *, run_id: Optional[str] = None,
                 logs_root: Path = LOGS_DIR,
                 instance_factory: Callable[..., Any] = wireguard.WireguardInstance,
                 runner_factory: Callable[..., Any] = workloads_mod.make_runner,
                 server_factory: Callable[..., Any] = runner_metrics.MetricsServer,
                 poll_interval: float = POLL_INTERVAL,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.time) -> None:
        self.experiment = experiment
        self.infra = infra
        self.run_id = run_id or make_run_id(experiment)
        self.logs_dir = Path(logs_root) / self.run_id
        self.instance_factory = instance_factory
        self.runner_factory = runner_factory
        self.server_factory = server_factory
        self.poll_interval = poll_interval
        self.sleep = sleep
        self.clock = clock
        self.metrics = runner_metrics.make_runner_registry(self.run_id, experiment.sha256,
                                                           experiment.name)
        self.server: Any = None
        self.instances: dict[str, Any] = {}
        self.runners: dict[str, Any] = {}
        self.hosts: dict[str, Any] = {}
        self.started = self.clock()
        self.interrupted = False
        self.timed_out = False
        self.errors: list[str] = []
        self._counted: dict[tuple[str, str], int] = {}
        self._sender_stats: dict[str, results_mod.SenderStats] = {}
        self._last_progress = 0.0
        self._last_reservations = 0.0

    # -- phases --------------------------------------------------------------------------------
    def clean_slate(self) -> None:
        problems = remove_leftovers(self.infra, self.experiment)
        if problems:
            raise RunnerError("could not clean up leftovers of earlier runs: " + "; ".join(problems))

    def check_binaries(self) -> None:
        binaries = self.infra.binary_paths()
        for key, host in self.hosts.items():
            if not host.path_exists(binaries[key]):
                raise RunnerError(f"{binaries[key]} is missing on {host.name}: run `setup` first")

    def start_instances(self) -> None:
        exp, infra = self.experiment, self.infra
        binaries, jwts = infra.binary_paths(), infra.jwt_paths() or {}
        for ep in exp.endpoints:
            key = ep.host_key
            inst = self.instance_factory(
                exp, ep, self.hosts[key], binaries[key], infra.run_dir(key), self.run_id,
                jwts.get(key) if ep.hummingbird else None, infra.sciond_address(ep))
            self.instances[ep.name] = inst
        # The run directory belongs to the SSH user, who runs the instances and the workloads.
        for key, host in self.hosts.items():
            host.run(["mkdir", "-p", "--", f"{infra.run_dir(key).rstrip('/')}/runs/{self.run_id}/work"])
        say(f"starting {len(self.instances)} wireguard-go instances")
        for ep in exp.endpoints:
            inst = self.instances[ep.name]
            pid = inst.start()
            say(f"  {ep.name}: {inst.host.name} {ep.interface} pid {pid}")

    def bring_up_tunnels(self) -> None:
        for tunnel in self.experiment.tunnels:
            a, b = (self.instances[e.name] for e in tunnel.endpoints)
            say(f"bringing tunnel {tunnel.id} up ({a.endpoint.name} <-> {b.endpoint.name})")
            lines = wireguard.bring_up_tunnel(a, b)
            for name, line in lines.items():
                if line:
                    say(f"  {name}: {line}")
            say(f"  tunnel {tunnel.id} is up")

    def start_metrics_server(self) -> None:
        port = self.experiment.monitoring.runner_metrics_port
        for ep in self.experiment.endpoints:  # series from zero, so that `increase` sees the first purchase
            if ep.hummingbird is not None:
                for result in ("ok", "failed"):
                    self.metrics.reservations.labels(endpoint=ep.name, result=result)
        self.server = self.server_factory(self.metrics.registry, port, "127.0.0.1")
        self.server.start()
        say(f"runner metrics on http://127.0.0.1:{port}/metrics")

    def make_runners(self) -> None:
        exp, infra = self.experiment, self.infra
        index = 0
        for w in exp.workloads:
            sender, receiver = self.hosts[w.sender.host_key], self.hosts[w.receiver.host_key]
            reservation = w.sender.hummingbird.bandwidth_bps if w.sender.hummingbird else None
            i = 0
            if w.kind == "file_copy":
                i, index = index, index + 1
            work = lambda ep: f"{infra.run_dir(ep.host_key).rstrip('/')}/runs/{self.run_id}/work"
            self.runners[w.id] = self.runner_factory(
                w, sender, receiver, self.metrics, work(w.sender), work(w.receiver), self.run_id,
                reservation, self.logs_dir, index=i)

    def prepare_runners(self) -> None:
        for w in self.experiment.workloads:
            say(f"preparing workload {w.id} ({w.kind}, {w.role}, {w.from_}->{w.to})")
            self.runners[w.id].prepare()

    def _check_instances(self) -> None:
        for name, inst in self.instances.items():
            if not inst.alive():
                raise RunnerError(f"wireguard-go for {name} died during the run:\n{inst.log_tail()}")

    def _update_reservations(self, final: bool = False) -> None:
        now = time.monotonic()
        if not final and now - self._last_reservations < RESERVATION_POLL_INTERVAL:
            return
        self._last_reservations = now
        for ep in self.experiment.endpoints:
            if ep.hummingbird is None:
                continue
            try:
                stats = self.instances[ep.name].reservation_log_stats()
            except Exception as err:  # noqa: BLE001 - metrics must not break the run
                say(f"warning: reading the log of {ep.name}: {err}")
                continue
            for result, total in (("ok", stats.purchased), ("failed", stats.failed)):
                delta = total - self._counted.get((ep.name, result), 0)
                counter = self.metrics.reservations.labels(endpoint=ep.name, result=result)
                if delta > 0:
                    counter.inc(delta)
                    self._counted[(ep.name, result)] = total
            self._sender_stats[ep.name] = results_mod.SenderStats(
                endpoint=ep.name, reservations_bought=stats.purchased,
                reservations_failed=stats.failed, handovers=stats.handovers,
                marketplace_addresses=list(stats.marketplaces))

    def _progress(self) -> None:
        now = time.monotonic()
        if now - self._last_progress < PROGRESS_INTERVAL:
            return
        self._last_progress = now
        parts = []
        for w in self.experiment.workloads:
            r = self.runners[w.id].result()
            text = f"{w.id}: {r.state}"
            if w.kind == "file_copy":
                text += f" {r.bytes / max(w.size_bytes, 1):.0%}"
            parts.append(text)
        say("  " + ", ".join(parts))

    def _sleep_checking(self, seconds: float) -> None:
        """Sleep, but notice a dying instance."""
        end = time.monotonic() + seconds
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                return
            self.sleep(min(self.poll_interval, remaining))
            self._check_instances()
            self._update_reservations()

    def run_workloads(self) -> None:
        exp = self.experiment
        background = [w for w in exp.workloads if w.role == "background"]
        primary = sorted((w for w in exp.workloads if w.role == "primary"),
                         key=lambda w: w.start_delay)
        t0 = time.monotonic()
        for w in background:
            self.runners[w.id].start()
            say(f"started background workload {w.id}")
        if exp.run.warmup > 0:
            say(f"warmup {exp.run.warmup:g}s")
            self._sleep_checking(exp.run.warmup)
        t1 = time.monotonic()
        pending = list(primary)
        say(f"starting {len(primary)} primary workload(s)")
        while True:
            now = time.monotonic()
            while pending and now - t1 >= pending[0].start_delay:
                w = pending.pop(0)
                self.runners[w.id].start()
                say(f"started primary workload {w.id}")
            states = [self.runners[w.id].poll() for w in primary]
            if any(s == workloads_mod.FAILED for s in states):
                failed = [w.id for w, s in zip(primary, states) if s == workloads_mod.FAILED]
                self.errors.append(f"primary workload(s) failed: {', '.join(failed)}")
                say(f"primary workload failed: {', '.join(failed)}; stopping")
                return
            if not pending and all(s == workloads_mod.PASSED for s in states):
                break
            if exp.run.max_duration is not None and now - t0 >= exp.run.max_duration:
                self.timed_out = True
                self.errors.append(f"run.max_duration of {exp.run.max_duration:g}s elapsed")
                say(self.errors[-1])
                return
            self.sleep(self.poll_interval)
            self._check_instances()
            self._update_reservations()
            self._progress()
        if exp.run.cooldown > 0:
            say(f"cooldown {exp.run.cooldown:g}s")
            self._sleep_checking(exp.run.cooldown)

    # -- end of run ----------------------------------------------------------------------------
    def stop_workloads(self) -> None:
        for w in self.experiment.workloads:
            runner = self.runners.get(w.id)
            if runner is not None:
                try:
                    runner.stop()
                except Exception as err:  # noqa: BLE001
                    say(f"warning: stopping {w.id}: {err}")

    def collect_logs(self) -> None:
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        for name, inst in self.instances.items():
            try:
                inst.host.get_file(inst.log_path, self.logs_dir / f"wg-{name}.log")
            except Exception as err:  # noqa: BLE001
                say(f"warning: could not collect the log of {name}: {err}")
        if self.logs_dir.exists():
            say(f"logs: {self.logs_dir}")

    def build_result(self, end: float) -> results_mod.RunResult:
        exp = self.experiment
        outcomes = []
        for w in exp.workloads:
            runner = self.runners.get(w.id)
            if runner is None:
                outcomes.append(missing_outcome(w, "not started: " + (
                    "; ".join(self.errors) or "the run ended before the workloads"),
                    self.interrupted))
                continue
            outcome = to_outcome(runner.result(), w, interrupted=self.interrupted,
                                 timed_out=self.timed_out and w.role == "primary"
                                 and runner.poll() != workloads_mod.PASSED)
            if (self.timed_out and w.role == "primary" and outcome.state == "timeout"
                    and not outcome.error):
                outcome.error = "run.max_duration elapsed"
            outcomes.append(outcome)
        try:
            self._update_reservations(final=True)
        except Exception as err:  # noqa: BLE001
            say(f"warning: reservation statistics: {err}")
        prometheus: dict = {}
        try:
            self.sleep(max(exp.monitoring.scrape_interval_seconds, 1.0) * 2)  # let a scrape land
            prometheus = results_mod.query_prometheus(self.infra.prometheus_url, self.started, end)
        except Exception as err:  # noqa: BLE001
            prometheus = {"error": str(err)}
        return results_mod.RunResult(
            run_id=self.run_id, config_path=str(exp.path), config_sha256=exp.sha256,
            deployment_kind=exp.kind, name=exp.name, started_at=iso(self.started) or "",
            ended_at=iso(end) or "", interrupted=self.interrupted, workloads=outcomes,
            senders=[self._sender_stats[e.name] for e in exp.endpoints if e.name in self._sender_stats],
            prometheus=prometheus, grafana_url=self.infra.grafana_url(self.started, end))

    def cleanup(self) -> list[str]:
        """Remove what the run created. Never raises."""
        problems: list[str] = []
        for w in self.experiment.workloads:
            runner = self.runners.get(w.id)
            if runner is not None:
                try:
                    runner.cleanup()
                except Exception as err:  # noqa: BLE001
                    problems.append(f"workload {w.id}: {err}")
        for name, inst in self.instances.items():
            try:
                inst.stop()
            except Exception as err:  # noqa: BLE001
                problems.append(f"instance {name}: {err}")
        if self.server is not None:
            try:
                self.server.stop()
            except Exception as err:  # noqa: BLE001
                problems.append(f"metrics server: {err}")
        for key, host in self.hosts.items():
            try:
                host.run(["rm", "-rf", "--", f"{self.infra.run_dir(key).rstrip('/')}/runs/{self.run_id}"],
                         check=False)
            except Exception as err:  # noqa: BLE001
                problems.append(f"{key}: {err}")
        for problem in problems:
            say(f"cleanup: {problem}")
        return problems

    # -- the whole run -------------------------------------------------------------------------
    def execute(self) -> int:
        exp = self.experiment
        say(f"run {self.run_id}")
        result: Optional[results_mod.RunResult] = None
        try:
            self.infra.check_clocks()
            self.hosts = dict(self.infra.hosts())
            if self.experiment.kind == "docker":  # file_sd picks the change up; SSH keeps its own
                self.infra.write_targets()
            self.check_binaries()
            self.clean_slate()
            self.start_instances()
            self.bring_up_tunnels()
            self.start_metrics_server()
            self.make_runners()
            self.prepare_runners()
            self.started = self.clock()
            self.run_workloads()
        except KeyboardInterrupt:
            self.interrupted = True
            say("interrupted: cleaning up")
        except Exception as err:  # noqa: BLE001
            self.errors.append(str(err))
            say(f"run failed: {err}")
        finally:
            previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                end = self.clock()
                self.stop_workloads()
                self.collect_logs()
                try:
                    result = self.build_result(end)
                    results_mod.write_results(self.logs_dir / "results.json", result)
                except Exception as err:  # noqa: BLE001
                    say(f"warning: could not write results.json: {err}")
                self.cleanup()
            finally:
                signal.signal(signal.SIGINT, previous)
        if result is None:
            return 1
        say()
        say(results_mod.render_summary(result))
        say(f"results: {self.logs_dir / 'results.json'}")
        return results_mod.exit_code(result)


def cmd_run(experiment: Experiment, scion_dir: Path, *,
            infra_factory: Callable[..., Any] = new_infra, **kwargs: Any) -> int:
    infra = infra_factory(experiment, scion_dir, False)
    def on_sigterm(*_: Any) -> None:
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, on_sigterm)
    try:
        return Run(experiment, infra, **kwargs).execute()
    finally:
        signal.signal(signal.SIGTERM, previous)


# ---------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Experiment runner for wireguard-go over SCION/Hummingbird.")
    parser.add_argument("command", choices=("setup", "run", "teardown"))
    parser.add_argument("--config", required=True, type=Path, help="experiment JSON file")
    parser.add_argument("--scion-dir", help="SCION checkout (default: $SCION_DIR)")
    parser.add_argument("--dry-run", action="store_true",
                        help="setup only: check everything, change nothing, list every step")
    return parser


def main(argv: Optional[list[str]] = None, *,
         infra_factory: Callable[..., Any] = new_infra,
         builder: Callable[..., Path] = build_binary) -> int:
    args = build_parser().parse_args(argv)
    if args.dry_run and args.command != "setup":
        say("--dry-run applies to setup only")
        return 2
    try:
        experiment = config_mod.load_config(args.config)
        scion_dir = resolve_scion_dir(args.scion_dir)
    except (ConfigError, OSError, ValueError) as err:
        say(f"{args.command}: invalid configuration: {err}")
        if args.command == "setup":
            say("setup: FAILED.")
        return 2
    try:
        if args.command == "setup":
            return cmd_setup(experiment, scion_dir, dry_run=args.dry_run,
                             infra_factory=infra_factory, builder=builder)
        if args.command == "run":
            return cmd_run(experiment, scion_dir, infra_factory=infra_factory)
        return cmd_teardown(experiment, scion_dir, infra_factory=infra_factory)
    except KeyboardInterrupt:
        say("interrupted")
        return 130
    except Exception as err:  # noqa: BLE001
        say(f"{args.command}: error: {err}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
