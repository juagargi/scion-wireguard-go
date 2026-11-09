"""Workload runners: file_copy (rsync), iperf3 and ping, driven through the Host protocol.

Lifecycle of every runner: prepare() -> start() -> poll()/wait() -> stop() -> cleanup(); result() any time.
Processes are always started from argv lists. Parsers are pure functions (see test_workloads.py).
"""

from __future__ import annotations

import math
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from config import FileCopy, Iperf3, Ping, Workload
from runner_metrics import RunnerMetrics, WorkloadLabels

PENDING, RUNNING, PASSED, FAILED = "pending", "running", "passed", "failed"
STATE_VALUE = {PENDING: 0, RUNNING: 1, PASSED: 2, FAILED: 3}

# rsync limits payload bytes, the border router accounts whole SCION packets (SCION + UDP + WireGuard
# headers). A limit equal to the reservation would get part of the traffic demoted.
PAYLOAD_EFFICIENCY = 0.8
RSYNC_BASE_PORT = 8730          # rsync daemon port = RSYNC_BASE_PORT + index (index unique per run)
POLL_INTERVAL = 0.05             # seconds between checks of a running process, for it and for stop
RESTART_BACKOFF = 1.0           # seconds between iperf3 restarts
RTT_BUCKETS = (0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1,
               0.25, 0.5, 1.0, 2.5, 5.0)

# ---------------------------------------------------------------------------------------------
# Pure parsers
# ---------------------------------------------------------------------------------------------

_RSYNC_PROGRESS_RE = re.compile(
    r"^\s*([\d,.]+)([KMGT]?)\s+(\d+)%\s+([\d.]+\s*[KkMmGgTt]?B/s)\s+(\d+:\d+:\d+)")


def parse_rsync_progress(line: str) -> Optional[int]:
    """Bytes transferred so far from one --info=progress2 line, or None for any other line."""
    m = _RSYNC_PROGRESS_RE.match(line)
    if not m:
        return None
    num, unit = m.group(1).replace(",", ""), m.group(2)
    try:
        return int(float(num) * {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}[unit])
    except ValueError:
        return None


def split_progress_chunks(text: str) -> list[str]:
    """rsync separates progress updates by carriage returns: split on both CR and LF."""
    return [c for c in re.split(r"[\r\n]+", text) if c.strip()]


def rsync_bwlimit_arg(bps: int) -> str:
    """bits per second -> rsync's --bwlimit (a bare number is KiB/s, so mark it)."""
    return f"--bwlimit={bps / 8 / 1024:.3f}K"


_UNIT = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}
_BITS = {"": 1, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}
_IPERF_RE = re.compile(
    r"^\[\s*(\d+|SUM)\]\s+([\d.]+)-\s*([\d.]+)\s+sec\s+([\d.]+)\s+([KMGT]?)Bytes\s+"
    r"([\d.]+)\s+([KMGT]?)bits/sec(.*)$")
_IPERF_LOSS_RE = re.compile(r"([\d.]+)\s+ms\s+(-?\d+)/(\d+)\s+\(\S+%\)")
_IPERF_DGRAMS_RE = re.compile(r"^\s+(\d+)\s*$")


@dataclass
class IperfInterval:
    stream: str                 # "5" or "SUM"
    start: float
    end: float
    bytes: int
    bits_per_second: float
    summary: bool               # the final sender/receiver lines
    jitter_ms: Optional[float] = None
    lost: Optional[int] = None  # UDP server lines
    total: Optional[int] = None  # UDP server lines: datagrams in the interval
    datagrams: Optional[int] = None  # UDP client lines


def parse_iperf3_line(line: str) -> Optional[IperfInterval]:
    """One per-interval line of iperf 3.x text output (client or server), else None."""
    m = _IPERF_RE.match(line.rstrip())
    if not m:
        return None
    rest = m.group(8)
    iv = IperfInterval(
        stream=m.group(1), start=float(m.group(2)), end=float(m.group(3)),
        bytes=int(round(float(m.group(4)) * _UNIT[m.group(5)])),
        bits_per_second=float(m.group(6)) * _BITS[m.group(7)],
        summary=bool(re.search(r"\b(sender|receiver)\s*$", rest)))
    loss = _IPERF_LOSS_RE.search(rest)
    if loss:
        iv.jitter_ms, iv.lost, iv.total = float(loss.group(1)), int(loss.group(2)), int(loss.group(3))
    else:
        d = _IPERF_DGRAMS_RE.match(rest)
        if d:
            iv.datagrams = int(d.group(1))
    return iv


_PING_RE = re.compile(
    r"^\[(\d+(?:\.\d+)?)\]\s+(\d+) bytes from \S+?:?\s.*?icmp_seq=(\d+).*?time[=<]([\d.]+)\s*ms(.*)$")
_PING_SUMMARY_RE = re.compile(r"(\d+) packets transmitted, (\d+) (?:packets )?received")


@dataclass
class PingReply:
    timestamp: float
    seq: int
    rtt_seconds: float
    duplicate: bool


def parse_ping_line(line: str) -> Optional[PingReply]:
    m = _PING_RE.match(line.strip())
    if not m:
        return None
    return PingReply(float(m.group(1)), int(m.group(3)), float(m.group(4)) / 1000.0,
                     "DUP" in m.group(5))


def parse_ping_summary(line: str) -> Optional[tuple[int, int]]:
    """(transmitted, received) from the final statistics line."""
    m = _PING_SUMMARY_RE.search(line)
    return (int(m.group(1)), int(m.group(2))) if m else None


class PingTracker:
    """Derives sent/received counts, RTT and RFC 3550 jitter from replies.

    sent is the highest sequence number seen (loss shows as gaps); iputils wraps the 16-bit
    sequence, handled by unwrapping.
    """

    def __init__(self) -> None:
        self.highest = 0        # unwrapped highest seq
        self.received = 0
        self.jitter = 0.0       # seconds
        self._prev_rtt: Optional[float] = None
        self._wraps = 0
        self._last_raw = 0
        self.rtts: list[float] = []

    def update(self, reply: PingReply) -> int:
        """Feed one reply; returns the number of newly counted sent packets."""
        raw = reply.seq
        if raw + 32768 < self._last_raw:
            self._wraps += 1
        self._last_raw = raw
        seq = raw + self._wraps * 65536
        new_sent = 0
        if not reply.duplicate:
            self.received += 1
            if seq > self.highest:
                new_sent = seq - self.highest
                self.highest = seq
            if self._prev_rtt is not None:
                self.jitter += (abs(reply.rtt_seconds - self._prev_rtt) - self.jitter) / 16.0
            self._prev_rtt = reply.rtt_seconds
            self.rtts.append(reply.rtt_seconds)
        return new_sent

    def sent_from_summary(self, transmitted: int) -> int:
        """Packets to add to sent so it matches the final summary (trailing losses)."""
        extra = max(0, transmitted - self.highest)
        self.highest += extra
        return extra


# ---------------------------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------------------------

@dataclass
class WorkloadResult:
    id: str
    kind: str
    role: str
    state: str
    iterations: int
    restarts: int
    bytes: int
    started_at: Optional[float]
    ended_at: Optional[float]
    duration: Optional[float]
    mean_goodput_bps: Optional[float]
    details: dict = field(default_factory=dict)
    error: Optional[str] = None


class WorkloadRunner:
    def __init__(self, workload: Workload, sender: Any, receiver: Any, metrics: RunnerMetrics,
                 run_dir_on_sender: str, run_dir_on_receiver: str, run_id: str,
                 reservation_bwlimit_bps: Optional[int], logs_dir: Path, *, index: int = 0) -> None:
        self.w, self.sender, self.receiver, self.metrics = workload, sender, receiver, metrics
        self.sender_dir = f"{run_dir_on_sender.rstrip('/')}/{workload.id}"
        self.receiver_dir = f"{run_dir_on_receiver.rstrip('/')}/{workload.id}"
        self.run_id, self.reservation_bwlimit_bps = run_id, reservation_bwlimit_bps
        self.logs_dir, self.index = Path(logs_dir), index
        self.src_ip = workload.sender.tunnel_ip
        self.dst_ip = workload.receiver.tunnel_ip
        labels = WorkloadLabels(workload)
        self._labels = labels
        self.m_state = metrics.workload_state.labels(**labels)
        self.m_bytes = metrics.workload_bytes.labels(**labels)
        self.m_iter = metrics.workload_iterations.labels(**labels)
        self.m_restarts = metrics.workload_restarts.labels(**labels)
        self.m_state.set(STATE_VALUE[PENDING])
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._done = threading.Event()
        self._state = PENDING
        self._error: Optional[str] = None
        self._completed = False
        self._timed_out = False
        self._procs: list[subprocess.Popen] = []
        self._threads: list[threading.Thread] = []
        self._worker: Optional[threading.Thread] = None
        self._started_at: Optional[float] = None
        self._ended_at: Optional[float] = None
        self.bytes = 0
        self.iterations = 0
        self.restarts = 0
        self.details: dict = {}
        self._prepared = False
        self._cleaned = False
        self.logs_dir.mkdir(parents=True, exist_ok=True)

    # -- hooks ---------------------------------------------------------------------------------
    def _prepare(self) -> None:
        pass

    def _run(self) -> None:
        raise NotImplementedError

    def _cleanup(self) -> None:
        pass

    def _on_stop(self) -> None:
        pass

    # -- lifecycle -----------------------------------------------------------------------------
    def prepare(self) -> None:
        if self._prepared:
            return
        try:
            self._prepare()
        except BaseException as e:
            self._fail(f"prepare failed: {e}")
            self._finish()
            raise
        self._prepared = True

    def start(self) -> None:
        with self._lock:
            if self._state != PENDING or self._worker is not None:
                return
            if not self._prepared:
                raise RuntimeError(f"{self.w.id}: start() before prepare()")
            self._started_at = time.time()
            self._set_state(RUNNING)
            self._worker = threading.Thread(target=self._main, name=f"wl-{self.w.id}", daemon=True)
            self._worker.start()
            if self.w.timeout:
                threading.Thread(target=self._watchdog, name=f"wl-{self.w.id}-watchdog",
                                 daemon=True).start()

    def poll(self) -> str:
        return self._state

    def wait(self, timeout: Optional[float] = None) -> str:
        """Block until the workload is no longer running (or the timeout expires); returns the state."""
        if self._worker is not None:
            self._done.wait(timeout)
        return self._state

    def stop(self) -> None:
        """Terminate everything the runner started. Idempotent."""
        self._stop.set()
        self._on_stop()
        for p in list(self._procs):
            self._terminate(p)
        worker = self._worker
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=15)
        for p in list(self._procs):  # processes started while stopping
            self._terminate(p)
        if worker is None:
            self._finish()

    def cleanup(self) -> None:
        if self._cleaned:
            return
        self.stop()
        self._cleaned = True
        try:
            self._cleanup()
        except Exception as e:  # cleanup must not hide the result
            self.details.setdefault("cleanup_error", str(e))

    def result(self) -> WorkloadResult:
        end = self._ended_at if self._ended_at is not None else (time.time() if self._started_at else None)
        duration = (end - self._started_at) if (self._started_at and end) else None
        goodput = (self.bytes * 8 / duration) if duration and duration > 0 else None
        return WorkloadResult(
            id=self.w.id, kind=self.w.kind, role=self.w.role, state=self._state,
            iterations=self.iterations, restarts=self.restarts, bytes=self.bytes,
            started_at=self._started_at, ended_at=self._ended_at, duration=duration,
            mean_goodput_bps=goodput, details=dict(self.details), error=self._error)

    # -- internals -----------------------------------------------------------------------------
    def _set_state(self, state: str) -> None:
        with self._lock:
            self._state = state
            self.m_state.set(STATE_VALUE[state])

    def _fail(self, message: str) -> None:
        with self._lock:
            if self._error is None:
                self._error = message
            self._set_state(FAILED)

    def _finish(self) -> None:
        with self._lock:
            if self._ended_at is None:
                self._ended_at = time.time()
            if self._state in (PENDING, RUNNING):
                if self._error is not None:
                    self._set_state(FAILED)
                elif self._completed or (self._stop.is_set() and self.w.role == "background"):
                    self._set_state(PASSED)
                else:
                    self._error = "stopped before completion"
                    self._set_state(FAILED)
        self._done.set()

    def _main(self) -> None:
        try:
            self._run()
        except BaseException as e:  # noqa: BLE001
            self._fail(f"{type(e).__name__}: {e}")
        finally:
            for p in list(self._procs):
                self._terminate(p)
            self._finish()

    def _watchdog(self) -> None:
        if not self._done.wait(self.w.timeout):
            self._timed_out = True
            self._fail(f"timed out after {self.w.timeout:g}s")
            self._stop.set()
            for p in list(self._procs):
                self._terminate(p)

    def _add_bytes(self, n: int) -> None:
        if n > 0:
            with self._lock:
                self.bytes += n
            self.m_bytes.inc(n)

    def _log(self, tag: str, line: str) -> None:
        try:
            with open(self.logs_dir / f"{self.w.id}.{tag}.log", "a", encoding="utf-8") as f:
                f.write(line if line.endswith("\n") else line + "\n")
        except OSError:
            pass

    def _spawn(self, host: Any, argv: list[str], tag: str,
               handler: Optional[Callable[[str], None]] = None) -> subprocess.Popen:
        self._log(tag, "$ " + " ".join(argv))
        proc = host.popen(argv)
        with self._lock:
            self._procs.append(proc)
        t = threading.Thread(target=self._pump, args=(proc, tag, handler), daemon=True,
                             name=f"wl-{self.w.id}-{tag}")
        t.start()
        proc._pump_thread = t  # type: ignore[attr-defined]
        self._threads.append(t)
        return proc

    def _pump(self, proc: subprocess.Popen, tag: str, handler: Optional[Callable[[str], None]]) -> None:
        stream = proc.stdout
        if stream is None:
            return
        try:
            for raw in stream:
                for line in split_progress_chunks(raw):
                    self._log(tag, line)
                    if handler is not None:
                        try:
                            handler(line)
                        except Exception as e:  # a parser bug must not kill the pipe
                            self._log(tag, f"handler error: {e}")
        except ValueError:  # closed under us
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def _terminate(self, proc: subprocess.Popen, grace: float = 3.0) -> None:
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=grace)
                except subprocess.TimeoutExpired:
                    pass
            except OSError:
                pass
        t = getattr(proc, "_pump_thread", None)
        if t is not None and t is not threading.current_thread():
            t.join(timeout=2)

    def _forget(self, proc: subprocess.Popen) -> None:
        with self._lock:
            if proc in self._procs:
                self._procs.remove(proc)

    def _sleep(self, seconds: float) -> bool:
        """Interruptible sleep; True if stop was requested."""
        return self._stop.wait(seconds)


# ---------------------------------------------------------------------------------------------
# file_copy
# ---------------------------------------------------------------------------------------------

class FileCopyRunner(WorkloadRunner):
    PAYLOAD = "payload.bin"

    def __init__(self, *a: Any, **kw: Any) -> None:
        super().__init__(*a, **kw)
        w: FileCopy = self.w  # type: ignore[assignment]
        self.port = RSYNC_BASE_PORT + self.index
        self.module = w.id
        self.src_file = f"{self.sender_dir}/{self.PAYLOAD}"
        self.recv_data = f"{self.receiver_dir}/data"
        self.recv_file = f"{self.recv_data}/{self.PAYLOAD}"
        self.conf_path = f"{self.receiver_dir}/rsyncd.conf"
        self.pid_path = f"{self.receiver_dir}/rsyncd.pid"
        self.log_path = f"{self.receiver_dir}/rsyncd.log"
        self.bwlimit_bps = self._resolve_bwlimit()
        self.m_verify_ok = self.metrics.verify.labels(**self._labels, result="ok")
        self.m_verify_bad = self.metrics.verify.labels(**self._labels, result="mismatch")
        self._daemon_started = False
        self._sender_sha: Optional[str] = None
        self.details.update(port=self.port, bwlimit_bps=self.bwlimit_bps, size_bytes=w.size_bytes)

    def _resolve_bwlimit(self) -> Optional[int]:
        w: FileCopy = self.w  # type: ignore[assignment]
        if w.bwlimit == "none":
            return None
        if w.bwlimit == "reservation":
            if not self.reservation_bwlimit_bps:
                raise ValueError(f"{w.id}: bwlimit 'reservation' needs reservation_bwlimit_bps")
            return max(1, int(self.reservation_bwlimit_bps * PAYLOAD_EFFICIENCY))
        return w.bwlimit_bps

    def _prepare(self) -> None:
        w: FileCopy = self.w  # type: ignore[assignment]
        self.sender.run(["rm", "-rf", self.sender_dir])
        self.sender.run(["mkdir", "-p", self.sender_dir])
        self.receiver.run(["rm", "-rf", self.receiver_dir])
        self.receiver.run(["mkdir", "-p", self.recv_data])
        self._create_payload(w.size_bytes)
        if w.verify:
            self._sender_sha = self._sha256(self.sender, self.src_file)
            self.details["sha256_sender"] = self._sender_sha
        is_root = self.receiver.run(["id", "-u"], check=False).stdout.strip() == "0"
        conf = [
            "use chroot = no", "max connections = 4",
            f"address = {self.dst_ip}", f"port = {self.port}",
            f"log file = {self.log_path}", f"pid file = {self.receiver_dir}/rsyncd.inner.pid",
            f"lock file = {self.receiver_dir}/rsyncd.lock",
        ]
        if is_root:
            conf = ["uid = root", "gid = root"] + conf
        conf += ["", f"[{self.module}]", f"path = {self.recv_data}", "read only = false", ""]
        self.receiver.put_text("\n".join(conf), self.conf_path)
        self.receiver.start_daemon(
            ["rsync", "--daemon", "--no-detach", f"--config={self.conf_path}"],
            env=None, log_path=f"{self.receiver_dir}/rsyncd.stdout", pid_path=self.pid_path)
        self._daemon_started = True
        deadline = time.monotonic() + 20
        delay = 0.05
        while True:
            probe = self.receiver.run(["rsync", f"rsync://{self.dst_ip}:{self.port}/"],
                                      check=False, timeout=10)
            if probe.returncode == 0:
                return
            if time.monotonic() > deadline:
                raise RuntimeError(f"rsync daemon on {self.dst_ip}:{self.port} did not come up: "
                                   f"{(probe.stderr or '').strip()}")
            time.sleep(delay)
            delay = min(delay * 2, 0.5)

    def _create_payload(self, size: int) -> None:
        mib, rem = divmod(size, 1 << 20)
        if mib:
            self.sender.run(["dd", "if=/dev/urandom", f"of={self.src_file}", "bs=1M",
                             f"count={mib}", "iflag=fullblock", "status=none"])
        if rem:
            argv = ["dd", "if=/dev/urandom", f"of={self.src_file}", f"bs={rem}", "count=1",
                    "iflag=fullblock", "status=none"]
            if mib:
                argv += ["oflag=append", "conv=notrunc"]
            self.sender.run(argv)

    def _sha256(self, host: Any, path: str) -> str:
        out = host.run(["sha256sum", path]).stdout.split()
        if not out:
            raise RuntimeError(f"sha256sum {path} printed nothing")
        return out[0]

    def _rsync_argv(self) -> list[str]:
        argv = ["rsync", "--whole-file", "--ignore-times", "--info=progress2"]
        if self.bwlimit_bps:
            argv.append(rsync_bwlimit_arg(self.bwlimit_bps))
        argv += [self.src_file, f"rsync://{self.dst_ip}:{self.port}/{self.module}/"]
        return argv

    def _run(self) -> None:
        w: FileCopy = self.w  # type: ignore[assignment]
        durations: list[float] = []
        self.details["iteration_seconds"] = durations
        n = 0
        while not self._stop.is_set() and (w.repeat == 0 or n < w.repeat):
            self.receiver.run(["rm", "-f", self.recv_file], check=False)
            seen = [0]

            def on_line(line: str) -> None:
                b = parse_rsync_progress(line)
                if b is not None and b > seen[0]:
                    self._add_bytes(b - seen[0])
                    seen[0] = b

            t0 = time.monotonic()
            proc = self._spawn(self.sender, self._rsync_argv(), "rsync", on_line)
            rc = proc.wait()
            t = getattr(proc, "_pump_thread", None)
            if t is not None:
                t.join(timeout=5)
            self._forget(proc)
            if self._stop.is_set():
                return
            if rc != 0:
                raise RuntimeError(f"rsync exited with status {rc} (iteration {n + 1})")
            self._add_bytes(w.size_bytes - seen[0])
            durations.append(time.monotonic() - t0)
            if w.verify:
                got = self._sha256(self.receiver, self.recv_file)
                self.details["sha256_receiver"] = got
                if got != self._sender_sha:
                    self.m_verify_bad.inc()
                    raise RuntimeError(f"sha256 mismatch in iteration {n + 1}: "
                                       f"sender {self._sender_sha} receiver {got}")
                self.m_verify_ok.inc()
            n += 1
            self.iterations = n
            self.m_iter.inc()
        self._completed = True

    def _cleanup(self) -> None:
        w: FileCopy = self.w  # type: ignore[assignment]
        if self._daemon_started:
            self.receiver.stop_daemon(self.pid_path)
        if w.keep_files:
            self.receiver.run(["rm", "-f", self.conf_path, self.pid_path], check=False)
        else:
            self.receiver.run(["rm", "-rf", self.receiver_dir], check=False)
            self.sender.run(["rm", "-rf", self.sender_dir], check=False)


# ---------------------------------------------------------------------------------------------
# iperf3
# ---------------------------------------------------------------------------------------------

class Iperf3Runner(WorkloadRunner):
    def __init__(self, *a: Any, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self.m_dgrams = self.metrics.iperf3_datagrams.labels(**self._labels)
        self.m_lost = self.metrics.iperf3_lost_datagrams.labels(**self._labels)
        self.port = self.w.server_port  # type: ignore[attr-defined]
        self._server: Optional[subprocess.Popen] = None
        self._listening = threading.Event()
        self.datagrams = 0
        self.lost = 0

    def _server_argv(self) -> list[str]:
        # stdbuf: iperf3 block-buffers its "Server listening" banner when stdout is a pipe
        return ["stdbuf", "-oL", "iperf3", "-s", "-B", self.dst_ip, "-p", str(self.port), "-i", "1",
                "--forceflush"]

    def _client_argv(self) -> list[str]:
        w: Iperf3 = self.w  # type: ignore[assignment]
        argv = ["iperf3", "-c", self.dst_ip, "-p", str(self.port), "-B", self.src_ip]
        if w.protocol == "udp":
            argv.append("-u")
        if w.bandwidth_bps:
            argv += ["-b", str(w.bandwidth_bps)]
        if w.length:
            argv += ["-l", str(w.length)]
        argv += ["-t", str(int(math.ceil(w.duration)) if w.duration else 0), "-i", "1", "--forceflush"]
        if w.parallel > 1:
            argv += ["-P", str(w.parallel)]
        return argv

    def _server_line(self, line: str) -> None:
        w: Iperf3 = self.w  # type: ignore[assignment]
        if "Server listening" in line:
            self._listening.set()
            return
        iv = parse_iperf3_line(line)
        if iv is None or iv.summary or iv.total is None:
            return
        if (w.parallel > 1) != (iv.stream == "SUM"):
            return
        lost, total = max(0, iv.lost or 0), iv.total
        self.datagrams += total
        self.lost += lost
        # UDP does not retransmit: count what arrived, not what the client sent, so that
        # bytes and goodput are the receiver's.
        self._add_bytes((total - lost) * w.length if w.length else iv.bytes)
        self.m_dgrams.inc(total)
        self.m_lost.inc(lost)
        self.details["datagrams"], self.details["lost_datagrams"] = self.datagrams, self.lost

    def _client_line(self, line: str) -> None:
        w: Iperf3 = self.w  # type: ignore[assignment]
        iv = parse_iperf3_line(line)
        if iv is None or iv.summary or (w.parallel > 1) != (iv.stream == "SUM"):
            return
        if w.protocol == "udp":
            return  # counted on the server side, see _server_line
        self._add_bytes(iv.bytes)

    def _start_server(self) -> None:
        self._listening.clear()
        self._server = self._spawn(self.receiver, self._server_argv(), "server", self._server_line)
        deadline = time.monotonic() + 10
        while not self._listening.wait(0.1):
            if self._server.poll() is not None:
                raise RuntimeError(f"iperf3 server exited with status {self._server.returncode} "
                                   f"(see {self.w.id}.server.log)")
            if time.monotonic() > deadline or self._stop.is_set():
                raise RuntimeError("iperf3 server did not report listening within 10s")

    def _stop_server(self) -> None:
        if self._server is not None:
            self._terminate(self._server)
            self._forget(self._server)
            self._server = None

    def _prepare(self) -> None:
        self._start_server()

    def _run(self) -> None:
        w: Iperf3 = self.w  # type: ignore[assignment]
        first = True
        while not self._stop.is_set():
            if not first:
                if self._sleep(RESTART_BACKOFF):
                    return
                self._stop_server()
                self._start_server()
                self.restarts += 1
                self.m_restarts.inc()
            first = False
            client = self._spawn(self.sender, self._client_argv(), "client", self._client_line)
            while client.poll() is None and (self._server is None or self._server.poll() is None):
                if self._stop.wait(POLL_INTERVAL):
                    return
            server_died = self._server is not None and self._server.poll() is not None
            if client.poll() is None:  # server died first
                self._terminate(client)
            rc = client.returncode
            self._forget(client)
            if self._stop.is_set():
                return
            if rc == 0 and not server_died and w.duration:
                self.iterations += 1
                self.m_iter.inc()
                self._completed = True
                self._stop_server()
                return
            reason = ("iperf3 server exited" if server_died else f"iperf3 client exited with status {rc}")
            if w.role != "background":
                raise RuntimeError(reason)
            self._log("client", f"restarting both sides: {reason}")
        self._completed = True

    def _on_stop(self) -> None:
        self._stop_server()


# ---------------------------------------------------------------------------------------------
# ping
# ---------------------------------------------------------------------------------------------

class PingRunner(WorkloadRunner):
    def __init__(self, *a: Any, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self.m_rtt = self.metrics.ping_rtt.labels(**self._labels)
        self.m_sent = self.metrics.ping_sent.labels(**self._labels)
        self.m_recv = self.metrics.ping_received.labels(**self._labels)
        self.m_jitter = self.metrics.ping_jitter.labels(**self._labels)
        self.tracker = PingTracker()
        self._tlock = threading.Lock()
        self._tail: list[str] = []

    def _argv(self) -> list[str]:
        w: Ping = self.w  # type: ignore[assignment]
        return ["ping", "-D", "-i", f"{w.interval:g}", "-s", str(w.payload_size),
                "-I", self.src_ip, self.dst_ip]

    def _line(self, line: str) -> None:
        self._tail = (self._tail + [line])[-5:]
        with self._tlock:
            r = parse_ping_line(line)
            if r is not None:
                new_sent = self.tracker.update(r)
                if not r.duplicate:
                    self.m_recv.inc()
                    self.m_rtt.observe(r.rtt_seconds)
                    self.m_jitter.set(self.tracker.jitter)
                if new_sent:
                    self.m_sent.inc(new_sent)
                return
            s = parse_ping_summary(line)
            if s is not None:
                extra = self.tracker.sent_from_summary(s[0])
                if extra:
                    self.m_sent.inc(extra)

    def _run(self) -> None:
        proc = self._spawn(self.sender, self._argv(), "ping", self._line)
        while proc.poll() is None:
            if self._stop.wait(POLL_INTERVAL):
                self._terminate(proc)  # SIGTERM: ping prints its summary, picked up by the pump
                self._summarise()
                self._completed = True
                return
        t = getattr(proc, "_pump_thread", None)
        if t is not None:
            t.join(timeout=5)
        if self._stop.is_set():
            self._summarise()
            self._completed = True
        else:
            raise RuntimeError(f"ping exited with status {proc.returncode}: " + " | ".join(self._tail))

    def _summarise(self) -> None:
        tr = self.tracker
        n = len(tr.rtts)
        self.details.update(
            sent=tr.highest, received=tr.received,
            loss_ratio=(1 - tr.received / tr.highest) if tr.highest else 0.0,
            rtt_min=min(tr.rtts) if n else None, rtt_max=max(tr.rtts) if n else None,
            rtt_mean=(sum(tr.rtts) / n) if n else None, jitter=tr.jitter)

    def result(self) -> WorkloadResult:
        if self._state == RUNNING:
            self._summarise()
        return super().result()


def make_runner(workload: Workload, sender: Any, receiver: Any, metrics: RunnerMetrics,
                run_dir_on_sender: str, run_dir_on_receiver: str, run_id: str,
                reservation_bwlimit_bps: Optional[int], logs_dir: Path, *,
                index: int = 0) -> WorkloadRunner:
    """index: unique per run among file_copy workloads (rsync port 8730 + index)."""
    cls = {"file_copy": FileCopyRunner, "iperf3": Iperf3Runner, "ping": PingRunner}[workload.kind]
    return cls(workload, sender, receiver, metrics, run_dir_on_sender, run_dir_on_receiver, run_id,
               reservation_bwlimit_bps, logs_dir, index=index)
