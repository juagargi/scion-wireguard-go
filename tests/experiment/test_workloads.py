import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

import workloads as wl  # noqa: E402
from config import FileCopy, Iperf3, Ping  # noqa: E402
from runner_metrics import make_runner_registry  # noqa: E402

# Real rsync 3.4.1 --info=progress2 output (CR separated).
RSYNC_OUT = ("\r         32,768   1%    0.00kB/s    0:00:00  \r      1,081,344  36%  1000.00kB/s    0:00:01  "
             "\r      3,000,000 100%    1.00MB/s    0:00:02 (xfr#1, to-chk=0/1)\n")

IPERF_UDP_CLIENT = """\
Connecting to host 10.0.0.2, port 5201
[  5] local 10.0.0.1 port 40000 connected to 10.0.0.2 port 5201
[ ID] Interval           Transfer     Bitrate         Total Datagrams
[  5]   0.00-1.00   sec   611 KBytes  5.00 Mbits/sec  695
[  5]   1.00-2.00   sec   611 KBytes  5.00 Mbits/sec  695
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-2.00   sec  1.19 MBytes  5.00 Mbits/sec  0.000 ms  0/1390 (0%)  sender
[  5]   0.00-2.00   sec  1.19 MBytes  5.00 Mbits/sec  0.014 ms  0/1390 (0%)  receiver
"""
IPERF_UDP_SERVER = """\
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-1.00   sec   611 KBytes  5.00 Mbits/sec  0.014 ms  3/695 (0.43%)  
[  5]   1.00-2.00   sec   611 KBytes  4.99 Mbits/sec  0.018 ms  0/695 (0%)  
"""
IPERF_TCP_CLIENT = "[  5]   0.00-1.00   sec  1.20 GBytes  10.3 Gbits/sec    0   3.22 MBytes       \n"
PING_OUT = """\
PING 10.0.0.2 (10.0.0.2) from 10.0.0.1 : 56(84) bytes of data.
[1793803811.957219] 64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=10.0 ms
[1793803812.163542] 64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=12.0 ms
[1793803812.571519] 64 bytes from 10.0.0.2: icmp_seq=4 ttl=64 time=12.0 ms
[1793803812.771519] 64 bytes from 10.0.0.2: icmp_seq=4 ttl=64 time=15.0 ms (DUP!)
--- 10.0.0.2 ping statistics ---
5 packets transmitted, 3 received, 40% packet loss, time 814ms
"""


class ParserTest(unittest.TestCase):
    def test_rsync(self):
        vals = [wl.parse_rsync_progress(c) for c in wl.split_progress_chunks(RSYNC_OUT)]
        self.assertEqual(vals, [32768, 1081344, 3000000])
        self.assertIsNone(wl.parse_rsync_progress("sending incremental file list"))
        self.assertEqual(wl.parse_rsync_progress("  1.50M  10%  1.00MB/s  0:00:01"), int(1.5 * 1048576))

    def test_bwlimit(self):
        self.assertEqual(wl.rsync_bwlimit_arg(20_000_000), "--bwlimit=2441.406K")

    def test_iperf_client_udp(self):
        ivs = [wl.parse_iperf3_line(l) for l in IPERF_UDP_CLIENT.splitlines()]
        ivs = [i for i in ivs if i]
        self.assertEqual([i.summary for i in ivs], [False, False, True, True])
        self.assertEqual(ivs[0].datagrams, 695)
        self.assertEqual(ivs[0].bytes, 611 * 1024)
        self.assertAlmostEqual(ivs[0].bits_per_second, 5e6)
        self.assertEqual(ivs[3].total, 1390)

    def test_iperf_server_udp(self):
        ivs = [i for i in map(wl.parse_iperf3_line, IPERF_UDP_SERVER.splitlines()) if i]
        self.assertEqual([(i.lost, i.total) for i in ivs], [(3, 695), (0, 695)])
        self.assertAlmostEqual(ivs[0].jitter_ms, 0.014)

    def test_iperf_tcp_and_sum(self):
        i = wl.parse_iperf3_line(IPERF_TCP_CLIENT)
        self.assertEqual(i.bytes, int(round(1.2 * 1024 ** 3)))
        self.assertIsNone(i.datagrams)
        s = wl.parse_iperf3_line("[SUM]   0.00-1.00   sec  2.00 MBytes  16.8 Mbits/sec  12")
        self.assertEqual(s.stream, "SUM")
        self.assertIsNone(wl.parse_iperf3_line("iperf3: error - unable to connect"))

    def test_ping(self):
        tr, sent = wl.PingTracker(), 0
        for line in PING_OUT.splitlines():
            r = wl.parse_ping_line(line)
            if r:
                sent += tr.update(r)
        self.assertEqual(sent, 4)  # seq 4 seen: 3 lost in between counted as sent
        self.assertEqual(tr.received, 3)  # the DUP does not count
        j = 0.002 / 16
        self.assertAlmostEqual(tr.jitter, j - j / 16)
        self.assertEqual(tr.sent_from_summary(5), 1)
        self.assertEqual(wl.parse_ping_summary(PING_OUT.splitlines()[-1]), (5, 3))
        r = wl.parse_ping_line(PING_OUT.splitlines()[1])
        self.assertEqual((r.seq, r.rtt_seconds, r.duplicate), (1, 0.01, False))

    def test_ping_wrap(self):
        tr = wl.PingTracker()
        total = 0
        for seq in (65534, 65535, 1, 2):
            total += tr.update(wl.PingReply(0.0, seq, 0.001, False))
        self.assertEqual(tr.highest, 65536 + 2)


class FakeHost:
    """A Host on this machine, built on subprocess."""
    name, kind = "local", "docker"

    def run(self, argv, *, check=True, timeout=None, env=None, input=None, root=False):
        p = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, input=input)
        if check and p.returncode != 0:
            raise RuntimeError(f"{argv} -> {p.returncode}: {p.stderr}")
        return p

    def popen(self, argv, *, env=None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, root=False):
        return subprocess.Popen(list(argv), stdout=stdout, stderr=stderr, text=True,
                                stdin=subprocess.DEVNULL)

    def start_daemon(self, argv, *, env, log_path, pid_path, root=False):
        with open(log_path, "w") as log:
            p = subprocess.Popen(list(argv), stdout=log, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, start_new_session=True)
        Path(pid_path).write_text(str(p.pid))
        return p.pid

    def stop_daemon(self, pid_path, *, timeout=5.0, root=False):
        try:
            pid = int(Path(pid_path).read_text())
        except OSError:
            return False
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return False
        time.sleep(0.3)
        Path(pid_path).unlink(missing_ok=True)
        return True

    def put_text(self, text, remote, mode="644"):
        Path(remote).write_text(text)


def endpoints():
    a = SimpleNamespace(name="A", tunnel_ip="127.0.0.1")
    b = SimpleNamespace(name="B", tunnel_ip="127.0.0.1")
    return SimpleNamespace(id="t1", mtu=1000, endpoints=(a, b))


def common(kind, wid, role, **kw):
    return dict(id=wid, kind=kind, from_="A", to="B", role=role, start_delay=0.0,
                timeout=kw.pop("timeout", None), tunnel=endpoints())


def have(*tools):
    return all(shutil.which(t) for t in tools)


class RunnerCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wgexp-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.metrics = make_runner_registry("r", "s", "e")
        self.runners = []
        self.addCleanup(lambda: [r.cleanup() for r in self.runners])

    def make(self, w, index=0, reservation=None):
        h = FakeHost()
        sd, rd = f"{self.tmp}/s", f"{self.tmp}/r"
        os.makedirs(sd, exist_ok=True)
        os.makedirs(rd, exist_ok=True)
        r = wl.make_runner(w, h, h, self.metrics, sd, rd, "r", reservation, Path(self.tmp) / "logs",
                           index=index)
        self.runners.append(r)
        return r


@unittest.skipUnless(have("rsync", "dd", "sha256sum"), "rsync/dd/sha256sum missing")
class FileCopyTest(RunnerCase):
    def fc(self, **kw):
        base = common("file_copy", "fc1", kw.pop("role", "primary"), timeout=kw.pop("timeout", None))
        args = dict(size="2500KiB", size_bytes=2500 * 1024 + 123, verify=True, repeat=2,
                    bwlimit="none", bwlimit_bps=None, keep_files=False)
        args.update(kw)
        return FileCopy(**base, **args)

    def test_two_iterations_with_remainder(self):
        r = self.make(self.fc(), index=21)
        r.prepare()
        self.assertEqual(os.path.getsize(f"{self.tmp}/s/fc1/payload.bin"), 2500 * 1024 + 123)
        r.start()
        self.assertEqual(r.wait(60), "passed", r.result().error)
        res = r.result()
        self.assertEqual(res.iterations, 2)
        self.assertEqual(res.bytes, 2 * (2500 * 1024 + 123))
        self.assertEqual(res.details["sha256_sender"], res.details["sha256_receiver"])
        self.assertIn('result="ok"} 2\n', self.metrics.registry.render())
        r.cleanup()
        self.assertFalse(os.path.exists(f"{self.tmp}/r/fc1"))

    def test_bwlimit_and_timeout(self):
        # 1 Mbps limit on ~2.5 MB: far longer than the 2 s timeout
        r = self.make(self.fc(bwlimit="1mbps", bwlimit_bps=1_000_000, timeout=2.0, repeat=1), index=22)
        self.assertEqual(r.bwlimit_bps, 1_000_000)
        r.prepare()
        r.start()
        self.assertEqual(r.wait(30), "failed")
        self.assertIn("timed out", r.result().error)

    def test_reservation_limit(self):
        r = self.make(self.fc(bwlimit="reservation"), index=23, reservation=10_000_000)
        self.assertEqual(r.bwlimit_bps, int(10_000_000 * wl.PAYLOAD_EFFICIENCY))
        with self.assertRaises(ValueError):
            self.make(self.fc(bwlimit="reservation"), index=24, reservation=None)

    def test_background_until_stopped(self):
        r = self.make(self.fc(role="background", repeat=0, size="1MiB", size_bytes=1 << 20), index=25)
        r.prepare()
        r.start()
        time.sleep(1.5)
        self.assertEqual(r.poll(), "running")
        r.stop()
        r.stop()
        self.assertEqual(r.poll(), "passed")
        self.assertGreaterEqual(r.result().iterations, 1)


@unittest.skipUnless(have("ping"), "ping missing")
class PingTest(RunnerCase):
    def test_ping_loopback(self):
        r = self.make(Ping(**common("ping", "p1", "background"), interval=0.2, payload_size=32))
        r.prepare()
        r.start()
        time.sleep(2.2)
        r.stop()
        res = r.result()
        self.assertEqual(res.state, "passed", res.error)
        self.assertGreaterEqual(res.details["received"], 5)
        self.assertEqual(res.details["sent"], res.details["received"])
        text = self.metrics.registry.render()
        self.assertIn("wgexp_ping_rtt_seconds_count{", text)
        self.assertIn("wgexp_ping_sent_total{", text)
        self.assertIn('le="+Inf"', text)


@unittest.skipUnless(have("iperf3"), "iperf3 missing")
class Iperf3Test(RunnerCase):
    def ip(self, **kw):
        args = dict(protocol="udp", bandwidth="4mbps", bandwidth_bps=4_000_000, length=900,
                    duration=3.0, parallel=1, server_port=5391)
        args.update(kw)
        return Iperf3(**common("iperf3", "ip1", args.pop("role", "primary")), **args)

    def test_primary_udp(self):
        r = self.make(self.ip())
        r.prepare()
        r.start()
        self.assertEqual(r.wait(30), "passed", r.result().error)
        res = r.result()
        self.assertGreater(res.bytes, 1_000_000)
        self.assertGreater(res.details["datagrams"], 1000)
        self.assertIn("wgexp_iperf3_datagrams_total{", self.metrics.registry.render())

    def test_background_restart(self):
        r = self.make(self.ip(role="background", duration=None, server_port=5392))
        r.prepare()
        r.start()
        time.sleep(1.5)
        # kill the server: both sides must be restarted
        for p in list(r._procs):
            if "-s" in p.args:
                p.kill()
        time.sleep(wl.RESTART_BACKOFF + 3)
        self.assertEqual(r.poll(), "running")
        self.assertGreaterEqual(r.restarts, 1)
        r.stop()
        self.assertEqual(r.poll(), "passed")


if __name__ == "__main__":
    unittest.main()
