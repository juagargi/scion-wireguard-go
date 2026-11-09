"""Tests for hosts.py: LocalHost for real, SSHHost against a fake ssh_orchestration, DockerHost's argv."""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import hosts  # noqa: E402
from hosts import DockerHost, HostError, LocalHost, SSHHost  # noqa: E402

SECRET = "s3cr3t-jwt-value"


def wait_until(cond, timeout=10.0):
    """Poll cond every few milliseconds until it holds."""
    deadline = time.monotonic() + timeout
    while not cond():
        if time.monotonic() > deadline:
            raise AssertionError("timed out waiting for the condition")
        time.sleep(0.005)


class LocalBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name
        self.host = LocalHost()

    def path(self, *p):
        return os.path.join(self.dir, *p)


class TestGuardScript(unittest.TestCase):
    """The Docker popen guard: the command lives while stdin is open and dies on EOF.
    (Regression: the watcher used to read /dev/null, the stdin of a background job, and killed the
    command at once.)"""

    def test_survives_while_stdin_is_open_and_dies_on_eof(self):
        proc = subprocess.Popen(hosts._bash(hosts._GUARD_SCRIPT, "bash", "-c", "echo up; exec sleep 30"),
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True)
        try:
            self.assertEqual(proc.stdout.readline().strip(), "up")
            time.sleep(0.2)  # the regression killed the command at once
            self.assertIsNone(proc.poll())
            proc.stdin.close()
            proc.wait(timeout=10)
        finally:
            if proc.poll() is None:
                proc.kill()
        self.assertNotEqual(proc.returncode, 0)


class TestLocalHost(LocalBase):
    def test_run_env_quoting_and_input(self):
        r = self.host.run(["bash", "-c", 'printf "%s|%s" "$V" "$1"', "x", "a b; $(touch /nonexistent)"],
                          env={"V": "q 'r' \"s\""})
        self.assertEqual(r.stdout, "q 'r' \"s\"|a b; $(touch /nonexistent)")
        self.assertEqual(self.host.run(["cat"], input="hello").stdout, "hello")
        self.assertEqual(self.host.run(["cat"], input=b"bytes").stdout, "bytes")

    def test_failure_is_host_error(self):
        with self.assertRaises(HostError) as cm:
            self.host.run(["bash", "-c", "echo boom >&2; exit 3"])
        self.assertEqual(cm.exception.status, 3)
        self.assertIn("boom", str(cm.exception))
        self.assertEqual(self.host.run(["false"], check=False).returncode, 1)

    def test_timeout(self):
        with self.assertRaises(HostError) as cm:
            self.host.run(["sleep", "5"], timeout=0.3)
        self.assertIsNone(cm.exception.status)

    def test_bad_env_name(self):
        with self.assertRaises(ValueError):
            self.host.run(["true"], env={"A B": "x"})

    def test_put_text_atomic_mode_and_parent(self):
        target = self.path("a", "b", "secret")
        self.host.put_text("tok\n", target, "600")
        self.assertEqual(oct(os.stat(target).st_mode & 0o777), "0o600")
        self.assertEqual(self.host.read_text(target), "tok\n")
        self.assertEqual(os.listdir(self.path("a", "b")), ["secret"])  # no temporary left
        with self.assertRaises(ValueError):
            self.host.put_text("x", target, "6; rm")

    def test_put_get_path(self):
        src = Path(self.path("src.bin"))
        src.write_bytes(bytes(range(256)))
        self.host.put_file(src, self.path("d", "dst.bin"), "640")
        self.assertTrue(self.host.path_exists(self.path("d", "dst.bin")))
        self.assertFalse(self.host.path_exists(self.path("d", "nope")))
        self.host.get_file(self.path("d", "dst.bin"), Path(self.path("back", "x.bin")))
        self.assertEqual(Path(self.path("back", "x.bin")).read_bytes(), bytes(range(256)))

    def test_popen_terminates(self):
        p = self.host.popen(["bash", "-c", "echo up; exec sleep 30"])
        self.assertEqual(p.stdout.readline().strip(), "up")
        p.terminate()
        self.assertIsNotNone(p.wait(5))
        p.stdout.close()
        p.stdin.close()

    def test_daemon_lifecycle_with_secret_file(self):
        secret = self.path("jwt")
        self.host.put_text(SECRET + "\n", secret, "600")
        pid_path, log = self.path("run", "d.pid"), self.path("run", "d.log")
        pid = self.host.start_daemon(
            ["bash", "-c", 'echo "T=$T A=$A"; exec sleep 30'], env={"A": "x y;z"},
            env_from_files={"T": secret}, log_path=log, pid_path=pid_path)
        self.addCleanup(self.host.stop_daemon, pid_path)
        self.assertEqual(int(Path(pid_path).read_text()), pid)
        self.assertTrue(self.host.daemon_alive(pid_path))
        wait_until(lambda: Path(log).read_text())
        self.assertEqual(Path(log).read_text().strip(), f"T={SECRET} A=x y;z")
        # The secret is in neither the command line of the daemon nor of anything we started.
        self.assertNotIn(SECRET, Path(f"/proc/{pid}/cmdline").read_text())
        self.assertTrue(self.host.stop_daemon(pid_path))
        self.assertFalse(self.host.daemon_alive(pid_path))
        self.assertFalse(Path(pid_path).exists())
        self.assertFalse(self.host.stop_daemon(pid_path))

    def test_start_waits_for_a_slow_pid(self):
        """A host whose disk stalls for seconds (SCIERA's ufes) records the pid late: the
        start waits up to START_PID_WAIT for it."""
        slow = self.path("slow-bin")
        os.makedirs(slow)
        wrapper = Path(slow, "setsid")
        wrapper.write_text(f"#!/bin/bash\nsleep 1.5\nexec {shutil.which('setsid')} \"$@\"\n")
        wrapper.chmod(0o755)
        env = {"PATH": f"{slow}:{os.environ['PATH']}"}
        pid_path, log = self.path("s.pid"), self.path("s.log")

        with mock.patch.object(hosts, "START_PID_WAIT", 1):
            with self.assertRaisesRegex(hosts.HostError, "within 1s"):
                self.host.start_daemon(["sleep", "5"], env=env, log_path=log, pid_path=pid_path)
        wait_until(lambda: Path(pid_path).exists())  # the late daemon: stop it
        self.host.stop_daemon(pid_path)

        with mock.patch.object(hosts, "START_PID_WAIT", 5):
            pid = self.host.start_daemon(["sleep", "30"], env=env, log_path=log, pid_path=pid_path)
        self.addCleanup(self.host.stop_daemon, pid_path)
        self.assertEqual(int(Path(pid_path).read_text()), pid)
        self.assertTrue(self.host.daemon_alive(pid_path))

    def test_stop_ignores_garbage_pidfile(self):
        Path(self.path("p.pid")).write_text("not a pid\n")
        self.assertFalse(self.host.stop_daemon(self.path("p.pid")))
        self.assertFalse(Path(self.path("p.pid")).exists())

    def test_stop_kills_a_term_ignoring_daemon(self):
        pid_path = self.path("t.pid")
        log = self.path("t.log")
        self.host.start_daemon(["bash", "-c", "trap '' TERM; echo ready; while :; do sleep 0.1; done"],
                               env=None, log_path=log, pid_path=pid_path)
        wait_until(lambda: Path(log).read_text())  # the trap is in place
        self.assertTrue(self.host.stop_daemon(pid_path, timeout=0.2))
        self.assertFalse(self.host.daemon_alive(pid_path))

    def test_start_script_input_quotes(self):
        text = hosts.start_script_input({"A": "it's $(x)"}, {"T": "/p q/jwt"})
        self.assertEqual(text.splitlines(), ["A='it'\"'\"'s $(x)'", "T=$(cat -- '/p q/jwt')"])
        with self.assertRaises(ValueError):
            hosts.start_script_input({"1X": "v"}, None)


class FakeOrchestration:
    """Stands in for hummbwtester's ssh_orchestration: runs the `sh -c` command locally and records it."""

    SSH_OPTIONS = ["-o", "LogLevel=ERROR"]

    def __init__(self, execute=True):
        self.commands, self.inputs, self.copied, self.execute = [], [], [], execute

    def ssh_command(self, host, command, *, check=True, **kwargs):
        self.commands.append(command)
        self.inputs.append(kwargs.get("input"))
        if not self.execute:
            return subprocess.CompletedProcess(command, 0, "", "")
        kwargs.setdefault("stdin", subprocess.DEVNULL) if "input" not in kwargs else None
        return subprocess.run(["sh", "-c", command], text=True, **kwargs)

    def scp_to(self, host, local, remote):
        self.copied.append((str(local), remote))
        subprocess.run(["cp", str(local), remote], check=True)


def fake_ssh_host(**kw):
    return types.SimpleNamespace(name="ufms", alias="ufms-alias", sciond="127.0.0.1:30255",
                                 run_dir="/tmp/wgexp", **kw)


class TestSSHHost(LocalBase):
    def setUp(self):
        super().setUp()
        self.orch = FakeOrchestration()
        self.host = SSHHost(fake_ssh_host(), orchestration=self.orch)

    def test_protocol_basics(self):
        self.assertEqual((self.host.kind, self.host.name), ("ssh", "ufms"))
        self.assertEqual(self.host.address(), "127.0.0.1")
        self.assertEqual(SSHHost(fake_ssh_host(), orchestration=self.orch, address="10.1.2.3").address(),
                         "10.1.2.3")
        self.assertEqual(self.host.sciond_address(), "127.0.0.1:30255")

    def test_command_construction(self):
        orch = FakeOrchestration(execute=False)
        host = SSHHost(fake_ssh_host(), orchestration=orch)
        host.run(["ip", "addr", "add", "10.0.0.1/24; reboot"], root=True, env={"A": "b c"})
        self.assertEqual(orch.commands[-1],
                         "sudo -n env 'A=b c' ip addr add '10.0.0.1/24; reboot'")
        host.run(["echo", "$(id)"])
        self.assertEqual(orch.commands[-1], "echo '$(id)'")

    def test_run_executes_and_reports(self):
        self.assertEqual(self.host.run(["printf", "%s", "a b"]).stdout, "a b")
        with self.assertRaises(HostError):
            self.host.run(["false"])

    def test_files(self):
        target = self.path("x", "y.txt")
        self.host.put_text("data", target, "600")
        self.assertEqual(oct(os.stat(target).st_mode & 0o777), "0o600")
        src = Path(self.path("s"))
        src.write_text("file")
        self.host.put_file(src, self.path("x", "z.txt"), "755")
        self.assertEqual(oct(os.stat(self.path("x", "z.txt")).st_mode & 0o777), "0o755")
        self.assertEqual(sorted(os.listdir(self.path("x"))), ["y.txt", "z.txt"])
        self.assertTrue(self.host.path_exists(target))

    def test_secrets_never_in_the_command(self):
        secret = self.path("jwt")
        self.host.put_text(SECRET, secret, "600")
        pid_path = self.path("r", "p.pid")
        pid = self.host.start_daemon(["bash", "-c", 'echo "$T $U"; exec sleep 30'],
                                     env={"U": SECRET + "-direct"}, env_from_files={"T": secret},
                                     log_path=self.path("r", "l.log"), pid_path=pid_path, root=False)
        self.addCleanup(self.host.stop_daemon, pid_path)
        self.assertGreater(pid, 0)
        # The JWT file's content and the env values only ever travelled on stdin.
        for command in self.orch.commands:
            self.assertNotIn(SECRET, command)
        self.assertTrue(any(SECRET in (i or "") for i in self.orch.inputs))
        wait_until(lambda: SECRET in Path(self.path("r", "l.log")).read_text())

    def test_root_prefix_for_daemon_commands(self):
        orch = FakeOrchestration(execute=False)
        host = SSHHost(fake_ssh_host(), orchestration=orch)
        host.daemon_alive("/p.pid", root=True)
        self.assertTrue(orch.commands[-1].startswith("sudo -n bash -c "))

    def test_popen_uses_tt_and_exec(self):
        with mock.patch.object(hosts.subprocess, "Popen") as popen:
            self.host.popen(["ping", "-c", "1", "10.0.0.2"], root=True)
        argv = popen.call_args.args[0]
        self.assertEqual(argv[:4], ["ssh", "-o", "LogLevel=ERROR", "-tt"])
        self.assertEqual(argv[4:7], ["--", "ufms-alias", "sh -c 'exec sudo -n ping -c 1 10.0.0.2'"])

    def test_import_failure_is_explained(self):
        hosts._SCION_DIR = None
        with self.assertRaises(HostError) as cm:
            SSHHost(fake_ssh_host())
        self.assertIn("configure", str(cm.exception))


class TestDockerHost(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        gen = Path(self.tmp.name, "gen")
        gen.mkdir()
        (gen / "scion-dc.yml").write_text("name: scion\n")
        self.host = DockerHost(Path(self.tmp.name), "1-ff00:0:112")

    def test_names(self):
        self.assertEqual(self.host.name, "tester_1-ff00_0_112")
        self.assertEqual(self.host.kind, "docker")
        self.assertEqual(hosts.tester_service("1-ff00:0:110"), "tester_1-ff00_0_110")

    def test_missing_compose_file(self):
        with self.assertRaises(HostError):
            DockerHost(Path(self.tmp.name, "nope"), "1-ff00:0:112")

    def test_argv(self):
        captured = {}

        def fake_run(argv, **kw):
            captured["argv"], captured["kw"] = argv, kw
            return subprocess.CompletedProcess(argv, 0, "out", 'time="x" level=warning msg="version obsolete"\nreal\n')

        with mock.patch.object(hosts.subprocess, "run", fake_run):
            r = self.host.run(["echo", "a b"], env={"K": "v w"}, root=True)
        compose = str(Path(self.tmp.name, "gen", "scion-dc.yml"))
        self.assertEqual(captured["argv"], ["docker", "compose", "-f", compose, "exec", "-T", "-e", "K=v w",
                                            "tester_1-ff00_0_112", "echo", "a b"])
        self.assertEqual(r.stderr, "real\n")  # compose's obsolete-version warning is dropped

    def test_daemon_secrets_not_in_argv(self):
        calls = []

        def fake_run(argv, **kw):
            calls.append((argv, kw))
            return subprocess.CompletedProcess(argv, 0, "123\n", "")

        with mock.patch.object(hosts.subprocess, "run", fake_run):
            pid = self.host.start_daemon(["/share/bin/wireguard-go", "-f", "wgx-ab"], env={"X": SECRET},
                                         env_from_files={"SCION_MARKETPLACE_JWT": "/tmp/wgexp/jwt"},
                                         log_path="/tmp/l", pid_path="/tmp/p")
        self.assertEqual(pid, 123)
        argv, kw = calls[0]
        self.assertNotIn(SECRET, " ".join(argv))
        self.assertIn(SECRET, kw["input"])
        self.assertIn("SCION_MARKETPLACE_JWT=$(cat -- /tmp/wgexp/jwt)", kw["input"])

    def test_popen_is_guarded(self):
        with mock.patch.object(hosts.subprocess, "Popen") as popen:
            self.host.popen(["iperf3", "-s"])
        argv = popen.call_args.args[0]
        self.assertEqual(argv[argv.index("tester_1-ff00_0_112") + 1:][:3], ["bash", "-c", hosts._GUARD_SCRIPT])
        self.assertEqual(argv[-2:], ["iperf3", "-s"])
        self.assertEqual(popen.call_args.kwargs["stdin"], subprocess.PIPE)

    def test_address_checks_the_as(self):
        def fake_run(argv, **kw):
            return subprocess.CompletedProcess(argv, 0, "1-ff00:0:999,fd00::1\n", "")

        with mock.patch.object(hosts.subprocess, "run", fake_run):
            with self.assertRaises(HostError):
                self.host.address()

        def ok(argv, **kw):
            return subprocess.CompletedProcess(argv, 0, "1-ff00:0:112,fd00:f00d:cafe::7f00:15\n", "")

        with mock.patch.object(hosts.subprocess, "run", ok):
            self.assertEqual(self.host.address(), "fd00:f00d:cafe::7f00:15")


if __name__ == "__main__":
    unittest.main()
