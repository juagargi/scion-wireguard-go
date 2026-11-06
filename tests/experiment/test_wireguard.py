"""Tests for wireguard.py with fake hosts: env, UAPI text, keys, log parsing, readiness, cleanup."""

import subprocess
import sys
import unittest
from unittest import mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import config  # noqa: E402
import wireguard as wg  # noqa: E402
from hosts import HostError, LocalHost  # noqa: E402
from wireguard import WireguardError, WireguardInstance  # noqa: E402

DOCKER = HERE / "experiment-docker.json"
JWT = "/tmp/wgexp/setup/marketplace.jwt"


class FakeHost:
    """Records every call; `answers` maps a predicate on argv to a CompletedProcess result."""

    kind = "fake"

    def __init__(self, name="tester", address="fd00::15"):
        self.name = name
        self._address = address
        self.calls, self.daemons, self.files, self.alive_state = [], [], {}, True
        self.responders = []  # (predicate(argv), stdout, returncode)
        self.stopped = []

    def run(self, argv, *, check=True, timeout=None, env=None, input=None, root=False):
        argv = list(argv)
        self.calls.append((argv, input, root))
        for pred, out, rc in self.responders:
            if pred(argv, input):
                r = subprocess.CompletedProcess(argv, rc, out, "")
                if check and rc != 0:
                    raise HostError(self.name, argv, rc, "")
                return r
        if argv[:3] == ["ip", "link", "show"]:  # no such device, unless a responder says otherwise
            return subprocess.CompletedProcess(argv, 1, "", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    def start_daemon(self, argv, *, env, log_path, pid_path, root=False, env_from_files=None):
        self.daemons.append(dict(argv=list(argv), env=dict(env), log=log_path, pid=pid_path,
                                 root=root, files=dict(env_from_files or {})))
        return 4242

    def daemon_alive(self, pid_path, *, root=False):
        return self.alive_state

    def stop_daemon(self, pid_path, *, timeout=5.0, root=False):
        self.stopped.append(pid_path)
        return True

    def path_exists(self, remote):
        return remote in self.files

    def read_text(self, remote):
        if remote not in self.files:
            raise HostError(self.name, ["cat", remote], 1, "no such file")
        return self.files[remote]

    def address(self):
        return self._address

    def sciond_address(self):
        return "[fd00::14]:30255"


def instance(name="QoS1", host=None, jwt=JWT, mutate=None, experiment=None):
    exp = experiment or config.load_config(DOCKER)
    ep = exp.endpoint(name)
    return WireguardInstance(exp, ep, host or FakeHost(), "/share/bin/wireguard-go", "/tmp/wgexp",
                             "run1", jwt, "[fd00::14]:30255")


def uapi_ok(argv, input):
    return argv[:1] in (["perl"], ["socat"], ["nc"])


class TestKeys(unittest.TestCase):
    def test_rfc7748_vector(self):
        # RFC 7748 section 6.1, Alice.
        private = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        self.assertEqual(wg.public_key(private),
                         "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

    def test_generated_pairs(self):
        a, b = wg.generate_keypair(), wg.generate_keypair()
        self.assertNotEqual(a, b)
        for private, public in (a, b):
            self.assertEqual((len(private), len(public)), (64, 64))
            self.assertEqual(wg.public_key(private), public)


class TestEnv(unittest.TestCase):
    def test_sender_env_in_order(self):
        inst = instance("QoS1")
        env = inst.env()
        self.assertEqual(list(env)[:8], ["USE_SCION", "USE_BATCH", "LOG_LEVEL", "WG_PROCESS_FOREGROUND",
                                         "WG_UAPI_DIR", "SCION_DAEMON_ADDRESS", "SCION_LOCAL_IA",
                                         "SCION_PATH_API_ADDRESS"])
        self.assertEqual(env["WG_UAPI_DIR"], "/tmp/wgexp/uapi")
        self.assertEqual(env["USE_SCION"], "1")
        self.assertEqual(env["USE_BATCH"], "1")
        self.assertEqual(env["LOG_LEVEL"], "verbose")
        self.assertEqual(env["WG_PROCESS_FOREGROUND"], "1")
        self.assertEqual(env["SCION_DAEMON_ADDRESS"], "[fd00::14]:30255")
        self.assertEqual(env["SCION_LOCAL_IA"], "1-ff00:0:111,fd00::15")
        self.assertEqual(env["SCION_PATH_API_ADDRESS"], "0.0.0.0:28015")
        self.assertEqual(env["HUMMINGBIRD_BANDWIDTH"], "20mbps")
        self.assertEqual(env["HUMMINGBIRD_MARKETPLACE_INSECURE"], "1")
        self.assertNotIn("SCION_MARKETPLACE_JWT", env)
        self.assertNotIn("HUMMINGBIRD_MARKETPLACE_ADDRESS", env)

    def test_receiver_has_no_hummingbird(self):
        env = instance("QoS2").env()
        self.assertFalse([k for k in env if k.startswith("HUMMINGBIRD")])

    def test_use_batch_false_policy_and_override_last(self):
        raw = config.json.loads(DOCKER.read_text())
        raw["tunnels"][0]["use_batch"] = False
        ep = raw["tunnels"][0]["endpoints"][0]
        ep["path_policy"] = "policy.json"
        ep["env"] = {"LOG_LEVEL": "debug", "EXTRA": "1"}
        raw["hummingbird"]["marketplace"].update(location_override=True, scion_address="[1-ff00:0:111,127.0.0.1]:8080")
        exp = config.parse_config(raw, Path("x.json"))
        env = instance("QoS1", experiment=exp).env()
        self.assertEqual(env["USE_BATCH"], "0")
        self.assertEqual(env["SCION_PATH_POLICY"], "policy.json")
        self.assertEqual(env["LOG_LEVEL"], "debug")  # endpoint.env overrides everything
        self.assertEqual(list(env)[-1], "EXTRA")
        self.assertEqual(env["HUMMINGBIRD_MARKETPLACE_ADDRESS"], "[1-ff00:0:111,127.0.0.1]:8080")

    def test_configured_host_wins_over_discovered(self):
        raw = config.json.loads(DOCKER.read_text())
        raw["tunnels"][0]["endpoints"][0]["host"] = "10.9.9.9"
        exp = config.parse_config(raw, Path("x.json"))
        self.assertEqual(instance("QoS1", experiment=exp).env()["SCION_LOCAL_IA"], "1-ff00:0:111,10.9.9.9")


class TestStart(unittest.TestCase):
    def test_start_passes_jwt_by_file_not_value(self):
        host = FakeHost()
        inst = instance("QoS1", host)
        self.assertEqual(inst.start(), 4242)
        d = host.daemons[0]
        self.assertEqual(d["argv"], ["/share/bin/wireguard-go", "-f", "wgx-ab"])
        self.assertEqual(d["files"], {"SCION_MARKETPLACE_JWT": JWT})
        self.assertNotIn("SCION_MARKETPLACE_JWT", d["env"])
        self.assertFalse(d["root"])  # the binary carries cap_net_admin; only `ip` needs root
        self.assertEqual(d["log"], "/tmp/wgexp/runs/run1/wg-QoS1.log")
        self.assertEqual(d["pid"], "/tmp/wgexp/runs/run1/wg-QoS1.pid")

    def test_receiver_takes_no_jwt(self):
        host = FakeHost()
        instance("QoS2", host, jwt=None).start()
        self.assertEqual(host.daemons[0]["files"], {})

    def test_sender_without_jwt_fails(self):
        with self.assertRaises(WireguardError):
            instance("QoS1", FakeHost(), jwt=None).start()

    def test_refuses_an_existing_interface(self):
        host = FakeHost()
        host.responders.append((lambda a, i: a[:3] == ["ip", "link", "show"], "", 0))
        with self.assertRaises(WireguardError) as cm:
            instance("QoS1", host).start()
        self.assertIn("wgx-ab", str(cm.exception))
        self.assertFalse(host.daemons)
        # Not-existing: ip link show fails.
        host = FakeHost()
        host.responders.append((lambda a, i: a[:3] == ["ip", "link", "show"], "", 1))
        instance("QoS1", host).start()
        self.assertEqual(len(host.daemons), 1)


class TestUapi(unittest.TestCase):
    def test_peer_transaction_text(self):
        text = wg.peer_transaction("PRIV", 32000, "PUB", "10.78.0.2", "1-ff00:0:112", "fd00::7f00:15",
                                   32000, 25)
        self.assertEqual(text, "set=1\nprivate_key=PRIV\nlisten_port=32000\npublic_key=PUB\n"
                               "allowed_ip=10.78.0.2/32\n"
                               "scion_endpoint=1-ff00:0:112,[fd00::7f00:15]:32000\n"
                               "persistent_keepalive_interval=25\n\n")

    def test_configure_sends_peer_values(self):
        host = FakeHost()
        inst = instance("QoS1", host)
        sent = []
        inst.uapi = lambda request: sent.append(request) or "errno=0\n\n"
        inst.configure("PEERPUB", "fd00::7f00:15")
        req = sent[0]
        self.assertIn(f"private_key={inst.private_key}", req)
        self.assertIn("listen_port=32000", req)
        self.assertIn("public_key=PEERPUB", req)
        self.assertIn("allowed_ip=10.78.0.2/32", req)  # QoS2's tunnel ip
        self.assertIn("scion_endpoint=1-ff00:0:112,[fd00::7f00:15]:32000", req)

    def test_configure_retries_while_the_daemon_has_no_path(self):
        host = FakeHost()
        inst = instance("QoS1", host)
        answers = [WireguardError("errno=-55: failed to get path for IA 1-ff00:0:112: no path found"),
                   "errno=0\n\n"]
        sent = []

        def uapi(request):
            sent.append(request)
            answer = answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer
        inst.uapi = uapi
        refreshed = []
        inst.refresh_paths = lambda: refreshed.append(True)
        with mock.patch.object(wg, "NO_PATH_RETRY_INTERVAL", 0):
            inst.configure("PEERPUB", "fd00::7f00:15")
        self.assertEqual(len(sent), 2)
        self.assertEqual(sent[0], sent[1])
        self.assertEqual(refreshed, [True])

    def test_configure_does_not_retry_other_errors(self):
        inst = instance("QoS1", FakeHost())
        sent = []

        def uapi(request):
            sent.append(request)
            raise WireguardError("errno=-22: invalid key")
        inst.uapi = uapi
        with self.assertRaises(WireguardError):
            inst.configure("PEERPUB", "fd00::7f00:15")
        self.assertEqual(len(sent), 1)

    def test_configure_needs_a_peer_host(self):
        with self.assertRaises(WireguardError):
            instance("QoS1").configure("PUB")

    def test_uapi_errno_and_redaction(self):
        host = FakeHost()
        host.responders = [
            (lambda a, i: a[0] == "bash", "perl\n", 0),
            (lambda a, i: a[0] == "perl", "errno=22\n\n", 0),
        ]
        inst = instance("QoS1", host)
        with self.assertRaises(WireguardError) as cm:
            inst.uapi("set=1\nprivate_key=SUPERSECRET\n\n")
        self.assertIn("errno=22", str(cm.exception))
        self.assertNotIn("SUPERSECRET", str(cm.exception))
        self.assertIn("<redacted>", str(cm.exception))

    def test_uapi_ok_and_client_probe_is_kept(self):
        host = FakeHost()
        host.responders = [
            (lambda a, i: a[0] == "bash", "perl\n", 0),
            (lambda a, i: a[0] == "perl", "public_key=ab\nerrno=0\n\n", 0),
        ]
        inst = instance("QoS1", host)
        self.assertIn("errno=0", inst.uapi("get=1\n\n"))
        inst.uapi("get=1\n\n")
        self.assertEqual(sum(1 for c in host.calls if c[0][0] == "bash"), 1)
        perl = [c for c in host.calls if c[0][0] == "perl"][0]
        self.assertEqual(perl[0][-1], "/tmp/wgexp/uapi/wgx-ab.sock")
        self.assertFalse(perl[2])  # the socket belongs to the user

    def test_no_uapi_tool(self):
        with self.assertRaises(WireguardError):
            instance("QoS1").uapi("get=1\n\n")

    def test_path_filter_read_back(self):
        inst = instance("QoS1")
        filt = inst.endpoint.path_filter
        replies = ["errno=0\n\n", f"x=1\nscion_path_filter=1-ff00:0:112 {filt}\nerrno=0\n\n"]
        sent = []
        inst.uapi = lambda r: sent.append(r) or replies.pop(0)
        self.assertTrue(inst.set_path_filter())
        self.assertEqual(sent[0], f"set=1\nscion_path_filter=1-ff00:0:112 {filt}\n\n")
        inst.uapi = lambda r: "errno=0\n\n"
        with self.assertRaises(WireguardError):
            inst.set_path_filter()

    def test_no_path_filter_configured(self):
        raw = config.json.loads(DOCKER.read_text())
        del raw["tunnels"][0]["endpoints"][0]["path_filter"]
        exp = config.parse_config(raw, Path("x.json"))
        inst = instance("QoS1", experiment=exp)
        inst.uapi = lambda r: self.fail("no UAPI call expected")
        self.assertFalse(inst.set_path_filter())


class TestChecks(unittest.TestCase):
    def test_bring_up_commands(self):
        host = FakeHost()
        instance("QoS1", host).bring_up()
        cmds = [c[0] for c in host.calls]
        self.assertEqual(cmds, [["ip", "address", "add", "10.78.0.1/24", "dev", "wgx-ab"],
                                ["ip", "link", "set", "mtu", "1000", "dev", "wgx-ab"],
                                ["ip", "link", "set", "up", "dev", "wgx-ab"]])
        self.assertTrue(all(c[2] for c in host.calls))

    def test_check_api_ok_and_failure_reports_cannot_listen(self):
        host = FakeHost()
        inst = instance("QoS1", host)
        host.responders.append((lambda a, i: a[0] == "bash", "HTTP/1.0 200 OK\n", 0))
        self.assertIn("200", inst.check_api())
        # connect target: 0.0.0.0 -> loopback
        call = [c for c in host.calls if c[0][0] == "bash"][0][0]
        self.assertEqual(call[-2:], ["127.0.0.1", "28015"])
        host.responders[:] = [(lambda a, i: a[0] == "bash", "", 1)]
        host.files[inst.log_path] = "x\nERROR: SCION path API cannot listen on 0.0.0.0:28015: in use\ny\n"
        with self.assertRaises(WireguardError) as cm:
            inst.check_api()
        self.assertIn("cannot listen on 0.0.0.0:28015", str(cm.exception))

    def test_reservation_stats_and_wait(self):
        log = ("a\nHummingbird reservation for 1-ff00:0:112 in use, expires at 1, flyovers at [x]\n"
               "Buying Hummingbird reservation for 1-ff00:0:112 failed (attempt 1/3): no assets\n"
               "Hummingbird: buying the reservation for 1-ff00:0:112 from the marketplace at "
               "[1-ff00:0:111,10.0.0.1]:8080, set by HUMMINGBIRD_MARKETPLACE_ADDRESS\n"
               "Hummingbird reservation for 1-ff00:0:112 in use, expires at 2, flyovers at [y]\n"
               "Hummingbird reservation for 1-ff00:0:112 in use, expires at 3, flyovers at [z]\n")
        stats = wg.parse_reservation_stats(log)
        self.assertEqual((stats.purchased, stats.failed, stats.handovers), (3, 1, 2))
        self.assertEqual(stats.marketplaces, ("[1-ff00:0:111,10.0.0.1]:8080",))
        self.assertEqual(wg.parse_reservation_stats("").handovers, 0)
        host = FakeHost()
        inst = instance("QoS1", host)
        host.files[inst.log_path] = log
        self.assertIn("in use", inst.wait_for_reservation(1))
        self.assertEqual(inst.reservation_log_stats().purchased, 3)
        # receivers have nothing to wait for
        self.assertIsNone(instance("QoS2", host).wait_for_reservation(1))

    def test_wait_for_reservation_times_out_with_hints(self):
        host = FakeHost()
        inst = instance("QoS1", host)
        host.files[inst.log_path] = "Hummingbird: no assets found\n"
        with self.assertRaises(WireguardError) as cm:
            inst.wait_for_reservation(0)
        self.assertIn("no assets found", str(cm.exception))

    def test_wait_uapi_detects_dead_daemon(self):
        host = FakeHost()
        host.alive_state = False
        inst = instance("QoS1", host)
        host.files[inst.log_path] = "boom\n"
        with self.assertRaises(WireguardError) as cm:
            inst.wait_uapi(1)
        self.assertIn("boom", str(cm.exception))

    def test_marketplace_override(self):
        raw = config.json.loads(DOCKER.read_text())
        addr = "[1-ff00:0:111,127.0.0.1]:8080"
        raw["hummingbird"]["marketplace"].update(location_override=True, scion_address=addr)
        exp = config.parse_config(raw, Path("x.json"))
        host = FakeHost()
        inst = instance("QoS1", host, experiment=exp)
        with self.assertRaises(WireguardError):
            inst.check_marketplace_override()
        line = ("Hummingbird: buying the reservation for 1-ff00:0:112 from the marketplace at {}, "
                "set by HUMMINGBIRD_MARKETPLACE_ADDRESS\n")
        host.files[inst.log_path] = line.format(addr)
        self.assertEqual(inst.check_marketplace_override(), addr)
        host.files[inst.log_path] += line.format("[1-ff00:0:110,1.2.3.4]:1")
        with self.assertRaises(WireguardError):
            inst.check_marketplace_override()
        # Without override there is nothing to check.
        self.assertIsNone(instance("QoS1", host).check_marketplace_override())

    def test_wait_for_tunnel(self):
        host = FakeHost()
        host.responders.append((lambda a, i: a == ["ping", "-V"], "ping from iputils 20211215\n", 0))
        host.responders.append((lambda a, i: a[0] == "ping", "", 0))
        self.assertEqual(wg.wait_for_tunnel(host, "10.78.0.1", "10.78.0.2", 5), 1)
        ping = [c[0] for c in host.calls][1]
        self.assertEqual(ping, ["ping", "-c", "1", "-W", "2", "-I", "10.78.0.1", "10.78.0.2"])
        host.responders[:] = [(lambda a, i: a[0] == "ping", "", 1)]
        with self.assertRaises(WireguardError) as cm:
            wg.wait_for_tunnel(host, "10.78.0.1", "10.78.0.2", 0, lambda: "STATE")
        self.assertIn("STATE", str(cm.exception))


    def test_wait_for_tunnel_with_inetutils_ping(self):
        # GNU inetutils ping (SCIERA's ufes) rejects -I <address>: the route picks the tunnel anyway.
        host = FakeHost()
        host.responders.append((lambda a, i: a == ["ping", "-V"], "ping (GNU inetutils) 2.5\n", 0))
        host.responders.append((lambda a, i: a[0] == "ping", "", 0))
        wg.wait_for_tunnel(host, "10.79.0.1", "10.79.0.2", 5)
        self.assertEqual([c[0] for c in host.calls][1], ["ping", "-c", "1", "-W", "2", "10.79.0.2"])


class TestPathFilterRetry(unittest.TestCase):
    def test_filter_matches(self):
        log = ("Path filter for 1-ff00:0:112: 0 of 0 paths match \"x\"\n"
               "Path filter for 1-ff00:0:111: 2 of 4 paths match \"y\"\n"
               "Path filter for 1-ff00:0:112: 1 of 3 paths match \"x\"\n")
        self.assertEqual(wg.filter_matches(log, "1-ff00:0:112"), 1)
        self.assertEqual(wg.filter_matches(log, "1-ff00:0:111"), 2)
        self.assertIsNone(wg.filter_matches(log, "1-ff00:0:110"))

    def test_reapplies_the_filter_while_no_path_matches(self):
        inst = instance("QoS1")
        filt = inst.endpoint.path_filter
        logs = [f'Path filter for 1-ff00:0:112: 0 of 0 paths match "{filt}"\n',
                f'Path filter for 1-ff00:0:112: 1 of 3 paths match "{filt}"\n']
        inst.log_text = lambda: logs[0] if len(sent) < 2 else logs[0] + logs[1]
        sent, refreshed = [], []
        inst.refresh_paths = lambda: refreshed.append(True)

        def uapi(request):
            sent.append(request)
            return f"scion_path_filter=1-ff00:0:112 {filt}\nerrno=0\n\n" if request.startswith("get") \
                else "errno=0\n\n"
        inst.uapi = uapi
        with mock.patch.object(wg, "NO_PATH_RETRY_INTERVAL", 0):
            self.assertTrue(inst.set_path_filter())
        sets = [r for r in sent if r.startswith("set=1")]
        self.assertEqual(len(sets), 2)
        self.assertEqual(refreshed, [True])


class TestStop(unittest.TestCase):
    def test_stop_deletes_only_its_interface(self):
        host = FakeHost()
        inst = instance("QoS1", host)
        inst.start()
        self.assertTrue(inst.stop())
        self.assertEqual(host.stopped, ["/tmp/wgexp/runs/run1/wg-QoS1.pid"])
        cmds = [c[0] for c in host.calls]
        self.assertIn(["ip", "link", "del", "dev", "wgx-ab"], cmds)
        self.assertIn(["rm", "-f", "--", "/tmp/wgexp/uapi/wgx-ab.sock"], cmds)
        roots = {tuple(c[0][:3]): c[2] for c in host.calls}
        self.assertTrue(roots[("ip", "link", "del")])
        self.assertFalse(roots[("rm", "-f", "--")])

    def test_cleanup_leftovers_spares_foreign_interfaces(self):
        host = FakeHost()
        host.responders.append((lambda a, i: a[0] == "bash",
                                "/tmp/wgexp/runs/old/wg-QoS1.pid /tmp/wgexp/runs/old/wg-QoS2.pid\n", 0))
        done = wg.cleanup_leftovers(host, "/tmp/wgexp/", ["wgx-ab", "wg0", "eth0"])
        self.assertEqual(host.stopped, ["/tmp/wgexp/runs/old/wg-QoS1.pid", "/tmp/wgexp/runs/old/wg-QoS2.pid"])
        dels = [c[0] for c in host.calls if c[0][:3] == ["ip", "link", "del"]]
        self.assertEqual(dels, [["ip", "link", "del", "dev", "wgx-ab"]])
        self.assertIn("wgx-ab", done)


if __name__ == "__main__":
    unittest.main()
