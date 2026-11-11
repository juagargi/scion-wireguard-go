"""Tests for config.py. Standard library only; optional checks need SCION_DIR+PyYAML or jsonschema."""

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import config  # noqa: E402
from config import ConfigError, load_config  # noqa: E402

DOCKER = HERE / "experiment-docker.json"
SCIERA = HERE / "experiment-sciera.json"


def example(path):
    return json.loads(path.read_text())


def parse(raw, name="x.json"):
    return config.parse_config(raw, Path(name))


class Base(unittest.TestCase):
    def assertInvalid(self, raw, *fragments):
        with self.assertRaises(ConfigError) as cm:
            parse(raw)
        for f in fragments:
            self.assertIn(f, str(cm.exception))
        return str(cm.exception)

    def docker(self, mutate=None):
        raw = example(DOCKER)
        if mutate:
            mutate(raw)
        return raw

    def sciera(self, mutate=None):
        raw = example(SCIERA)
        if mutate:
            mutate(raw)
        return raw


class TestParsers(unittest.TestCase):
    def test_bandwidth(self):
        self.assertEqual(config.parse_bandwidth("20mbps"), 20_000_000)
        self.assertEqual(config.parse_bandwidth("950Mbps"), 950_000_000)
        self.assertEqual(config.parse_bandwidth("1.5gbps"), 1_500_000_000)
        with self.assertRaises(ValueError):
            config.parse_bandwidth("20")

    def test_duration(self):
        self.assertEqual(config.parse_duration("30s"), 30)
        self.assertEqual(config.parse_duration("-5s"), -5)
        self.assertEqual(config.parse_duration("1m30s"), 90)
        self.assertAlmostEqual(config.parse_duration("200ms"), 0.2)
        self.assertEqual(config.parse_duration("1h"), 3600)
        with self.assertRaises(ValueError):
            config.parse_duration("5")

    def test_size(self):
        self.assertEqual(config.parse_size("1GiB"), 1 << 30)
        self.assertEqual(config.parse_size("10B"), 10)
        with self.assertRaises(ValueError):
            config.parse_size("1GB")


class TestExamples(Base):
    def test_docker_loads(self):
        e = load_config(DOCKER)
        self.assertEqual(e.kind, "docker")
        self.assertEqual(e.name, "docker-tiny-1g")
        self.assertEqual(len(e.sha256), 64)
        self.assertEqual(e.endpoint("QoS2").host_key, "1-ff00:0:112")
        self.assertEqual(e.endpoint("BE2").host_key, "1-ff00:0:112")
        self.assertEqual(e.peer_of("QoS1").name, "QoS2")
        self.assertEqual(e.tunnel_of("BE2").id, "cd")
        self.assertEqual(e.endpoint("QoS1").interface, "wgx-ab")
        self.assertEqual(e.endpoint("QoS1").api_bind, "0.0.0.0")
        self.assertIsNone(e.endpoint("QoS1").host)
        self.assertIsNone(e.endpoint("QoS1").node)
        self.assertEqual(e.run.warmup, 30)
        self.assertEqual(e.run.max_duration, 3600)
        self.assertEqual(e.monitoring.scrape_interval_seconds, 1)
        self.assertEqual(e.tc["rate"], "50mbit")
        self.assertEqual(e.deployment.router["egress_queue_size"], 640)
        self.assertFalse(e.marketplace.location_override)
        self.assertTrue(e.marketplace_insecure)
        self.assertEqual(str(e.tunnels[0].network), "10.78.0.0/24")
        copy_wl, be, ping_ab, ping_cd = e.workloads
        self.assertIsInstance(copy_wl, config.FileCopy)
        self.assertEqual(copy_wl.size_bytes, 1 << 30)
        self.assertEqual(copy_wl.bwlimit, "reservation")
        self.assertEqual(copy_wl.timeout, 1800)
        self.assertEqual(copy_wl.sender.name, "QoS1")
        self.assertIsInstance(be, config.Iperf3)
        self.assertEqual((be.length, be.server_port, be.bandwidth_bps), (900, 5201, 50_000_000))
        self.assertEqual(be.tunnel.id, "cd")
        self.assertIsInstance(ping_ab, config.Ping)
        self.assertAlmostEqual(ping_cd.interval, 0.2)
        self.assertEqual(e.endpoint("QoS1").hummingbird.bandwidth_bps, 20_000_000)
        self.assertEqual(e.endpoint("QoS1").hummingbird.env(), {
            "HUMMINGBIRD_BANDWIDTH": "20mbps", "HUMMINGBIRD_REVERSE_BANDWIDTH": "2mbps",
            "HUMMINGBIRD_DURATION": "60s", "HUMMINGBIRD_RENEWAL_AHEAD": "15s",
            "HUMMINGBIRD_RESERVATION_OVERLAP": "10s"})
        self.assertEqual(e.hummingbird_env("QoS2"), {})
        self.assertEqual(e.hummingbird_env("QoS1")["HUMMINGBIRD_MARKETPLACE_INSECURE"], "1")
        self.assertEqual(e.endpoint("QoS1").api_address, "0.0.0.0:28015")

    def test_sciera_loads(self):
        e = load_config(SCIERA)
        self.assertEqual(e.kind, "ssh")
        self.assertEqual(e.endpoint("QoS2").host_key, "ufms")
        self.assertEqual(e.endpoint("BE2").host_key, "ufms")
        self.assertEqual(e.endpoint("QoS1").api_bind, "127.0.0.1")
        self.assertEqual(e.endpoint("QoS1").host, "127.0.0.1")
        self.assertEqual(e.deployment.raw, e.raw["deployment"])
        h = e.endpoint("QoS1").hummingbird
        self.assertEqual((h.humm_start_offset, h.humm_start_offset_seconds), ("-5s", -5))
        self.assertEqual(h.partial, "71-1916,71-2:0:5c")
        self.assertEqual(e.marketplace.scion_address, "[71-2:0:5c,127.0.0.1]:31888")
        self.assertEqual(e.hummingbird_env("QoS1")["HUMMINGBIRD_MARKETPLACE_ADDRESS"],
                         "[71-2:0:5c,127.0.0.1]:31888")
        self.assertEqual(e.marketplace.interfaces["71-2:0:5c"], [0, 104])

    def test_check_environment(self):
        d, s = load_config(DOCKER), load_config(SCIERA)
        self.assertEqual(config.check_environment(d, {}), "1234")
        self.assertEqual(config.check_environment(d, {"WGEXP_MARKETPLACE_PASSWORD": "pw"}), "pw")
        self.assertEqual(config.check_environment(s, {"WGEXP_MARKETPLACE_PASSWORD": "pw"}), "pw")
        self.assertEqual(config.check_environment(s, {}), "1234")
        self.assertEqual(config.check_environment(s, {"WGEXP_MARKETPLACE_PASSWORD": ""}), "1234")

    def test_defaults(self):
        def m(r):
            del r["run"], r["monitoring"]
            for t in r["tunnels"]:
                t.pop("mtu")
            r["tunnels"][1]["endpoints"][0]["interface"] = "custom0"
            del r["workloads"][1]["length"]
            del r["name"]
        e = parse(self.docker(m), "my-exp.json")
        self.assertEqual(e.name, "my-exp")
        self.assertEqual((e.run.warmup, e.run.cooldown, e.run.max_duration), (30, 10, None))
        self.assertEqual((e.monitoring.prometheus_port, e.monitoring.grafana_port,
                          e.monitoring.runner_metrics_port), (8091, 3001, 9189))
        t = e.tunnels[0]
        self.assertEqual((t.mtu, t.prefix_len, t.persistent_keepalive, t.use_batch),
                         (1000, 24, 25, True))
        self.assertEqual(e.endpoint("BE1").interface, "custom0")
        self.assertEqual(e.workloads[1].length, 900)  # mtu - 100

    def test_ipv6_api_address(self):
        def m(r):
            r["tunnels"][0]["endpoints"][0]["api_bind"] = "::1"
        e = parse(self.docker(m))
        self.assertEqual(e.endpoint("QoS1").api_address, "[::1]:28015")


class TestSemanticRules(Base):
    def test_duplicate_endpoint_name(self):
        self.assertInvalid(self.docker(lambda r: r["tunnels"][1]["endpoints"][0].update(name="QoS1")),
                           "tunnels[1].endpoints[0].name", "duplicate")

    def test_duplicate_tunnel_id(self):
        self.assertInvalid(self.docker(lambda r: r["tunnels"][1].update(id="ab")),
                           "tunnels[1].id", "duplicate")

    def test_duplicate_workload_id(self):
        self.assertInvalid(self.docker(lambda r: r["workloads"][1].update(id="copy-1g")),
                           "workloads[1].id", "duplicate")

    def test_workload_unknown_endpoint(self):
        self.assertInvalid(self.docker(lambda r: r["workloads"][0].update(to="Z")),
                           "workloads[0].to", "unknown endpoint")

    def test_workload_ends_of_different_tunnels(self):
        self.assertInvalid(self.docker(lambda r: r["workloads"][0].update(to="BE2")),
                           "workloads[0].to", "other end")

    def test_workload_to_itself(self):
        self.assertInvalid(self.docker(lambda r: r["workloads"][0].update(to="QoS1")),
                           "workloads[0].to")

    def test_duplicate_listen_port_same_host(self):
        # B and D share the tester of 1-ff00:0:112
        self.assertInvalid(
            self.docker(lambda r: r["tunnels"][1]["endpoints"][1].update(listen_port=32000)),
            "tunnels[1].endpoints[1].listen_port", "tunnels[0].endpoints[1]")

    def test_duplicate_api_port_same_host(self):
        self.assertInvalid(
            self.docker(lambda r: r["tunnels"][1]["endpoints"][1].update(api_port=28015)),
            "tunnels[1].endpoints[1].api_port")

    def test_duplicate_interface_same_host(self):
        self.assertInvalid(
            self.docker(lambda r: r["tunnels"][1]["endpoints"][1].update(interface="wgx-ab")),
            "tunnels[1].endpoints[1].interface")

    def test_same_ports_on_different_hosts_are_fine(self):
        parse(self.docker())  # A and B both use 32000/28015 on different testers

    def test_ssh_ports_unique_per_node(self):
        self.assertInvalid(
            self.sciera(lambda r: r["tunnels"][1]["endpoints"][1].update(api_port=28015)),
            "tunnels[1].endpoints[1].api_port", "'ufms'")

    def test_iperf3_server_ports_unique_per_host(self):
        def m(r):
            extra = dict(r["workloads"][1], id="be-load2")
            r["workloads"].append(extra)
        e = parse(self.docker(m))
        ports = [w.server_port for w in e.workloads if isinstance(w, config.Iperf3)]
        self.assertEqual(ports, [5201, 5202])

    def test_tunnel_ips_in_one_prefix(self):
        self.assertInvalid(
            self.docker(lambda r: r["tunnels"][0]["endpoints"][1].update(tunnel_ip="10.99.0.2")),
            "tunnels[0].endpoints[1].tunnel_ip", "10.78.0.0/24")

    def test_tunnel_ips_equal(self):
        self.assertInvalid(
            self.docker(lambda r: r["tunnels"][0]["endpoints"][1].update(tunnel_ip="10.78.0.1")),
            "tunnels[0].endpoints[1].tunnel_ip")

    def test_tunnel_prefixes_overlap(self):
        def m(r):
            r["tunnels"][1]["endpoints"][0]["tunnel_ip"] = "10.78.0.5"
            r["tunnels"][1]["endpoints"][1]["tunnel_ip"] = "10.78.0.6"
        self.assertInvalid(self.docker(m), "tunnels[1].endpoints[0].tunnel_ip", "overlaps")

    def test_ssh_needs_node(self):
        self.assertInvalid(self.sciera(lambda r: r["tunnels"][0]["endpoints"][0].pop("node")),
                           "tunnels[0].endpoints[0].node", "required")

    def test_ssh_node_must_exist(self):
        self.assertInvalid(
            self.sciera(lambda r: r["tunnels"][0]["endpoints"][0].update(node="nowhere")),
            "tunnels[0].endpoints[0].node", "nowhere")

    def test_ssh_needs_host(self):
        self.assertInvalid(self.sciera(lambda r: r["tunnels"][0]["endpoints"][0].pop("host")),
                           "tunnels[0].endpoints[0].host", "required")

    def test_docker_forbids_node(self):
        self.assertInvalid(
            self.docker(lambda r: r["tunnels"][0]["endpoints"][0].update(node="rnp")),
            "tunnels[0].endpoints[0].node", "not allowed")

    def test_hummingbird_section_required_with_reservation(self):
        self.assertInvalid(self.docker(lambda r: r.pop("hummingbird")), "hummingbird",
                           "tunnels[0].endpoints[0].hummingbird")

    def test_hummingbird_section_without_reservation(self):
        self.assertInvalid(
            self.docker(lambda r: r["tunnels"][0]["endpoints"][0].pop("hummingbird")),
            "hummingbird: is present but no endpoint")

    def test_marketplace_location_override_needs_address(self):
        self.assertInvalid(
            self.docker(lambda r: r["hummingbird"]["marketplace"].update(location_override=True)),
            "hummingbird.marketplace.scion_address")

    def test_marketplace_unknown_field(self):
        self.assertInvalid(
            self.docker(lambda r: r["hummingbird"]["marketplace"].update(bogus=1)),
            "hummingbird.marketplace.bogus")

    def test_bwlimit_reservation_needs_reserved_sender(self):
        def m(r):
            w = r["workloads"][0]
            w.update({"from": "QoS2", "to": "QoS1"})
        self.assertInvalid(self.docker(m), "workloads[0].bwlimit", "'QoS2'")

    def test_bwlimit_default_without_reservation_is_none(self):
        def m(r):
            w = r["workloads"][0]
            w.update({"from": "QoS2", "to": "QoS1"})
            del w["bwlimit"]
        self.assertEqual(parse(self.docker(m)).workloads[0].bwlimit, "none")

    def test_bwlimit_explicit_rate(self):
        e = parse(self.docker(lambda r: r["workloads"][0].update(bwlimit="5mbps")))
        self.assertEqual(e.workloads[0].bwlimit_bps, 5_000_000)

    def test_file_copy_repeat_zero_only_background(self):
        self.assertInvalid(self.docker(lambda r: r["workloads"][0].update(repeat=0)),
                           "workloads[0].repeat")
        parse(self.docker(lambda r: r["workloads"][0].update(repeat=0, role="background")))

    def test_iperf3_without_duration_only_background(self):
        def m(r):
            r["workloads"][1]["role"] = "primary"
        self.assertInvalid(self.docker(m), "workloads[1].duration")
        def ok(r):
            r["workloads"][1].update(role="primary", duration="1m")
        parse(self.docker(ok))

    def test_udp_length_fits_mtu(self):
        self.assertInvalid(self.docker(lambda r: r["workloads"][1].update(length=973)),
                           "workloads[1].length", "972")
        parse(self.docker(lambda r: r["workloads"][1].update(length=972)))

    def test_udp_needs_bandwidth(self):
        self.assertInvalid(self.docker(lambda r: r["workloads"][1].pop("bandwidth")),
                           "workloads[1].bandwidth")

    def test_no_primary_needs_max_duration(self):
        def m(r):
            r["workloads"][0]["role"] = "background"
            r["workloads"][0].pop("timeout")
            del r["run"]["max_duration"]
        self.assertInvalid(self.docker(m), "run.max_duration")

    def test_no_primary_with_max_duration_ok(self):
        def m(r):
            r["workloads"][0]["role"] = "background"
        parse(self.docker(m))

    def test_timeout_exceeds_max_duration(self):
        self.assertInvalid(self.docker(lambda r: r["run"].update(max_duration="10m")),
                           "workloads[0].timeout", "max_duration")

    def test_unknown_field(self):
        self.assertInvalid(self.docker(lambda r: r["tunnels"][0].update(bogus=1)),
                           "tunnels[0].bogus")

    def test_missing_required_field(self):
        self.assertInvalid(self.docker(lambda r: r["tunnels"][0]["endpoints"][0].pop("api_port")),
                           "tunnels[0].endpoints[0]", "api_port")

    def test_bad_values_name_their_path(self):
        self.assertInvalid(
            self.docker(lambda r: r["tunnels"][0]["endpoints"][0]["hummingbird"].update(
                bandwidth="fast")), "tunnels[0].endpoints[0].hummingbird.bandwidth")
        self.assertInvalid(self.docker(lambda r: r["run"].update(warmup="soon")), "run.warmup")
        self.assertInvalid(self.docker(lambda r: r["tunnels"][0]["endpoints"][0].update(
            listen_port=70000)), "tunnels[0].endpoints[0].listen_port")
        self.assertInvalid(self.docker(lambda r: r["tunnels"][0].update(id="a" * 12)),
                           "tunnels[0].id")

    def test_bad_deployment_kind(self):
        self.assertInvalid(self.docker(lambda r: r["deployment"].update(kind="k8s")),
                           "deployment.kind")

    def test_invalid_json_and_missing_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"
            p.write_text("{")
            with self.assertRaises(ConfigError):
                load_config(p)
            with self.assertRaises(ConfigError):
                load_config(Path(d) / "nope.json")


class TestStdlibOnly(unittest.TestCase):
    def test_imports_without_third_party_modules(self):
        code = (
            "import sys\n"
            "class Block:\n"
            "    def find_spec(self, name, path=None, target=None):\n"
            "        if name.split('.')[0] in ('yaml','jsonschema','bcrypt','tools'):\n"
            "            raise ImportError('blocked ' + name)\n"
            "sys.meta_path.insert(0, Block())\n"
            f"sys.path.insert(0, {str(HERE)!r})\n"
            "import config\n"
            f"config.load_config(__import__('pathlib').Path({str(DOCKER)!r}))\n"
            f"config.load_config(__import__('pathlib').Path({str(SCIERA)!r}))\n"
            "assert not [m for m in sys.modules if m.split('.')[0] in ('yaml','jsonschema','bcrypt')]\n"
        )
        r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


# ---------------------------------------------------------------------------------------------
# Optional checks
# ---------------------------------------------------------------------------------------------

try:
    import jsonschema  # type: ignore
except ImportError:
    jsonschema = None


@unittest.skipIf(jsonschema is None, "jsonschema is not installed: schema checks skipped")
class TestSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads((HERE / "experiment.schema.json").read_text())
        cls.validator = jsonschema.Draft202012Validator(cls.schema)

    def valid(self, raw):
        return not list(self.validator.iter_errors(raw))

    def test_schema_is_valid(self):
        jsonschema.Draft202012Validator.check_schema(self.schema)

    def test_examples_accepted(self):
        self.assertTrue(self.valid(example(DOCKER)))
        self.assertTrue(self.valid(example(SCIERA)))

    def test_shape_errors_rejected(self):
        def bad(mutate, base=DOCKER):
            raw = example(base)
            mutate(raw)
            self.assertFalse(self.valid(raw))
        bad(lambda r: r.update(bogus=1))
        bad(lambda r: r.pop("tunnels"))
        bad(lambda r: r["tunnels"][0]["endpoints"].pop())
        bad(lambda r: r["tunnels"][0]["endpoints"][0].update(api_port="x"))
        bad(lambda r: r["tunnels"][0]["endpoints"][0]["hummingbird"].update(bandwidth="20"))
        bad(lambda r: r["workloads"][1].update(kind="nope"))
        bad(lambda r: r["workloads"][1].update(bogus=1))
        bad(lambda r: r["workloads"][1].pop("bandwidth"))
        bad(lambda r: r["deployment"].update(kind="k8s"))
        bad(lambda r: r["run"].update(warmup="5"))
        bad(lambda r: r["tunnels"][0].update(id="x" * 12))
        bad(lambda r: r["hummingbird"]["marketplace"].update(location_override=True) or
            r["hummingbird"]["marketplace"].pop("username"))


# hummbwtester compatibility (needs SCION_DIR and PyYAML)
_SCION_DIR = os.environ.get("SCION_DIR")
_hummb = None
_hummb_skip = "SCION_DIR is not set: hummbwtester compatibility checks skipped"
if _SCION_DIR:
    try:
        import yaml  # noqa: F401
        sys.path.insert(0, _SCION_DIR)
        from tools.hummbwtester.scripts import orchestration, ssh_orchestration  # type: ignore
        _hummb = (orchestration, ssh_orchestration)
    except ImportError as e:
        _hummb_skip = f"hummbwtester not importable ({e}): compatibility checks skipped"


@unittest.skipIf(_hummb is None, _hummb_skip)
class TestHummbwtesterCompat(unittest.TestCase):
    def test_marketplace_sections(self):
        orchestration, _ = _hummb
        for path, kind in ((DOCKER, "docker"), (SCIERA, "ssh")):
            raw = example(path)
            orchestration.parse_marketplace_config(raw["hummingbird"]["marketplace"], kind)

    def test_sciera_deployment(self):
        _, remote = _hummb
        raw = example(SCIERA)
        e = load_config(SCIERA)
        root = copy.deepcopy(raw)
        root["deployment"].setdefault("metrics", {})["local_prometheus_port"] = \
            e.monitoring.prometheus_port
        participants = {ep.name: ep.node for ep in e.endpoints}
        inv = remote.load_deployment(root, participants, relay_ports=len(participants) + 1)
        self.assertEqual(set(inv.participant_hosts), set(participants.values()))


if __name__ == "__main__":
    unittest.main()
