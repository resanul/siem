"""
Tier 5 Adversarial White-Box Stress Testing: Service & Infrastructure Layer.
Validates:
1. docker-compose.yml and podman-compose.yml:
   - Host port collision tests and dual-protocol separation
   - Subnet conflict and IPAM allocation probing
   - SELinux :z vs :Z multi-container access checks
   - Suricata host mode capability boundaries (NET_ADMIN, NET_RAW, SYS_NICE, security_opt)
   - Healthcheck intervals, timeouts, retries, and start_periods
2. systemd/opensoc-forge.service:
   - Unit file directives (Type=simple, Restart=on-failure, RestartSec=10s, TimeoutStartSec=300, LimitNOFILE=65536)
   - Syntax correctness and INI parser validation
   - Clean signal termination (KillMode=mixed, TimeoutStopSec=60, ExecStop)
3. Security policies:
   - Firewalld XML parser integrity against malformed rules
   - Missing port detection and cross-policy alignment (Firewalld, UFW, Compose)
   - SELinux boolean checks and graceful Disabled mode handling
   - Setcap capability syntax and missing binary fallbacks
"""

import os
import re
import sys
import yaml
import ipaddress
import unittest
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Tuple, Set

# Ensure repo root is on sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from tests.e2e.helpers import (
    DOCKER_COMPOSE_PATH,
    PODMAN_COMPOSE_PATH,
    SYSTEMD_SERVICE_PATH,
    FIREWALLD_XML_PATH,
    parse_systemd_unit,
    parse_firewalld_service_xml,
    ALL_OPEN_PORTS,
)

CONFIGURE_SECURITY_SH_PATH = os.path.join(REPO_ROOT, "scripts", "configure_security_policies.sh")
INSTALL_SH_PATH = os.path.join(REPO_ROOT, "install.sh")
ENV_EXAMPLE_PATH = os.path.join(REPO_ROOT, ".env.example")


def extract_compose_published_ports(compose_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extracts published host ports from compose services.
    Returns list of dicts:
      {'service': str, 'host_port': int, 'container_port': int, 'protocol': str}
    """
    extracted = []
    services = compose_data.get("services", {})
    for svc_name, svc_conf in services.items():
        # Host networking services don't publish mapped bridge ports
        if svc_conf.get("network_mode") == "host":
            continue

        raw_ports = svc_conf.get("ports", [])
        for p in raw_ports:
            p_str = str(p)
            # Resolve default if pattern like "${ES_PORT:-9200}:9200"
            resolved = re.sub(r"\${[A-Za-z0-9_]+:-([A-Za-z0-9_]+)}", r"\1", p_str)
            # Match formats: host:container, host:container/proto
            proto = "tcp"
            if "/" in resolved:
                resolved, proto = resolved.split("/", 1)
                proto = proto.lower()

            parts = resolved.split(":")
            if len(parts) == 2:
                host_p = int(parts[0])
                cont_p = int(parts[1])
            elif len(parts) == 3:
                # ip:host:container
                host_p = int(parts[1])
                cont_p = int(parts[2])
            else:
                host_p = int(parts[0])
                cont_p = int(parts[0])

            extracted.append({
                "service": svc_name,
                "host_port": host_p,
                "container_port": cont_p,
                "protocol": proto,
            })
    return extracted


def detect_port_collisions(ports: List[Dict[str, Any]]) -> List[str]:
    """
    Detects duplicate (host_port, protocol) bindings across different services.
    """
    seen: Dict[Tuple[int, str], str] = {}
    collisions = []
    for item in ports:
        key = (item["host_port"], item["protocol"])
        if key in seen:
            collisions.append(
                f"Collision on host port {key[0]}/{key[1]} between services "
                f"'{seen[key]}' and '{item['service']}'"
            )
        else:
            seen[key] = item["service"]
    return collisions


def parse_duration_to_seconds(duration_str: str) -> int:
    """Parses compose duration string like '10s', '1m', '300s' into integer seconds."""
    match = re.match(r"^(\d+)([smhd]?)$", duration_str.strip())
    if not match:
        raise ValueError(f"Invalid duration format: '{duration_str}'")
    val, unit = match.groups()
    val = int(val)
    if unit == "s" or not unit:
        return val
    elif unit == "m":
        return val * 60
    elif unit == "h":
        return val * 3600
    elif unit == "d":
        return val * 86400
    return val


class TestTier5ComposePortCollision(unittest.TestCase):
    """Tier 5 Probes: Host port collision and dual-protocol separation."""

    def test_adv_01_compose_published_ports_no_collision(self):
        """Verifies that published host ports in docker-compose and podman-compose have zero collisions."""
        for compose_path, label in [(DOCKER_COMPOSE_PATH, "docker-compose"), (PODMAN_COMPOSE_PATH, "podman-compose")]:
            with open(compose_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            ports = extract_compose_published_ports(data)
            collisions = detect_port_collisions(ports)
            self.assertEqual(
                len(collisions), 0,
                f"Unexpected port collisions detected in {label}: {collisions}"
            )
            # Verify minimum 8 distinct host ports are published
            unique_host_ports = {p["host_port"] for p in ports}
            self.assertGreaterEqual(
                len(unique_host_ports), 8,
                f"{label} must publish at least 8 unique host ports, found {len(unique_host_ports)}"
            )

    def test_adv_02_compose_dual_protocol_separation(self):
        """
        Adversarial test: verify explicit /udp and /tcp separation on shared port numbers.
        Syslog port 514 and Wazuh port 1514 must be bound on both TCP and UDP without colliding.
        """
        with open(DOCKER_COMPOSE_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        ports = extract_compose_published_ports(data)

        # Port 514 must have both tcp and udp
        p514_protocols = {p["protocol"] for p in ports if p["host_port"] == 514}
        self.assertEqual(p514_protocols, {"tcp", "udp"}, "Port 514 must have separate tcp and udp bindings")

        # Port 1514 must have both tcp and udp
        p1514_protocols = {p["protocol"] for p in ports if p["host_port"] == 1514}
        self.assertEqual(p1514_protocols, {"tcp", "udp"}, "Port 1514 must have separate tcp and udp bindings")

    def test_adv_03_port_collision_adversarial_oracle(self):
        """
        Adversarial Generator & Oracle:
        Injects synthetic collisions into port mapping list and verifies the collision detector catches it.
        """
        clean_ports = [
            {"service": "mgmt", "host_port": 8000, "protocol": "tcp"},
            {"service": "es", "host_port": 9200, "protocol": "tcp"},
            {"service": "kibana", "host_port": 5601, "protocol": "tcp"},
        ]
        self.assertEqual(len(detect_port_collisions(clean_ports)), 0)

        # Attack 1: Duplicate TCP port
        colliding_ports = list(clean_ports) + [
            {"service": "malicious_app", "host_port": 8000, "protocol": "tcp"}
        ]
        collisions = detect_port_collisions(colliding_ports)
        self.assertEqual(len(collisions), 1)
        self.assertIn("Collision on host port 8000/tcp", collisions[0])

        # Attack 2: Same port number but different protocol should NOT collide
        valid_dual = list(clean_ports) + [
            {"service": "udp_listener", "host_port": 8000, "protocol": "udp"}
        ]
        self.assertEqual(len(detect_port_collisions(valid_dual)), 0)

    def test_adv_04_env_default_ports_uniqueness(self):
        """
        Validates that all environment variable port defaults across .env.example are mutually distinct.
        """
        with open(ENV_EXAMPLE_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        env_ports = {}
        for line in content.splitlines():
            line = line.strip()
            if "_PORT=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env_ports[k.strip()] = int(v.strip())

        # Check critical ports
        self.assertIn("MGMT_PORT", env_ports)
        self.assertIn("ES_PORT", env_ports)
        self.assertIn("ES_TRANSPORT_PORT", env_ports)
        self.assertIn("KIBANA_PORT", env_ports)
        self.assertIn("WAZUH_AGENT_TCP_PORT", env_ports)
        self.assertIn("WAZUH_AGENT_UDP_PORT", env_ports)
        self.assertIn("WAZUH_ENROLL_PORT", env_ports)
        self.assertIn("WAZUH_API_PORT", env_ports)
        self.assertIn("SYSLOG_UDP_PORT", env_ports)
        self.assertIn("SYSLOG_TCP_PORT", env_ports)
        self.assertIn("SYSLOG_TLS_PORT", env_ports)

        # Unique port numbers for TCP services
        tcp_ports = [
            env_ports["MGMT_PORT"],
            env_ports["ES_PORT"],
            env_ports["ES_TRANSPORT_PORT"],
            env_ports["KIBANA_PORT"],
            env_ports["WAZUH_AGENT_TCP_PORT"],
            env_ports["WAZUH_ENROLL_PORT"],
            env_ports["WAZUH_API_PORT"],
            env_ports["SYSLOG_TCP_PORT"],
            env_ports["SYSLOG_TLS_PORT"],
        ]
        self.assertEqual(len(tcp_ports), len(set(tcp_ports)), "TCP ports across .env.example must be distinct")

        # Unique port numbers for UDP services
        udp_ports = [
            env_ports["WAZUH_AGENT_UDP_PORT"],
            env_ports["SYSLOG_UDP_PORT"],
        ]
        self.assertEqual(len(udp_ports), len(set(udp_ports)), "UDP ports across .env.example must be distinct")


class TestTier5SubnetAndNetwork(unittest.TestCase):
    """Tier 5 Probes: Subnet conflicts, IPAM configuration, and network topology."""

    def test_adv_05_subnet_validity_and_rfc1918(self):
        """Verifies opensoc-net subnet is valid RFC 1918 private CIDR and does not collide with docker0."""
        for compose_path in [DOCKER_COMPOSE_PATH, PODMAN_COMPOSE_PATH]:
            with open(compose_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            net_conf = data.get("networks", {}).get("opensoc-net", {})
            self.assertEqual(net_conf.get("driver"), "bridge")
            ipam = net_conf.get("ipam", {}).get("config", [{}])[0]
            subnet_str = ipam.get("subnet")
            self.assertIsNotNone(subnet_str, "Subnet must be explicitly defined")

            net = ipaddress.ip_network(subnet_str)
            self.assertTrue(net.is_private, "opensoc-net subnet must be private (RFC 1918)")
            self.assertEqual(net.prefixlen, 16, "Expected /16 subnet mask")

            # Check isolation from standard Docker default bridge (172.17.0.0/16)
            docker_default = ipaddress.ip_network("172.17.0.0/16")
            self.assertFalse(
                net.overlaps(docker_default),
                f"Subnet {subnet_str} overlaps with standard docker0 bridge (172.17.0.0/16)"
            )

    def test_adv_06_subnet_gateway_validity(self):
        """Verifies gateway IP is within subnet and is a valid host address."""
        with open(DOCKER_COMPOSE_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        ipam = data["networks"]["opensoc-net"]["ipam"]["config"][0]
        subnet = ipaddress.ip_network(ipam["subnet"])
        gateway = ipaddress.ip_address(ipam["gateway"])

        self.assertIn(gateway, subnet, f"Gateway {gateway} must belong to subnet {subnet}")
        self.assertNotEqual(gateway, subnet.network_address, "Gateway cannot be the network address")
        self.assertNotEqual(gateway, subnet.broadcast_address, "Gateway cannot be the broadcast address")
        self.assertEqual(gateway, subnet.network_address + 1, "Gateway must be the first usable address (.1)")

    def test_adv_07_suricata_host_network_no_bridge_conflict(self):
        """
        Adversarial check: Suricata runs in network_mode: host and MUST NOT attach to bridge networks.
        In Docker Compose, specifying both network_mode: host and networks causes container engine error.
        """
        for compose_path in [DOCKER_COMPOSE_PATH, PODMAN_COMPOSE_PATH]:
            with open(compose_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            suricata = data["services"]["suricata"]
            self.assertEqual(
                suricata.get("network_mode"), "host",
                "Suricata must run in host networking mode"
            )
            self.assertNotIn(
                "networks", suricata,
                "Suricata must NOT declare bridge networks when network_mode: host is active"
            )

    def test_adv_08_data_plane_bridge_attachment_integrity(self):
        """Verifies all internal data plane containers attach to opensoc-net."""
        with open(DOCKER_COMPOSE_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        bridge_services = [
            "opensoc-forge-mgmt",
            "elasticsearch",
            "kibana",
            "wazuh-manager",
            "syslog-collector",
        ]
        for svc_name in bridge_services:
            svc = data["services"][svc_name]
            nets = svc.get("networks", [])
            self.assertIn(
                "opensoc-net", nets,
                f"Service {svc_name} must attach to explicit bridge network 'opensoc-net'"
            )

    def test_adv_09_subnet_overlap_detection_oracle(self):
        """
        Adversarial Oracle: Test overlap detection logic against various colliding CIDRs.
        """
        base_net = ipaddress.ip_network("172.28.0.0/16")

        colliding_cidrs = [
            "172.28.1.0/24",     # Sub-range
            "172.28.0.0/15",     # Super-range
            "172.28.100.0/20",   # Sub-range
            "172.28.0.0/16",     # Exact match
        ]
        non_colliding_cidrs = [
            "172.17.0.0/16",
            "172.18.0.0/16",
            "10.0.0.0/8",
            "192.168.1.0/24",
            "172.29.0.0/16",
        ]

        for cidr in colliding_cidrs:
            test_net = ipaddress.ip_network(cidr, strict=False)
            self.assertTrue(
                base_net.overlaps(test_net),
                f"Failed to detect collision between {base_net} and {test_net}"
            )

        for cidr in non_colliding_cidrs:
            test_net = ipaddress.ip_network(cidr, strict=False)
            self.assertFalse(
                base_net.overlaps(test_net),
                f"False positive collision between {base_net} and {test_net}"
            )


class TestTier5SelinuxVolumeLabeling(unittest.TestCase):
    """Tier 5 Probes: SELinux volume relabeling flags (:z vs :Z) and multi-container access."""

    def test_adv_10_all_volume_mounts_use_lowercase_z(self):
        """
        SELinux requirement:
        All volume mounts must use lowercase ':z' (shared label).
        Uppercase ':Z' (exclusive label) locks out other containers and is strictly forbidden.
        """
        for compose_path, label in [(DOCKER_COMPOSE_PATH, "docker-compose"), (PODMAN_COMPOSE_PATH, "podman-compose")]:
            with open(compose_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            for svc_name, svc_conf in data.get("services", {}).items():
                volumes = svc_conf.get("volumes", [])
                for vol in volumes:
                    vol_str = str(vol)
                    parts = vol_str.split(":")
                    if len(parts) >= 3:
                        mode = parts[-1]
                        self.assertNotIn(
                            ":Z", vol_str,
                            f"Illegal uppercase :Z flag in {label} service {svc_name}: {vol_str}"
                        )
                        self.assertNotIn(
                            ",Z", vol_str,
                            f"Illegal uppercase ,Z flag in {label} service {svc_name}: {vol_str}"
                        )
                        self.assertTrue(
                            "z" in mode.split(","),
                            f"Missing SELinux :z flag in {label} service {svc_name} mount: {vol_str}"
                        )

    def test_adv_11_multi_container_shared_volumes_safeguard(self):
        """
        Verifies specific multi-container shared paths:
        1. /var/log/suricata (shared between suricata and opensoc-forge-mgmt)
        2. /etc/opensoc/certs (shared between mgmt, elasticsearch, kibana, syslog)
        """
        with open(DOCKER_COMPOSE_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        services = data["services"]

        # Suricata logs shared between suricata (rw) and mgmt (ro)
        suricata_vols = [str(v) for v in services["suricata"]["volumes"]]
        mgmt_vols = [str(v) for v in services["opensoc-forge-mgmt"]["volumes"]]

        suricata_log_mount = [v for v in suricata_vols if "/var/log/suricata" in v]
        mgmt_log_mount = [v for v in mgmt_vols if "/var/log/suricata" in v]

        self.assertTrue(len(suricata_log_mount) > 0, "Suricata must mount suricata log dir")
        self.assertTrue(len(mgmt_log_mount) > 0, "Mgmt must mount suricata log dir")
        self.assertTrue(suricata_log_mount[0].endswith(",z") or suricata_log_mount[0].endswith(":z"))
        self.assertTrue(mgmt_log_mount[0].endswith(",z") or mgmt_log_mount[0].endswith(":z"))

        # Certs directory shared by 4 services
        cert_sharing_services = ["opensoc-forge-mgmt", "elasticsearch", "kibana", "syslog-collector"]
        for svc in cert_sharing_services:
            svc_vols = [str(v) for v in services[svc]["volumes"]]
            cert_mounts = [v for v in svc_vols if "certs" in v]
            self.assertTrue(
                len(cert_mounts) > 0,
                f"Service {svc} must mount certs directory"
            )
            for cm in cert_mounts:
                self.assertNotIn("Z", cm, f"Shared cert mount must not use uppercase Z: {cm}")
                self.assertTrue("z" in cm, f"Shared cert mount must include lowercase z: {cm}")

    def test_adv_12_uppercase_z_exclusive_lockout_oracle(self):
        """
        Adversarial Oracle: Simulates an invalid volume spec with uppercase :Z and confirms rejection.
        """
        def validate_volume_selinux_mode(vol_spec: str) -> bool:
            parts = vol_spec.split(":")
            if len(parts) >= 3:
                flags = parts[-1].split(",")
                if "Z" in flags:
                    return False
                if "z" in flags:
                    return True
            return False

        self.assertTrue(validate_volume_selinux_mode("/host/path:/container/path:rw,z"))
        self.assertTrue(validate_volume_selinux_mode("/host/path:/container/path:ro,z"))
        self.assertFalse(validate_volume_selinux_mode("/host/path:/container/path:rw,Z"))
        self.assertFalse(validate_volume_selinux_mode("/host/path:/container/path:Z"))


class TestTier5SuricataCapabilityBoundaries(unittest.TestCase):
    """Tier 5 Probes: Suricata host networking and least-privilege capability containment."""

    def test_adv_13_suricata_capabilities_exact_match(self):
        """Verifies Suricata has required packet capture capabilities."""
        for compose_path in [DOCKER_COMPOSE_PATH, PODMAN_COMPOSE_PATH]:
            with open(compose_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            suricata = data["services"]["suricata"]
            caps = suricata.get("cap_add", [])
            self.assertIn("NET_ADMIN", caps, "Suricata requires NET_ADMIN for promiscuous mode and fanout")
            self.assertIn("NET_RAW", caps, "Suricata requires NET_RAW for AF_PACKET raw socket capture")
            self.assertIn("SYS_NICE", caps, "Suricata requires SYS_NICE for thread priority pinning")

    def test_adv_14_suricata_security_opt_label_disable(self):
        """
        Verifies Suricata security_opt includes label=disable.
        Required under SELinux Enforcing on RHEL/Rocky to open raw sockets on host network interfaces.
        """
        with open(DOCKER_COMPOSE_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        suricata = data["services"]["suricata"]
        sec_opts = suricata.get("security_opt", [])
        self.assertIn(
            "label=disable", sec_opts,
            "Suricata must have label=disable to allow raw packet sniffing on host interfaces"
        )

    def test_adv_15_non_suricata_containers_least_privilege(self):
        """
        Adversarial check: No other container should have NET_ADMIN, NET_RAW, or network_mode: host.
        """
        with open(DOCKER_COMPOSE_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        for svc_name, svc_conf in data["services"].items():
            if svc_name == "suricata":
                continue

            self.assertNotEqual(
                svc_conf.get("network_mode"), "host",
                f"Service {svc_name} must NOT use host networking"
            )
            caps = svc_conf.get("cap_add", [])
            self.assertNotIn("NET_ADMIN", caps, f"Service {svc_name} must not have NET_ADMIN")
            self.assertNotIn("NET_RAW", caps, f"Service {svc_name} must not have NET_RAW")
            self.assertFalse(svc_conf.get("privileged", False), f"Service {svc_name} must not be privileged")

    def test_adv_16_suricata_no_unnecessary_superuser_caps(self):
        """
        Verifies Suricata does not request excessive capabilities (SYS_ADMIN, ALL, etc.).
        """
        with open(DOCKER_COMPOSE_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        suricata_caps = set(data["services"]["suricata"].get("cap_add", []))
        forbidden_caps = {"ALL", "SYS_ADMIN", "SYS_RAWIO", "SYS_BOOT", "SYS_MODULE", "MKNOD"}

        intersection = suricata_caps.intersection(forbidden_caps)
        self.assertEqual(
            len(intersection), 0,
            f"Suricata requests excessive dangerous capabilities: {intersection}"
        )


class TestTier5HealthcheckTimingSafety(unittest.TestCase):
    """Tier 5 Probes: Container healthcheck intervals, timeouts, and startup margins."""

    def test_adv_17_healthcheck_interval_timeout_invariants(self):
        """
        Invariant: For every container, interval >= timeout.
        If timeout > interval, healthcheck executions queue up and cause false container kills.
        """
        for compose_path, label in [(DOCKER_COMPOSE_PATH, "docker-compose"), (PODMAN_COMPOSE_PATH, "podman-compose")]:
            with open(compose_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            for svc_name, svc_conf in data["services"].items():
                hc = svc_conf.get("healthcheck")
                self.assertIsNotNone(hc, f"Service {svc_name} in {label} must define a healthcheck")

                interval_sec = parse_duration_to_seconds(hc["interval"])
                timeout_sec = parse_duration_to_seconds(hc["timeout"])

                self.assertGreaterEqual(
                    interval_sec, timeout_sec,
                    f"Healthcheck invariant violated in {svc_name}: interval ({interval_sec}s) "
                    f"must be >= timeout ({timeout_sec}s)"
                )

    def test_adv_18_healthcheck_positive_durations_and_retries(self):
        """Verifies interval, timeout, and retries are strictly positive integers."""
        with open(DOCKER_COMPOSE_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        for svc_name, svc_conf in data["services"].items():
            hc = svc_conf["healthcheck"]
            interval = parse_duration_to_seconds(hc["interval"])
            timeout = parse_duration_to_seconds(hc["timeout"])
            retries = int(hc["retries"])

            self.assertGreater(interval, 0, f"{svc_name} interval must be > 0")
            self.assertGreater(timeout, 0, f"{svc_name} timeout must be > 0")
            self.assertGreaterEqual(retries, 3, f"{svc_name} retries must be >= 3")

    def test_adv_19_datastore_start_period_safety(self):
        """
        Verifies that resource-heavy components (Elasticsearch, Kibana, Wazuh) define start_period >= 30s.
        Prevents premature restart loops during JVM/startup initialization.
        """
        with open(DOCKER_COMPOSE_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        heavy_services = ["elasticsearch", "kibana", "wazuh-manager"]
        for svc in heavy_services:
            hc = data["services"][svc]["healthcheck"]
            start_period = hc.get("start_period")
            self.assertIsNotNone(start_period, f"Service {svc} must specify a start_period")
            sp_sec = parse_duration_to_seconds(start_period)
            self.assertGreaterEqual(
                sp_sec, 30,
                f"Service {svc} start_period ({sp_sec}s) must be >= 30s to allow initialization"
            )

    def test_adv_20_healthcheck_shell_syntax_safety(self):
        """
        Verifies healthcheck test commands use non-blocking error handling (|| exit 1)
        and proper dollar sign escaping for container runtime variable expansion ($${...}).
        """
        with open(DOCKER_COMPOSE_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        for svc_name, svc_conf in data["services"].items():
            hc = svc_conf["healthcheck"]
            test_cmd = hc.get("test")
            self.assertIsInstance(test_cmd, list)
            cmd_str = " ".join(test_cmd)
            self.assertTrue(
                "exit 1" in cmd_str or "grep" in cmd_str,
                f"Healthcheck for {svc_name} must use deterministic failure signaling"
            )

        # Elasticsearch and Wazuh healthchecks must use $${...} escape
        es_test = " ".join(data["services"]["elasticsearch"]["healthcheck"]["test"])
        self.assertIn("$${ELASTIC_PASSWORD", es_test, "ES healthcheck must use $$ for runtime variable expansion")

        wazuh_test = " ".join(data["services"]["wazuh-manager"]["healthcheck"]["test"])
        self.assertIn("$${WAZUH_API_USER", wazuh_test, "Wazuh healthcheck must use $$ for runtime variable expansion")


class TestTier5SystemdUnitResilience(unittest.TestCase):
    """Tier 5 Probes: Systemd unit file directives, syntax, and clean signal termination."""

    def test_adv_21_systemd_core_directives(self):
        """Verifies core directives in systemd/opensoc-forge.service."""
        with open(SYSTEMD_SERVICE_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        unit = parse_systemd_unit(content)
        svc = unit.get("Service", {})
        inst = unit.get("Install", {})

        self.assertEqual(svc.get("Type"), "simple", "Service Type must be simple")
        self.assertEqual(svc.get("Restart"), "on-failure", "Restart must be on-failure")
        self.assertEqual(svc.get("RestartSec"), "10s", "RestartSec must be 10s")
        self.assertEqual(svc.get("TimeoutStartSec"), "300", "TimeoutStartSec must be 300")
        self.assertEqual(svc.get("LimitNOFILE"), "65536", "LimitNOFILE must be 65536")
        self.assertEqual(inst.get("WantedBy"), "multi-user.target", "WantedBy must be multi-user.target")

    def test_adv_22_systemd_clean_signal_termination(self):
        """
        Verifies clean signal termination configuration:
        - KillMode=mixed: SIGTERM to main process, allowing children to shut down gracefully
        - TimeoutStopSec=60: 60s window before SIGKILL
        - ExecStop invokes opensoc-ctl stop
        """
        with open(SYSTEMD_SERVICE_PATH, "r", encoding="utf-8") as f:
            unit = parse_systemd_unit(f.read())

        svc = unit["Service"]
        self.assertEqual(svc.get("KillMode"), "mixed", "KillMode must be mixed for graceful container drain")
        self.assertEqual(svc.get("TimeoutStopSec"), "60", "TimeoutStopSec must provide 60s drain window")
        self.assertEqual(svc.get("ExecStop"), "/usr/local/bin/opensoc-ctl stop", "ExecStop must call opensoc-ctl stop")

    def test_adv_23_systemd_absolute_paths_validation(self):
        """
        Systemd strict syntax rule: All Exec* commands MUST specify absolute executable paths.
        """
        with open(SYSTEMD_SERVICE_PATH, "r", encoding="utf-8") as f:
            unit = parse_systemd_unit(f.read())

        svc = unit["Service"]
        exec_keys = ["ExecStartPre", "ExecStart", "ExecStop", "ExecReload"]

        for k in exec_keys:
            val = svc.get(k, "")
            self.assertTrue(len(val) > 0, f"Missing {k} directive")
            # Strip leading '-' if present (ignore exit status prefix)
            clean_cmd = val.lstrip("-")
            exe_path = clean_cmd.split()[0]
            self.assertTrue(
                os.path.isabs(exe_path),
                f"{k} command '{exe_path}' is not an absolute path"
            )
            self.assertEqual(exe_path, "/usr/local/bin/opensoc-ctl")

    def test_adv_24_systemd_dependency_ordering(self):
        """Verifies systemd unit dependency ordering and mount requirements."""
        with open(SYSTEMD_SERVICE_PATH, "r", encoding="utf-8") as f:
            unit = parse_systemd_unit(f.read())

        u = unit["Unit"]
        after_str = u.get("After", "")
        self.assertIn("network.target", after_str)
        self.assertIn("docker.service", after_str)
        self.assertIn("podman.service", after_str)
        self.assertIn("firewalld.service", after_str)

        self.assertEqual(u.get("RequiresMountsFor"), "/opt/opensoc-forge")

    def test_adv_25_systemd_parser_malformed_oracle(self):
        """
        Adversarial Oracle: Validates rejection of malformed or invalid systemd units.
        """
        from tests.e2e.helpers import validate_systemd_unit_specification

        # Valid unit
        valid_unit = {
            "Unit": {"Description": "Test"},
            "Service": {"Type": "simple", "Restart": "on-failure", "TimeoutStartSec": "300", "ExecStart": "/usr/local/bin/opensoc-ctl start-foreground"},
            "Install": {"WantedBy": "multi-user.target"},
        }
        ok, errors = validate_systemd_unit_specification(valid_unit)
        self.assertTrue(ok, f"Valid unit should pass: {errors}")

        # Attack 1: Type=oneshot rejected
        bad_type = dict(valid_unit)
        bad_type["Service"] = dict(valid_unit["Service"], Type="oneshot")
        ok, errors = validate_systemd_unit_specification(bad_type)
        self.assertFalse(ok)
        self.assertTrue(any("Type must be 'simple'" in e for e in errors))

        # Attack 2: Restart=always rejected
        bad_restart = dict(valid_unit)
        bad_restart["Service"] = dict(valid_unit["Service"], Restart="always")
        ok, errors = validate_systemd_unit_specification(bad_restart)
        self.assertFalse(ok)
        self.assertTrue(any("Restart must be 'on-failure'" in e for e in errors))

        # Attack 3: TimeoutStartSec too small
        bad_timeout = dict(valid_unit)
        bad_timeout["Service"] = dict(valid_unit["Service"], TimeoutStartSec="60")
        ok, errors = validate_systemd_unit_specification(bad_timeout)
        self.assertFalse(ok)
        self.assertTrue(any("TimeoutStartSec must be >= 300" in e for e in errors))


class TestTier5SecurityPoliciesAndFirewalld(unittest.TestCase):
    """Tier 5 Probes: Firewalld XML parser integrity, port alignment, SELinux booleans, and setcap."""

    def test_adv_26_firewalld_xml_integrity_and_ports(self):
        """Verifies configs/firewalld/opensoc-forge.xml defines all 8 external service ports."""
        with open(FIREWALLD_XML_PATH, "r", encoding="utf-8") as f:
            data = parse_firewalld_service_xml(f.read())

        self.assertEqual(data["short"], "OpenSOC Forge")
        self.assertIn("SIEM/SOC", data["description"])

        ports = data["ports"]
        port_dict = {}
        for p, proto in ports:
            port_dict.setdefault(p, set()).add(proto)

        # All canonical ports must be present
        for req_p in ALL_OPEN_PORTS:
            self.assertIn(req_p, port_dict, f"Port {req_p} missing from firewalld service XML")

        # Specific dual-protocol assertions
        self.assertEqual(port_dict[514], {"tcp", "udp"}, "Port 514 must be open for both TCP and UDP in firewalld")
        self.assertEqual(port_dict[1514], {"tcp", "udp"}, "Port 1514 must be open for both TCP and UDP in firewalld")

    def test_adv_27_firewalld_malformed_xml_attacks_oracle(self):
        """
        Adversarial Oracle: Test XML parser resilience against malformed XML payloads.
        """
        def validate_firewalld_xml(xml_str: str) -> Tuple[bool, str]:
            try:
                root = ET.fromstring(xml_str)
                if root.tag != "service":
                    return False, f"Invalid root tag: '{root.tag}'"
                for p in root.findall("port"):
                    port_attr = p.attrib.get("port")
                    proto_attr = p.attrib.get("protocol")
                    if not port_attr or not proto_attr:
                        return False, "Missing port or protocol attribute"
                    port_num = int(port_attr)
                    if port_num < 1 or port_num > 65535:
                        return False, f"Port out of range: {port_num}"
                    if proto_attr not in ("tcp", "udp"):
                        return False, f"Invalid protocol: '{proto_attr}'"
                return True, "Valid"
            except Exception as e:
                return False, str(e)

        # Valid sample
        valid_xml = '<service><short>Test</short><port port="8000" protocol="tcp"/></service>'
        ok, msg = validate_firewalld_xml(valid_xml)
        self.assertTrue(ok)

        # Attack 1: Unclosed tag
        ok, msg = validate_firewalld_xml('<service><short>Test</service>')
        self.assertFalse(ok)

        # Attack 2: Non-numeric port
        ok, msg = validate_firewalld_xml('<service><port port="invalid" protocol="tcp"/></service>')
        self.assertFalse(ok)

        # Attack 3: Out-of-range port
        ok, msg = validate_firewalld_xml('<service><port port="70000" protocol="tcp"/></service>')
        self.assertFalse(ok)

        # Attack 4: Invalid protocol
        ok, msg = validate_firewalld_xml('<service><port port="8000" protocol="sctp"/></service>')
        self.assertFalse(ok)

    def test_adv_28_firewalld_and_ufw_port_alignment(self):
        """
        Cross-Policy Alignment:
        Verifies that configure_security_policies.sh configures the exact same ports
        for both firewalld and UFW.
        """
        with open(CONFIGURE_SECURITY_SH_PATH, "r", encoding="utf-8") as f:
            script_content = f.read()

        # Extract firewalld ports added via --add-port
        fw_ports = set(re.findall(r"--add-port=([0-9]+/(?:tcp|udp))", script_content))
        # Extract UFW ports added via ufw allow
        ufw_ports = set(re.findall(r"ufw allow ([0-9]+/(?:tcp|udp))", script_content))

        expected_rules = {
            "8000/tcp",
            "5601/tcp",
            "9200/tcp",
            "1514/tcp",
            "1514/udp",
            "1515/tcp",
            "55000/tcp",
            "514/udp",
            "514/tcp",
            "6514/tcp",
        }

        self.assertEqual(
            fw_ports, expected_rules,
            f"Firewalld script port rules mismatch: missing {expected_rules - fw_ports}"
        )
        self.assertEqual(
            ufw_ports, expected_rules,
            f"UFW script port rules mismatch: missing {expected_rules - ufw_ports}"
        )

    def test_adv_29_selinux_boolean_policy_alignment(self):
        """
        Verifies SELinux booleans (container_manage_cgroup, container_use_devices)
        and Disabled mode detection.
        """
        with open(CONFIGURE_SECURITY_SH_PATH, "r", encoding="utf-8") as f:
            script = f.read()

        self.assertIn("setsebool -P container_manage_cgroup 1", script)
        self.assertIn("setsebool -P container_use_devices 1", script)
        self.assertIn('"${SELINUX_MODE}" != "Disabled"', script, "Must handle SELinux Disabled mode gracefully")
        self.assertIn("chcon -Rt container_file_t", script, "Must relabel volume directories with container_file_t")

    def test_adv_30_setcap_capability_syntax_and_fallbacks(self):
        """
        Verifies setcap capability syntax and binary existence check.
        """
        with open(CONFIGURE_SECURITY_SH_PATH, "r", encoding="utf-8") as f:
            script = f.read()

        # Syntax check
        self.assertIn("setcap cap_net_raw,cap_net_admin+eip", script)
        # Check that it verifies target binary exists before setcap
        self.assertIn('[ -f "${bin_target}" ]', script)
        # Check promiscuous mode excludes loopback 'lo'
        self.assertIn('$2 != "lo"', script)


if __name__ == "__main__":
    unittest.main()
