"""
Unit tests for Milestone 1: All-in-One Containerized Multi-Service Data Plane (Requirement R2).
Verifies:
- Dockerfile compliance (python:3.12-slim, port 8000, healthcheck).
- docker-compose.yml and podman-compose.yml topology, 6 services, ports, network, SELinux labels.
- .env.example environment defaults.
- scripts/generate_certs.sh TLS generator validity.
- Configuration files compliance with Component Adapters (Elasticsearch, Suricata, Syslog).
"""

import os
import unittest
import yaml
import json
import tomllib
from adapters.elastic.adapter import ElasticAdapter
from adapters.suricata.adapter import SuricataAdapter
from adapters.syslog.adapter import SyslogAdapter

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestMilestone1DataPlane(unittest.TestCase):

    def setUp(self):
        self.dockerfile_path = os.path.join(BASE_DIR, "Dockerfile")
        self.docker_compose_path = os.path.join(BASE_DIR, "docker-compose.yml")
        self.podman_compose_path = os.path.join(BASE_DIR, "podman-compose.yml")
        self.env_example_path = os.path.join(BASE_DIR, ".env.example")
        self.generate_certs_path = os.path.join(BASE_DIR, "scripts", "generate_certs.sh")
        self.es_config_path = os.path.join(BASE_DIR, "configs", "elasticsearch", "elasticsearch.yml")
        self.suricata_config_path = os.path.join(BASE_DIR, "configs", "suricata", "suricata.yaml")
        self.suricata_rules_path = os.path.join(BASE_DIR, "configs", "suricata", "suricata.rules")
        self.syslog_json_path = os.path.join(BASE_DIR, "configs", "syslog", "syslog-collector.json")
        self.vector_toml_path = os.path.join(BASE_DIR, "configs", "syslog", "vector.toml")

    def test_dockerfile_specification(self):
        self.assertTrue(os.path.exists(self.dockerfile_path), "Dockerfile must exist")
        with open(self.dockerfile_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertTrue("FROM python:3.12-slim" in content or "FROM docker.io/library/python:3.12-slim" in content)
        self.assertTrue("EXPOSE 8000" in content or "EXPOSE 7070" in content)
        self.assertIn("HEALTHCHECK", content)
        self.assertTrue("curl -f http://localhost:8000/ || exit 1" in content or "curl -f http://localhost:7070/ || exit 1" in content)
        self.assertIn("backend", content)
        self.assertIn("frontend", content)
        self.assertIn("adapters", content)
        self.assertIn("configs", content)
        self.assertIn("scripts", content)

    def test_docker_compose_services_and_topology(self):
        self.assertTrue(os.path.exists(self.docker_compose_path), "docker-compose.yml must exist")
        with open(self.docker_compose_path, "r", encoding="utf-8") as f:
            compose = yaml.safe_load(f)

        services = compose.get("services", {})
        self.assertEqual(len(services), 6, "Must define exactly 6 data plane services")

        expected_services = [
            "opensoc-forge-mgmt",
            "elasticsearch",
            "kibana",
            "wazuh-manager",
            "suricata",
            "syslog-collector",
        ]
        for s in expected_services:
            self.assertIn(s, services, f"Service {s} must be present in docker-compose.yml")

        # 1. opensoc-forge-mgmt
        mgmt = services["opensoc-forge-mgmt"]
        self.assertTrue(any("8000" in str(p) or "7070" in str(p) for p in mgmt.get("ports", [])))
        self.assertIn("healthcheck", mgmt)
        self.assertIn("opensoc-net", mgmt.get("networks", []))

        # 2. elasticsearch
        es = services["elasticsearch"]
        ports_str = str(es.get("ports", []))
        self.assertIn("9200", ports_str)
        self.assertIn("9300", ports_str)
        env = es.get("environment", [])
        self.assertTrue(any("discovery.type=single-node" in str(e) for e in env))
        self.assertTrue(any("xpack.security.enabled=true" in str(e) for e in env))
        self.assertTrue(any("ES_JAVA_OPTS" in str(e) for e in env))
        self.assertIn("healthcheck", es)

        # 3. kibana
        kibana = services["kibana"]
        self.assertTrue(any("5601" in str(p) for p in kibana.get("ports", [])))
        self.assertIn("elasticsearch", kibana.get("depends_on", []))
        self.assertIn("healthcheck", kibana)

        # 4. wazuh-manager
        wazuh = services["wazuh-manager"]
        wazuh_ports = str(wazuh.get("ports", []))
        self.assertIn("1514", wazuh_ports)
        self.assertIn("1515", wazuh_ports)
        self.assertIn("55000", wazuh_ports)
        self.assertIn("healthcheck", wazuh)

        # 5. suricata
        suricata = services["suricata"]
        self.assertEqual(suricata.get("network_mode"), "host", "Suricata must use host network mode")
        caps = suricata.get("cap_add", [])
        self.assertIn("NET_ADMIN", caps)
        self.assertIn("NET_RAW", caps)
        suricata_vols = str(suricata.get("volumes", []))
        self.assertIn("/var/log/suricata", suricata_vols)

        # 6. syslog-collector
        syslog = services["syslog-collector"]
        syslog_ports = str(syslog.get("ports", []))
        self.assertIn("514", syslog_ports)
        self.assertIn("6514", syslog_ports)
        self.assertIn("healthcheck", syslog)

        # Network configuration
        networks = compose.get("networks", {})
        self.assertIn("opensoc-net", networks)
        ipam_config = networks["opensoc-net"]["ipam"]["config"]
        self.assertEqual(ipam_config[0]["subnet"], "172.28.0.0/16")

        # SELinux volume labels (:z)
        all_volume_mounts = []
        for s_name, s_def in services.items():
            for v in s_def.get("volumes", []):
                all_volume_mounts.append((s_name, str(v)))

        for s_name, v_str in all_volume_mounts:
            if ":" in v_str and not v_str.startswith("es_data") and not v_str.startswith("kibana_data") and not v_str.startswith("wazuh_") and not v_str.startswith("suricata_rules"):
                self.assertTrue(
                    ":z" in v_str or ":ro,z" in v_str or ":rw,z" in v_str,
                    f"Volume mount {v_str} in service {s_name} must specify SELinux :z label for cross-distro compatibility"
                )

    def test_podman_compose_compatibility(self):
        self.assertTrue(os.path.exists(self.podman_compose_path), "podman-compose.yml must exist")
        with open(self.podman_compose_path, "r", encoding="utf-8") as f:
            compose = yaml.safe_load(f)
        services = compose.get("services", {})
        self.assertEqual(len(services), 6)
        self.assertIn("suricata", services)
        self.assertEqual(services["suricata"].get("network_mode"), "host")

    def test_env_example_defaults(self):
        self.assertTrue(os.path.exists(self.env_example_path), ".env.example must exist")
        with open(self.env_example_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        keys = {}
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                keys[k.strip()] = v.strip()

        required_keys = [
            "ELASTIC_PASSWORD",
            "WAZUH_API_USER",
            "WAZUH_API_PASSWORD",
            "MONITORED_INTERFACE",
            "MGMT_PORT",
            "ES_PORT",
            "KIBANA_PORT",
            "WAZUH_AGENT_TCP_PORT",
            "WAZUH_ENROLL_PORT",
            "WAZUH_API_PORT",
            "SYSLOG_UDP_PORT",
            "SYSLOG_TCP_PORT",
            "SYSLOG_TLS_PORT",
        ]
        for k in required_keys:
            self.assertIn(k, keys, f".env.example must define {k}")

    def test_scripts_generate_certs(self):
        self.assertTrue(os.path.exists(self.generate_certs_path), "generate_certs.sh must exist")
        with open(self.generate_certs_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertTrue(content.startswith("#!/usr/bin/env bash") or content.startswith("#!/bin/bash"))
        self.assertIn("set -euo pipefail", content)
        self.assertIn("openssl", content)
        self.assertIn("elasticsearch", content)
        self.assertIn("kibana", content)
        self.assertIn("syslog", content)
        self.assertIn("mgmt", content)
        self.assertIn("ca.crt", content)
        self.assertIn("chmod 600", content)

    def test_elasticsearch_configuration_validation(self):
        self.assertTrue(os.path.exists(self.es_config_path))
        with open(self.es_config_path, "r", encoding="utf-8") as f:
            es_content = f.read()

        adapter = ElasticAdapter(simulated=True)
        val_result = adapter.validate_configuration(es_content)
        self.assertTrue(val_result.valid, f"elasticsearch.yml must pass adapter validation: {val_result.errors}")
        self.assertEqual(len(val_result.errors), 0)

    def test_suricata_configuration_validation(self):
        self.assertTrue(os.path.exists(self.suricata_config_path))
        self.assertTrue(os.path.exists(self.suricata_rules_path))
        with open(self.suricata_config_path, "r", encoding="utf-8") as f:
            suricata_content = f.read()

        adapter = SuricataAdapter(simulated=True)
        val_result = adapter.validate_configuration(suricata_content)
        self.assertTrue(val_result.valid, f"suricata.yaml must pass adapter validation: {val_result.errors}")
        self.assertEqual(len(val_result.errors), 0)

    def test_syslog_configuration_validation(self):
        self.assertTrue(os.path.exists(self.syslog_json_path))
        self.assertTrue(os.path.exists(self.vector_toml_path))

        with open(self.syslog_json_path, "r", encoding="utf-8") as f:
            syslog_content = f.read()

        adapter = SyslogAdapter(simulated=True)
        val_result = adapter.validate_configuration(syslog_content)
        self.assertTrue(val_result.valid, f"syslog-collector.json must pass adapter validation: {val_result.errors}")
        self.assertEqual(len(val_result.errors), 0)

        with open(self.vector_toml_path, "rb") as f:
            parsed_toml = tomllib.load(f)
        self.assertIn("sources", parsed_toml)
        self.assertIn("transforms", parsed_toml)
        self.assertIn("sinks", parsed_toml)


if __name__ == "__main__":
    unittest.main()
