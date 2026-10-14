"""
Integration tests for Enterprise BAS, Purple Team Cyber Range, Threat Hunting, Sigma Compiler, and Incident War Room.
"""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def get_token(username: str, role: str) -> str:
    res = client.post("/api/v1/auth/login", json={"username": username, "password": f"{username.capitalize()}Pass123!"})
    if res.status_code == 200:
        return res.json()["access_token"]
    # Fallback to admin
    res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "AdminPass123!"})
    return res.json()["access_token"]


def test_bas_atomic_tests_and_scorecard():
    token = get_token("detector", "detection_engineer")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. List atomic tests
    res = client.get("/api/v1/simulation/bas/tests", headers=headers)
    assert res.status_code == 200
    tests = res.json()
    assert len(tests) >= 8
    assert any(t["technique_id"] == "T1059.001" for t in tests)

    # 2. Run atomic test (T1059.001)
    res = client.post("/api/v1/simulation/bas/run", json={"test_id": "ATOM-1059-001"}, headers=headers)
    assert res.status_code == 200
    run_data = res.json()
    assert run_data["status"] == "DETECTED"
    assert run_data["technique_id"] == "T1059.001"
    assert run_data["mttd_seconds"] is not None

    # 3. Get scorecard
    res = client.get("/api/v1/simulation/bas/scorecard", headers=headers)
    assert res.status_code == 200
    scorecard = res.json()
    assert scorecard["tested_count"] >= 1
    assert scorecard["detected_count"] >= 1
    assert scorecard["efficacy_score_percent"] > 0


def test_purple_team_campaign_workflow():
    token = get_token("detector", "detection_engineer")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. List campaigns
    res = client.get("/api/v1/simulation/purple-team/campaigns", headers=headers)
    assert res.status_code == 200
    campaigns = res.json()
    assert len(campaigns) >= 2
    camp_id = campaigns[0]["id"]

    # 2. Get campaign details
    res = client.get(f"/api/v1/simulation/purple-team/campaigns/{camp_id}", headers=headers)
    assert res.status_code == 200
    detail = res.json()
    assert len(detail["steps"]) >= 3

    # 3. Execute step 1 with SOAR trigger
    res = client.post(
        f"/api/v1/simulation/purple-team/campaigns/{camp_id}/execute-step",
        json={"step_num": 1, "trigger_soar": True},
        headers=headers,
    )
    assert res.status_code == 200
    step_res = res.json()
    assert step_res["status"] == "SUCCESS"
    assert step_res["detected"] is True
    assert step_res["soar_executed"] is True


def test_threat_hunting_campaign_execution():
    token = get_token("analyst", "incident_responder")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. List threat hunt campaigns
    res = client.get("/api/v1/hunting/campaigns", headers=headers)
    assert res.status_code == 200
    hunts = res.json()
    assert len(hunts) >= 3
    hunt_id = hunts[0]["id"]

    # 2. Launch hunt campaign
    res = client.post(f"/api/v1/hunting/campaigns/{hunt_id}/launch", headers=headers)
    assert res.status_code == 200
    launch_res = res.json()
    assert launch_res["status"] == "COMPLETED"
    assert launch_res["scanned_events_count"] > 10000
    assert len(launch_res["findings"]) >= 1


def test_sigma_rule_compiler():
    token = get_token("detector", "detection_engineer")
    headers = {"Authorization": f"Bearer {token}"}

    sample_sigma_yaml = """
title: Suspicious Certutil Download
id: SIGMA-00109
status: test
description: Detects certutil downloading files from external IP
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\certutil.exe'
    CommandLine|contains:
      - '-urlcache'
      - '-split'
  condition: selection
level: high
"""
    res = client.post("/api/v1/rules/sigma/compile", json={"rule_yaml": sample_sigma_yaml}, headers=headers)
    assert res.status_code == 200
    comp = res.json()
    assert comp["title"] == "Suspicious Certutil Download"
    assert "elasticsearch" in comp["targets"]
    assert "query" in comp["targets"]["elasticsearch"]["query_dsl"]
    assert "wazuh" in comp["targets"]
    assert "<group name=\"opensoc,sigma,\">" in comp["targets"]["wazuh"]["xml_rule"]


def test_incident_war_room_lifecycle():
    token = get_token("analyst", "incident_responder")
    headers = {"Authorization": f"Bearer {token}"}
    case_id = "CASE-2026-901"

    # 1. Get or create War Room
    res = client.get(f"/api/v1/cases/{case_id}/war-room", headers=headers)
    assert res.status_code == 200
    room = res.json()
    assert room["case_id"] == case_id
    assert len(room["checklist"]) >= 8

    # 2. Toggle checklist task
    task_id = room["checklist"][0]["id"]
    res = client.post(f"/api/v1/cases/{case_id}/war-room/tasks/{task_id}/toggle", headers=headers)
    assert res.status_code == 200
    assert res.json()["completed"] is True

    # 3. Add forensic evidence
    res = client.post(
        f"/api/v1/cases/{case_id}/war-room/evidence",
        json={
            "evidence_type": "PCAP",
            "value": "/var/log/suricata/pcaps/attack-flow-99.pcap",
            "description": "Network packet capture of C2 beaconing",
            "source_host": "web-app-dmz-01",
        },
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json()["evidence_type"] == "PCAP"

    # 4. Add collaborative timeline note
    res = client.post(
        f"/api/v1/cases/{case_id}/war-room/timeline",
        json={
            "message": "Domain Controller firewall rule updated. Lateral SMB movement blocked.",
            "action_type": "CONTAINMENT_ACTION",
        },
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json()["action_type"] == "CONTAINMENT_ACTION"
