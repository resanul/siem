"""
OpenSOC Forge - RSA NetWitness SIEM Integration Adapter.
Authenticates against RSA NetWitness Platform 12.5.1.3 over OAuth2 and STOMP-over-WebSocket,
retrieving live cluster status, core services inventory, and streaming log & network telemetry.
"""

import os
import time
import json
import uuid
import logging
from typing import Dict, Any, List, Optional
import requests
import websocket
import ssl
import urllib3

urllib3.disable_warnings()

logger = logging.getLogger(__name__)

# NetWitness Configuration
NW_HOST = os.getenv("NETWITNESS_HOST", "172.31.101.34")
NW_USER = os.getenv("NETWITNESS_USER", "resanul")
NW_PASS = os.getenv("NETWITNESS_PASS", "CF!WF*$zRvAKh*R7Pv^9")

# Known Node IDs in the NetWitness Cluster
CORE_ENDPOINTS = {
    "broker": {
        "id": "4ffac1ef-48b1-413e-988c-5296960ca050",
        "name": "RSA-SIEM-SA01 - Broker",
        "host": "172.31.101.34",
        "port": 56003,
        "role": "Broker / Primary Head Node",
        "service": "broker"
    },
    "log_concentrator": {
        "id": "1467c1d0-18f8-41fc-a7e2-a62097955f87",
        "name": "Log-Concentrator01 - Concentrator",
        "host": "172.31.101.36",
        "port": 56005,
        "role": "Log Concentrator (Indexing & Meta)",
        "service": "concentrator"
    },
    "log_decoder": {
        "id": "490f92da-1769-4156-ba96-ab14216a91a1",
        "name": "Log-Decoder01 - Log Decoder",
        "host": "172.31.101.37",
        "port": 56002,
        "role": "Log Decoder (Log Parser)",
        "service": "log-decoder"
    },
    "network_concentrator": {
        "id": "f3574b67-5559-483c-8a01-e6add64b2c20",
        "name": "Network-Concentrator01 - Concentrator",
        "host": "172.31.101.38",
        "port": 56005,
        "role": "Network Concentrator (Network Sessions)",
        "service": "concentrator"
    },
    "network_decoder": {
        "id": "53b5f910-f859-4074-87c5-452f40350aa8",
        "name": "Network-Decoder01 - Decoder",
        "host": "172.31.101.39",
        "port": 56004,
        "role": "Network Decoder (Full Packet Capture)",
        "service": "decoder"
    },
    "archiver": {
        "id": "3e6b3ad9-95bb-4efe-bfaf-bf9d3c27f2ef",
        "name": "Archiver01 - Archiver",
        "host": "172.31.101.41",
        "port": 56008,
        "role": "Long-Term Compliance Archiver",
        "service": "archiver"
    }
}


class NetWitnessClient:
    def __init__(self, host: str = NW_HOST, username: str = NW_USER, password: str = NW_PASS):
        self.host = host
        self.username = username
        self.password = password
        self.token: Optional[str] = None
        self.csrf: Optional[str] = None
        self.cookies: Dict[str, str] = {}
        self.token_expiry: float = 0.0
        self.last_cache_time: float = 0.0
        self.cached_status: Optional[Dict[str, Any]] = None

    def _ensure_authenticated(self) -> bool:
        """Acquires or refreshes OAuth2 token and CSRF token."""
        now = time.time()
        if self.token and self.csrf and now < self.token_expiry - 120:
            return True

        try:
            s = requests.Session()
            s.trust_env = False  # Avoid intranet proxy collisions
            s.verify = False

            # Request OAuth2 password grant
            url = f"https://{self.host}/oauth/token"
            resp = s.post(
                url,
                data={
                    "grant_type": "password",
                    "username": self.username,
                    "password": self.password,
                    "client_id": "netwitness"
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=8
            )

            if resp.status_code != 200:
                logger.error(f"NetWitness OAuth login failed with status {resp.status_code}: {resp.text}")
                return False

            data = resp.json()
            self.token = data.get("access_token")
            self.csrf = resp.headers.get("X-CSRF-TOKEN")
            expires_in = data.get("expires_in", 3600)
            self.token_expiry = now + expires_in
            self.cookies = s.cookies.get_dict()

            logger.info("Successfully authenticated to RSA NetWitness Platform.")
            return True
        except Exception as e:
            logger.error(f"Error authenticating to NetWitness: {e}")
            return False

    def _create_ws_connection(self, prefix: str = "/api/investigate/socket") -> Optional[websocket.WebSocket]:
        """Creates an authenticated STOMP-over-WebSocket connection."""
        if not self._ensure_authenticated():
            return None

        server_id = "000"
        session_id = uuid.uuid4().hex[:8]
        ws_url = f"wss://{self.host}{prefix}/{server_id}/{session_id}/websocket"

        cookie_str = "; ".join([f"{k}={v}" for k, v in self.cookies.items()])

        try:
            ws = websocket.create_connection(
                ws_url,
                sslopt={"cert_reqs": ssl.CERT_NONE},
                header=[
                    f"Cookie: {cookie_str}",
                    f"X-CSRF-TOKEN: {self.csrf}",
                    f"authorization: Bearer {self.token}",
                    "User-Agent: OpenSOC-Forge/1.0"
                ],
                timeout=12
            )
            # Read SockJS open frame 'o'
            ws.recv()

            # STOMP CONNECT frame
            connect_frame = (
                "CONNECT\n"
                "accept-version:1.1,1.0\n"
                "heart-beat:10000,10000\n"
                f"X-CSRF-TOKEN:{self.csrf}\n"
                f"authorization:Bearer {self.token}\n\n"
                "\x00"
            )
            ws.send(json.dumps([connect_frame]))
            conn_res = ws.recv()

            if "CONNECTED" in conn_res:
                return ws
            else:
                logger.error(f"STOMP CONNECT failed: {conn_res}")
                ws.close()
                return None
        except Exception as e:
            logger.error(f"Failed to connect to NetWitness WebSocket {ws_url}: {e}")
            return None

    def get_cluster_status(self) -> Dict[str, Any]:
        """Returns the complete NetWitness cluster services status."""
        now = time.time()
        if self.cached_status and (now - self.last_cache_time < 30):
            return self.cached_status

        if not self._ensure_authenticated():
            return {
                "connected": False,
                "error": "Failed to authenticate to NetWitness",
                "host": self.host,
                "nodes": list(CORE_ENDPOINTS.values()),
                "total_nodes": len(CORE_ENDPOINTS),
                "online_nodes": 0
            }

        ws = self._create_ws_connection("/api/investigate/socket")
        live_endpoints = []

        if ws:
            try:
                sub_id = "sub-endpoints-" + uuid.uuid4().hex[:6]
                ws.send(json.dumps([f"SUBSCRIBE\nid:{sub_id}\ndestination:/user/queue/investigate/endpoints\n\n\x00"]))
                ws.send(json.dumps([f"SEND\ndestination:/ws/investigate/endpoints\ncontent-type:application/json\n\n{{}}\x00"]))

                for _ in range(6):
                    raw = ws.recv()
                    if raw.startswith("a["):
                        frames = json.loads(raw[1:])
                        stomp_msg = frames[0]
                        idx = stomp_msg.find("\n\n")
                        body = stomp_msg[idx+2:].rstrip("\x00")
                        data = json.loads(body)
                        if "data" in data and isinstance(data["data"], list):
                            live_endpoints = data["data"]
                            break
            except Exception as e:
                logger.error(f"Failed to fetch endpoints: {e}")
            finally:
                ws.close()

        # Build comprehensive nodes response
        nodes = []
        live_map = {ep.get("id"): ep for ep in live_endpoints}

        for key, static_node in CORE_ENDPOINTS.items():
            node_id = static_node["id"]
            live_info = live_map.get(node_id)
            is_online = live_info is not None

            host_meta = live_info.get("meta", {}).get("host", {}) if live_info else {}
            version_str = live_info.get("version", "12.5.1.3") if live_info else "12.5.1.3"

            nodes.append({
                "key": key,
                "id": node_id,
                "name": live_info.get("displayName", static_node["name"]) if live_info else static_node["name"],
                "service": static_node["service"],
                "role": static_node["role"],
                "host": static_node["host"],
                "port": static_node["port"],
                "use_tls": True,
                "version": version_str,
                "status": "ONLINE" if is_online else "STANDBY",
                "last_check": datetime_now_iso(),
                "node_zero": host_meta.get("nodeZeroHost", False)
            })

        online_count = sum(1 for n in nodes if n["status"] == "ONLINE")

        result = {
            "connected": True,
            "host": self.host,
            "version": "12.5.1.3",
            "cluster_name": "RSA-SIEM-PROD-CLUSTER",
            "total_nodes": len(nodes),
            "online_nodes": online_count,
            "nodes": nodes,
            "synced_at": datetime_now_iso()
        }

        self.cached_status = result
        self.last_cache_time = now
        return result

    def get_event_count(self, endpoint_type: str = "log", hours: int = 24) -> int:
        """Returns indexed event count for the requested time range."""
        ws = self._create_ws_connection("/api/investigate/socket")
        if not ws:
            return 0

        endpoint_id = (
            CORE_ENDPOINTS["log_concentrator"]["id"]
            if endpoint_type == "log"
            else CORE_ENDPOINTS["network_concentrator"]["id"]
        )

        now = int(time.time())
        from_time = now - (hours * 3600)

        count_req = {
            "filter": [
                {"field": "endpointId", "value": endpoint_id},
                {"field": "threshold", "value": 100000},
                {"field": "timeRange", "range": {"from": from_time, "to": now}},
                {"field": "query", "value": ""},
                {"field": "searchTerm", "value": ""}
            ],
            "stream": {"limit": 100, "batch": 100}
        }

        sub_id = "sub-count-" + uuid.uuid4().hex[:6]
        try:
            ws.send(json.dumps([f"SUBSCRIBE\nid:{sub_id}\ndestination:/user/queue/investigate/events/count\n\n\x00"]))
            ws.send(json.dumps([f"SEND\ndestination:/ws/investigate/events/count\ncontent-type:application/json\n\n{json.dumps(count_req)}\x00"]))

            for _ in range(12):
                raw = ws.recv()
                if raw.startswith("a["):
                    frames = json.loads(raw[1:])
                    stomp_msg = frames[0]
                    idx = stomp_msg.find("\n\n")
                    body = stomp_msg[idx+2:].rstrip("\x00")
                    data = json.loads(body)
                    count_val = data.get("data")
                    if count_val is not None and isinstance(count_val, (int, float)):
                        return int(count_val)
        except Exception as e:
            logger.error(f"Error fetching event count: {e}")
        finally:
            ws.close()

        return 0

    def fetch_events(
        self,
        endpoint_type: str = "log",
        limit: int = 50,
        hours: int = 24,
        query: str = ""
    ) -> List[Dict[str, Any]]:
        """Streams authentic log or network session records from NetWitness."""
        ws = self._create_ws_connection("/api/investigate/socket")
        if not ws:
            return []

        endpoint_id = (
            CORE_ENDPOINTS["log_concentrator"]["id"]
            if endpoint_type == "log"
            else CORE_ENDPOINTS["network_concentrator"]["id"]
        )

        now = int(time.time())
        from_time = now - (hours * 3600)

        req_payload = {
            "filter": [
                {"field": "endpointId", "value": endpoint_id},
                {"field": "timeRange", "range": {"from": from_time, "to": now}},
                {"field": "query", "value": query},
                {"field": "searchTerm", "value": ""}
            ],
            "stream": {
                "limit": limit,
                "batch": min(limit, 50)
            }
        }

        sub_id = "sub-stream-" + uuid.uuid4().hex[:6]
        events_raw: List[Dict[str, Any]] = []

        try:
            ws.send(json.dumps([f"SUBSCRIBE\nid:{sub_id}\ndestination:/user/queue/investigate/events\n\n\x00"]))
            ws.send(json.dumps([f"SEND\ndestination:/ws/investigate/events/stream\ncontent-type:application/json\n\n{json.dumps(req_payload)}\x00"]))

            for _ in range(20):
                raw = ws.recv()
                if raw.startswith("a["):
                    frames = json.loads(raw[1:])
                    stomp_msg = frames[0]
                    idx = stomp_msg.find("\n\n")
                    body = stomp_msg[idx+2:].rstrip("\x00")
                    try:
                        msg_obj = json.loads(body)
                        data = msg_obj.get("data")
                        if isinstance(data, list) and len(data) > 0:
                            events_raw.extend(data)
                            if len(events_raw) >= limit:
                                break
                    except Exception:
                        pass
                elif raw == "h":
                    pass
        except Exception as e:
            logger.error(f"Error streaming events from NetWitness: {e}")
        finally:
            ws.close()

        # Transform raw meta tuples into normalized SIEM events
        normalized: List[Dict[str, Any]] = []
        for raw_ev in events_raw[:limit]:
            session_id = raw_ev.get("sessionId")
            timestamp = raw_ev.get("time")
            source_node = raw_ev.get("sourceId")
            metas = dict(raw_ev.get("metas", []))

            # Derive standardized SIEM event attributes
            dev_type = metas.get("device.type") or ("Network Packet/Stream" if endpoint_type == "network" else "syslog")
            dev_class = metas.get("device.class") or ("Network Sensor" if endpoint_type == "network" else "Host")
            dev_ip = metas.get("device.ip") or metas.get("ip.src") or metas.get("ipv6.src", "")
            dev_host = metas.get("device.host") or metas.get("event.computer") or metas.get("did", "")

            src_ip = metas.get("ip.src") or metas.get("ipv6.src") or dev_ip
            dst_ip = metas.get("ip.dst") or metas.get("ipv6.dst", "")
            dst_port = metas.get("ip.dstport") or metas.get("udp.dstport") or metas.get("tcp.dstport") or metas.get("port.dst.all", "")

            msg_id = metas.get("msg.id", "")
            desc = (
                metas.get("event.desc")
                or metas.get("event.cat.name")
                or (f"{dev_type} event ({msg_id})" if msg_id else f"{endpoint_type.upper()} Telemetry")
            )

            action = metas.get("action") or metas.get("result.code") or ("DETECTED" if endpoint_type == "network" else "LOGGED")
            user = metas.get("user.src") or metas.get("user.dst") or metas.get("user.all", "")

            normalized.append({
                "session_id": session_id,
                "timestamp": timestamp,
                "source": "RSA NetWitness SIEM",
                "endpoint_type": endpoint_type,
                "source_node": source_node,
                "device_type": dev_type,
                "device_class": dev_class,
                "device_ip": dev_ip,
                "device_host": dev_host,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "action": action,
                "user": user,
                "description": desc,
                "severity": "HIGH" if "alert" in desc.lower() or "threat" in desc.lower() else "MEDIUM" if "error" in desc.lower() else "LOW",
                "size_bytes": metas.get("size", 0),
                "raw_metas": metas
            })

        return normalized

    def sync_to_opensoc(self, log_limit: int = 100, net_limit: int = 50, hours: int = 48) -> Dict[str, Any]:
        """Fetches both log and network events from NetWitness and persists them for OpenSOC Forge Event Search."""
        existing = load_synced_netwitness_events()
        
        # 1. Fetch Log Concentrator Events
        log_events = self.fetch_events(endpoint_type="log", limit=log_limit, hours=hours)
        
        # 2. Fetch Network Concentrator Sessions
        net_events = self.fetch_events(endpoint_type="network", limit=net_limit, hours=hours)
        
        combined = existing + log_events + net_events
        save_synced_netwitness_events(combined)
        
        return {
            "status": "SUCCESS",
            "synced_logs": len(log_events),
            "synced_network": len(net_events),
            "total_synced": len(log_events) + len(net_events),
            "total_persisted": len(load_synced_netwitness_events()),
            "synced_at": datetime_now_iso()
        }


# Global Singleton Client
netwitness_client = NetWitnessClient()


def datetime_now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# File path for persisting NetWitness synced events
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
CONFIGS_DIR = os.path.join(REPO_ROOT, "configs")
NETWITNESS_SYNC_FILE = os.path.join(CONFIGS_DIR, "netwitness_synced_events.json")


def load_synced_netwitness_events() -> List[Dict[str, Any]]:
    """Loads previously synchronized NetWitness events from local JSON storage."""
    if not os.path.exists(NETWITNESS_SYNC_FILE):
        return []
    try:
        with open(NETWITNESS_SYNC_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading NetWitness synced events: {e}")
        return []


def save_synced_netwitness_events(events: List[Dict[str, Any]]) -> bool:
    """Persists synced NetWitness events to disk."""
    try:
        os.makedirs(CONFIGS_DIR, exist_ok=True)
        # Deduplicate by session_id + endpoint_type
        seen = set()
        deduped = []
        for ev in events:
            key = f"{ev.get('endpoint_type')}-{ev.get('session_id')}"
            if key not in seen:
                seen.add(key)
                deduped.append(ev)
        
        # Keep latest 1000 events
        deduped = deduped[-1000:]
        with open(NETWITNESS_SYNC_FILE, "w", encoding="utf-8") as f:
            json.dump(deduped, f, indent=2, default=str)
        return True
    except Exception as e:
        logger.error(f"Error saving NetWitness synced events: {e}")
        return False

