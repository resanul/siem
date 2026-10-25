import re

new_endpoints = '''

# ---------------------------------------------------------
# RSA NetWitness SIEM Integration Endpoints
# ---------------------------------------------------------

@api_router.get("/netwitness/status")
def get_netwitness_cluster_status():
    """Returns RSA NetWitness SIEM cluster connectivity, health, and core services status."""
    from backend.app.services.netwitness_siem import netwitness_client
    return netwitness_client.get_cluster_status()


@api_router.get("/netwitness/events")
def get_netwitness_events(
    endpoint_type: str = Query("log", regex="^(log|network)$"),
    limit: int = Query(50, ge=1, le=500),
    hours: int = Query(24, ge=1, le=168),
    query: str = Query("", max_length=500)
):
    """Streams live log or network telemetry events directly from RSA NetWitness Core Services."""
    from backend.app.services.netwitness_siem import netwitness_client
    events = netwitness_client.fetch_events(
        endpoint_type=endpoint_type,
        limit=limit,
        hours=hours,
        query=query
    )
    return {
        "status": "SUCCESS",
        "endpoint_type": endpoint_type,
        "count": len(events),
        "hours": hours,
        "events": events
    }


@api_router.get("/netwitness/count")
def get_netwitness_event_count(
    endpoint_type: str = Query("log", regex="^(log|network)$"),
    hours: int = Query(24, ge=1, le=168)
):
    """Returns total indexed sessions/events count in NetWitness for given time range."""
    from backend.app.services.netwitness_siem import netwitness_client
    count = netwitness_client.get_event_count(endpoint_type=endpoint_type, hours=hours)
    return {
        "status": "SUCCESS",
        "endpoint_type": endpoint_type,
        "hours": hours,
        "count": count
    }


@api_router.post("/netwitness/sync")
def sync_netwitness_to_opensoc(
    log_limit: int = Query(100, ge=10, le=500),
    net_limit: int = Query(50, ge=10, le=500),
    hours: int = Query(48, ge=1, le=168)
):
    """Ingests and synchronizes live RSA NetWitness SIEM logs and network sessions into OpenSOC Forge Event Search."""
    from backend.app.services.netwitness_siem import netwitness_client
    return netwitness_client.sync_to_opensoc(
        log_limit=log_limit,
        net_limit=net_limit,
        hours=hours
    )
'''

with open("backend/app/api/v1/api.py", "r", encoding="utf-8") as f:
    code = f.read()

if "/netwitness/status" not in code:
    code = code.rstrip() + "\n" + new_endpoints + "\n"
    with open("backend/app/api/v1/api.py", "w", encoding="utf-8") as f:
        f.write(code)
    print("NetWitness endpoints appended successfully!")
else:
    print("Endpoints already present.")
