# Script to integrate RSA NetWitness SIEM view into frontend/index.html
import re

with open('frontend/index.html', 'r', encoding='utf-8') as f:
    html = f.read()

# 1. Add nav item under OPERATIONS
nav_target = 'id: "search",\n\n      label: "Event Investigation",'
nav_replacement = '''id: "netwitness_siem",

      label: "RSA NetWitness SIEM",

      icon: "database",

      badge: "12.5 Live"

    }, {

      id: "search",

      label: "Event Investigation",'''

if 'id: "netwitness_siem"' not in html:
    html = html.replace(nav_target, nav_replacement, 1)
    print("Nav item added.")
else:
    print("Nav item already present.")

# 2. Add state definitions
state_target = '  // Universal Table Sorting States'
state_code = '''  // RSA NetWitness SIEM Integration State
  const [nwClusterStatus, setNwClusterStatus] = useState(null);
  const [nwEvents, setNwEvents] = useState([]);
  const [nwLoading, setNwLoading] = useState(false);
  const [nwSyncing, setNwSyncing] = useState(false);
  const [nwTab, setNwTab] = useState("log");
  const [nwSortField, setNwSortField] = useState("timestamp");
  const [nwSortOrder, setNwSortOrder] = useState("desc");
  const [nwTypeFilter, setNwTypeFilter] = useState("all");
  const [nwSearchQuery, setNwSearchQuery] = useState("");
  const [nwPage, setNwPage] = useState(1);
  const [nwPageSize, setNwPageSize] = useState(25);
  const [nwSelectedEvent, setNwSelectedEvent] = useState(null);

  // Universal Table Sorting States'''

if 'nwClusterStatus' not in html:
    html = html.replace(state_target, state_code, 1)
    print("State variables added.")
else:
    print("State variables already present.")

# 3. Add fetch and sync methods
fetch_target = '  const fetchSophosTelemetry = async (force = false) => {'
fetch_code = '''  const fetchNetWitnessData = async (force = false) => {
    if (!nwClusterStatus) {
      setNwLoading(true);
    }
    try {
      const token = localStorage.getItem("opensoc_token");
      const headers = token ? { "Authorization": `Bearer ${token}` } : {};
      
      const resStatus = await fetch("/api/v1/netwitness/status", { headers });
      if (resStatus.ok) {
        const dataStatus = await resStatus.json();
        setNwClusterStatus(dataStatus);
      }
      
      const resEvents = await fetch(`/api/v1/netwitness/events?endpoint_type=${nwTab}&limit=50&hours=48`, { headers });
      if (resEvents.ok) {
        const dataEvents = await resEvents.json();
        setNwEvents(dataEvents.events || []);
      }
    } catch (e) {
      console.error("Failed to fetch NetWitness data:", e);
    } finally {
      setNwLoading(false);
    }
  };

  const syncNetWitnessData = async () => {
    setNwSyncing(true);
    try {
      const token = localStorage.getItem("opensoc_token");
      const headers = token ? { "Authorization": `Bearer ${token}` } : {};
      const res = await fetch("/api/v1/netwitness/sync?log_limit=100&net_limit=50", {
        method: "POST",
        headers
      });
      if (res.ok) {
        const syncData = await res.json();
        if (typeof showToast === "function") {
          showToast(`Synced ${syncData.total_synced} live events from RSA NetWitness!`, "success");
        } else {
          alert(`Successfully synced ${syncData.total_synced} live events from RSA NetWitness!`);
        }
        await fetchNetWitnessData(true);
      }
    } catch (e) {
      alert("NetWitness Sync failed: " + e.message);
    } finally {
      setNwSyncing(false);
    }
  };

  const fetchSophosTelemetry = async (force = false) => {'''

if 'fetchNetWitnessData' not in html:
    html = html.replace(fetch_target, fetch_code, 1)
    print("Fetch methods added.")
else:
    print("Fetch methods already present.")

# 4. Add useEffect hook
hook_target = '    if (currentScreen === "search") {\n\n      executeEventSearch();\n\n    }'
hook_code = '''    if (currentScreen === "netwitness_siem") {

      fetchNetWitnessData();

    }

    if (currentScreen === "search") {

      executeEventSearch();

    }'''

if 'currentScreen === "netwitness_siem"' not in html:
    html = html.replace(hook_target, hook_code, 1)
    print("useEffect hook added.")
else:
    print("useEffect hook already present.")

with open('frontend/index.html', 'w', encoding='utf-8') as f:
    f.write(html)

print("Stage 1 injected successfully!")
