# Technical Analysis Report: Event Investigation & Query Console UI Architecture (R2)

**Explorer**: Explorer 2 (Frontend UI Architecture)  
**Date**: 2026-10-18  
**Working Directory**: `d:\AI\siem\.agents\teamwork\teamwork_preview_explorer_survey_2`  
**Target Files**: `frontend/index.html` (lines ~230-300, ~850-890, ~2480-2520)

---

## 1. Executive Summary

This report delivers a deep architectural exploration of the frontend implementation for the **Event Investigation & Query Console (Requirement R2)** in OpenSOC Forge. 

Currently, navigating to `currentScreen === "search"` renders a static HTML mockup (lines 2480–2518 of `frontend/index.html`) featuring hardcoded input values, static hits ("42 hits in 18ms"), and two static log divs. No state binding, API requests, dynamic event lists, modals, time range pickers, or filter chips currently exist for this screen.

Because OpenSOC Forge operates in air-gapped/offline production environments, `frontend/index.html` is structured as a **zero-transpile, self-contained single-page React 18 application** using UMD `window.React` and `React.createElement` syntax without runtime Babel. This design ensures instant load performance and zero build-step overhead.

We provide a complete, drop-in technical specification for replacing the static mockup with a fully reactive, high-performance console that connects to `POST /api/v1/events/search` (and `GET`), with auto-load on screen entry, responsive timing metrics, preset chips, dynamic badges, empty state recommendations, and an interactive raw JSON telemetry inspector modal with one-click clipboard copying.

---

## 2. Frontend Architecture & Technology Stack

### 2.1 Runtime & Framework Structure
- **Framework**: React 18.2.0 (UMD build: `vendor/react.production.min.js`, fallback to CDN).
- **DOM Engine**: ReactDOM 18.2.0 (`vendor/react-dom.production.min.js`).
- **Icons**: Lucide Icons 1.59.0 (`vendor/lucide.min.js`), initialized dynamically via `data-lucide` attributes and `window.lucide.createIcons()`.
- **CSS Engine**: Tailwind CSS (`vendor/tailwind.min.js`) configured via inline `tailwind.config` with custom brand palette.
- **Transpilation Mode**: **NO runtime Babel, NO build step**. All components are written in standard ECMAScript using `React.createElement(tag, props, ...children)` with React Hooks (`useState`, `useEffect`, `useMemo`).
- **Static Hosting**: Served directly by FastAPI via `backend/app/main.py` mounted at `/console` (`StaticFiles(directory="frontend", html=True)`).

### 2.2 Theme & Styling Conventions
The console strictly adheres to an enterprise cybersecurity dark theme:
- Background primary: `#080c14` (`brand.dark`)
- Surface / Panel: `#0e1422` (`brand.surface`)
- Card / Item: `#131b2e` (`brand.card`)
- Border: `#1f293d` (`brand.border`)
- Accent / Brand: `#00ff41` (Emerald / Neon Green) and `#38bdf8` (Sky blue)
- Typography: Sans-serif (`Inter`) for UI controls; monospace (`JetBrains Mono`, `ui-monospace`) for timestamps, queries, hostnames, and JSON payloads.

### 2.3 Icon Lifecycle
Lucide icons are rendered using `<i data-lucide="..."></i>`. In `frontend/index.html` (lines 850–860), a `useEffect` listens to state changes and calls `requestAnimationFrame(() => window.lucide.createIcons())`. Whenever new search results or modals are rendered, the icons must be re-processed.

---

## 3. Deep-Dive: Existing `currentScreen === "search"` Implementation

### 3.1 Code Inspection (lines 2480–2518)
The existing implementation is 100% static:

```javascript
currentScreen === "search" && /*#__PURE__*/React.createElement("div", {
  className: "space-y-4"
}, /*#__PURE__*/React.createElement("h2", {
  className: "text-xl font-bold text-slate-100"
}, "Event Investigation & Query Console"), /*#__PURE__*/React.createElement("p", {
  className: "text-xs text-slate-400"
}, "KQL/Lucene query syntax against normalized indices: ", /*#__PURE__*/React.createElement("code", null, "suricata-*"), ", ", /*#__PURE__*/React.createElement("code", null, "wazuh-alerts-*"), ", ", /*#__PURE__*/React.createElement("code", null, "syslog-*"), "."), /*#__PURE__*/React.createElement("div", {
  className: "flex space-x-2"
}, /*#__PURE__*/React.createElement("input", {
  type: "text",
  defaultValue: "host.name:\"web-app-dmz-01\" AND event.category:\"network\"",
  className: "flex-1 bg-[#0e1422] border border-[#1f293d] rounded px-3 py-2 text-xs font-mono text-emerald-400 focus:outline-none focus:border-emerald-500"
}), /*#__PURE__*/React.createElement("button", {
  className: "px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-bold text-xs rounded font-mono"
}, "Execute Query")), /*#__PURE__*/React.createElement("div", {
  className: "bg-[#0e1422] p-4 rounded-lg border border-[#1f293d]"
}, /*#__PURE__*/React.createElement("div", {
  className: "flex justify-between items-center text-xs text-slate-400 border-b border-[#1f293d] pb-2 mb-3"
}, /*#__PURE__*/React.createElement("span", null, "Query Results: 42 hits in 18ms"), /*#__PURE__*/React.createElement("span", {
  className: "font-mono"
}, "Time range: Last 24 Hours")), /*#__PURE__*/React.createElement("div", {
  className: "space-y-2 font-mono text-xs"
}, /*#__PURE__*/React.createElement("div", {
  className: "p-2.5 rounded bg-[#131b2e] border border-[#1f293d] hover:border-slate-600 cursor-pointer"
}, /*#__PURE__*/React.createElement("div", {
  className: "flex justify-between text-[11px] text-slate-400"
}, /*#__PURE__*/React.createElement("span", null, "2026-10-14 20:12:45.102"), /*#__PURE__*/React.createElement("span", {
  className: "text-purple-400"
}, "suricata.eve.alert")), /*#__PURE__*/React.createElement("div", {
  className: "text-slate-200 mt-1"
}, "CVE-2021-44228 Log4j JNDI pattern observed in URI header from 10.0.1.15 to 198.51.100.84:1389")), /*#__PURE__*/React.createElement("div", {
  className: "p-2.5 rounded bg-[#131b2e] border border-[#1f293d] hover:border-slate-600 cursor-pointer"
}, /*#__PURE__*/React.createElement("div", {
  className: "flex justify-between text-[11px] text-slate-400"
}, /*#__PURE__*/React.createElement("span", null, "2026-10-14 20:18:10.450"), /*#__PURE__*/React.createElement("span", {
  className: "text-sky-400"
}, "wazuh.syscheck")), /*#__PURE__*/React.createElement("div", {
  className: "text-slate-200 mt-1"
}, "FIM file integrity altered: /usr/bin/sudo size changed from 182400 to 194012 bytes")))))
```

### 3.2 Gaps Identified Against Requirement R2
1. **Unbound Input**: `<input>` uses `defaultValue` without `value` or `onChange` state binding. Pressing Enter does nothing.
2. **Static Trigger**: "Execute Query" button has no `onClick` handler.
3. **Hardcoded Metrics**: Displays static `"Query Results: 42 hits in 18ms"` and static `"Time range: Last 24 Hours"`.
4. **No Time Range Controls**: No selector to switch between `15m`, `1h`, `24h`, `7d`, `all`.
5. **No Preset Chips**: Missing quick-filter chips for indices and common KQL filters (`suricata-*`, `wazuh-alerts-*`, `event.category:network`, etc.).
6. **Hardcoded Data**: Only two hardcoded sample cards; does not dynamically render live backend search results.
7. **No Detail Modal**: Clicking a result row does nothing; no formatted JSON inspector modal exists.
8. **No Copy Feature**: No clipboard copy button for raw JSON.
9. **No Empty State**: Does not handle zero-result queries with actionable suggestions.
10. **No Auto-Load**: Does not fetch recent events upon screen mount or navigation.

---

## 4. Frontend API Communication Architecture

### 4.1 Base URL & Routing
All API calls are relative to `/api/v1/` (e.g. `/api/v1/events/search`). This eliminates hardcoded hostname/port issues across development (`localhost:8000`), container deployments, and production server IP addresses.

### 4.2 Authentication Headers
Authentication tokens are stored in `localStorage.getItem("token")`.
The standard headers helper used throughout `index.html`:
```javascript
const token = localStorage.getItem("token") || "";
const headers = {
  "Content-Type": "application/json",
  ...(token ? { "Authorization": `Bearer ${token}` } : {})
};
```

### 4.3 Request Payload Specification
The backend endpoint accepts POST payloads conforming to:
```json
{
  "query": "*",
  "indices": ["*"],
  "time_range": "24h",
  "limit": 100
}
```

### 4.4 Response Payload Specification
```json
{
  "total_hits": 12,
  "took_ms": 14,
  "indices_searched": ["suricata-*", "wazuh-alerts-*", "syslog-*"],
  "events": [
    {
      "id": "evt-001",
      "timestamp": "2026-10-18T19:20:00Z",
      "index": "suricata-eve",
      "source_type": "suricata.eve.alert",
      "host": "web-app-dmz-01",
      "severity": "CRITICAL",
      "summary": "ET EXPLOIT Possible Log4j RCE Attempt",
      "raw": { ... }
    }
  ]
}
```

---

## 5. Concrete Technical Strategy for R2 Implementation

### 5.1 New React State Variables in `App()`
The following state variables should be added in `App()` (around line 236):
```javascript
// Event Investigation & Search Console State
const [eventQuery, setEventQuery] = useState("*");
const [eventTimeRange, setEventTimeRange] = useState("24h");
const [eventSelectedIndices, setEventSelectedIndices] = useState(["*"]);
const [eventResults, setEventResults] = useState([]);
const [eventTotalHits, setEventTotalHits] = useState(0);
const [eventTookMs, setEventTookMs] = useState(0);
const [eventIndicesSearched, setEventIndicesSearched] = useState([]);
const [eventLoading, setEventLoading] = useState(false);
const [eventError, setEventError] = useState(null);
const [selectedEvent, setSelectedEvent] = useState(null);
const [eventCopied, setEventCopied] = useState(false);
const [eventHasSearched, setEventHasSearched] = useState(false);
```

### 5.2 Search Execution Handler (`executeEventSearch`)
```javascript
const executeEventSearch = async (overrideQuery, overrideTimeRange, overrideIndices) => {
  const q = overrideQuery !== undefined ? overrideQuery : eventQuery;
  const tr = overrideTimeRange !== undefined ? overrideTimeRange : eventTimeRange;
  const idx = overrideIndices !== undefined ? overrideIndices : eventSelectedIndices;

  setEventLoading(true);
  setEventError(null);
  const startMs = Date.now();

  try {
    const token = localStorage.getItem("token") || "";
    const headers = {
      "Content-Type": "application/json",
      ...(token ? { "Authorization": `Bearer ${token}` } : {})
    };

    const payload = {
      query: (q && q.trim()) ? q.trim() : "*",
      time_range: tr || "24h",
      indices: Array.isArray(idx) && idx.length > 0 ? idx : ["*"],
      limit: 100
    };

    const res = await fetch("/api/v1/events/search", {
      method: "POST",
      headers: headers,
      body: JSON.stringify(payload)
    });

    if (res.ok) {
      const data = await res.json();
      const incomingEvents = Array.isArray(data.events) ? data.events : [];
      setEventResults(incomingEvents);
      setEventTotalHits(typeof data.total_hits === "number" ? data.total_hits : incomingEvents.length);
      setEventTookMs(typeof data.took_ms === "number" ? data.took_ms : (Date.now() - startMs));
      setEventIndicesSearched(Array.isArray(data.indices_searched) ? data.indices_searched : ["*"]);
      setEventHasSearched(true);
    } else {
      const errJson = await res.json().catch(() => ({}));
      setEventError(errJson.detail || `Search query returned HTTP ${res.status}`);
    }
  } catch (err) {
    console.error("Event search request failed:", err);
    setEventError("Failed to reach search backend. Ensure OpenSOC Forge API service is active.");
  } finally {
    setEventLoading(false);
  }
};
```

### 5.3 Auto-Load on Screen Entry / Mount
Hook into the existing `useEffect` on `[currentScreen]` (around line 862):
```javascript
if (currentScreen === "search") {
  executeEventSearch();
}
```
If the user opens the application directly on the `search` screen (from localStorage `opensoc_current_screen`), or switches from another tab, events load immediately.

### 5.4 Lucide Icon Lifecycle Extension
Add search state triggers to the Lucide icon `useEffect` dependency array (line 860):
`[..., eventResults, eventLoading, selectedEvent, eventCopied]`
This guarantees all Lucide icons (`search`, `clock`, `copy`, `check`, `server`, `alert-triangle`, `refresh-cw`, `x`) render properly as dynamic DOM elements appear.

### 5.5 Clipboard Copying with Air-Gap Resilience
Certain enterprise and lab browsers accessed via HTTP or non-localhost IPs restrict `navigator.clipboard`. A resilient copy helper is provided:
```javascript
const handleCopyEventJson = (eventObj) => {
  const jsonStr = JSON.stringify(eventObj ? (eventObj.raw || eventObj) : {}, null, 2);
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(jsonStr).then(() => {
      setEventCopied(true);
      setTimeout(() => setEventCopied(false), 2000);
    }).catch(() => fallbackCopyText(jsonStr));
  } else {
    fallbackCopyText(jsonStr);
  }
};

const fallbackCopyText = (text) => {
  try {
    const el = document.createElement("textarea");
    el.value = text;
    el.style.position = "fixed";
    el.style.left = "-9999px";
    document.body.appendChild(el);
    el.select();
    document.execCommand("copy");
    document.body.removeChild(el);
    setEventCopied(true);
    setTimeout(() => setEventCopied(false), 2000);
  } catch (e) {
    console.warn("Clipboard copy failed:", e);
  }
};
```

### 5.6 Quick Filter Presets / Chips
```javascript
const eventPresets = [
  { label: "All Telemetry (*)", query: "*" },
  { label: "Suricata NIDS", query: "suricata-*" },
  { label: "Wazuh Alerts", query: "wazuh-alerts-*" },
  { label: "Syslog Stream", query: "syslog-*" },
  { label: "Network Category", query: "event.category:network" },
  { label: "Critical Severity", query: "severity:CRITICAL" },
  { label: "DMZ Host", query: "host.name:\"web-app-dmz-01\"" },
  { label: "MITRE Execution", query: "mitre.tactic:Execution" }
];
```
When clicked:
```javascript
onClick: () => {
  setEventQuery(p.query);
  executeEventSearch(p.query, eventTimeRange);
}
```

### 5.7 Color-Coded Badges & Styling Helpers
- **Source Type Badges**:
  - `suricata`: `bg-purple-500/10 text-purple-400 border-purple-500/30`
  - `wazuh`: `bg-sky-500/10 text-sky-400 border-sky-500/30`
  - `syslog` / `auth`: `bg-teal-500/10 text-teal-400 border-teal-500/30`
  - `sim` / `atomic`: `bg-amber-500/10 text-amber-400 border-amber-500/30`
- **Severity Badges**:
  - `CRITICAL`: `bg-rose-500/10 text-rose-400 border-rose-500/30`
  - `HIGH`: `bg-amber-500/10 text-amber-400 border-amber-500/30`
  - `MEDIUM`: `bg-yellow-500/10 text-yellow-400 border-yellow-500/30`
  - `LOW` / `INFORMATIONAL` / `INFO`: `bg-sky-500/10 text-sky-400 border-sky-500/30`

---

## 6. Detailed Replacement Blueprint for `frontend/index.html`

### 6.1 State & Handlers Insertion Point
Insert directly after line 236 (`const [searchQuery, setSearchQuery] = useState("");`):
```javascript
  // Event Investigation & Search Console State (R2)
  const [eventQuery, setEventQuery] = useState("*");
  const [eventTimeRange, setEventTimeRange] = useState("24h");
  const [eventSelectedIndices, setEventSelectedIndices] = useState(["*"]);
  const [eventResults, setEventResults] = useState([]);
  const [eventTotalHits, setEventTotalHits] = useState(0);
  const [eventTookMs, setEventTookMs] = useState(0);
  const [eventIndicesSearched, setEventIndicesSearched] = useState([]);
  const [eventLoading, setEventLoading] = useState(false);
  const [eventError, setEventError] = useState(null);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [eventCopied, setEventCopied] = useState(false);
  const [eventHasSearched, setEventHasSearched] = useState(false);

  const executeEventSearch = async (overrideQuery, overrideTimeRange, overrideIndices) => {
    const q = overrideQuery !== undefined ? overrideQuery : eventQuery;
    const tr = overrideTimeRange !== undefined ? overrideTimeRange : eventTimeRange;
    const idx = overrideIndices !== undefined ? overrideIndices : eventSelectedIndices;

    setEventLoading(true);
    setEventError(null);
    const startMs = Date.now();

    try {
      const token = localStorage.getItem("token") || "";
      const headers = {
        "Content-Type": "application/json",
        ...(token ? { "Authorization": `Bearer ${token}` } : {})
      };

      const payload = {
        query: (q && q.trim()) ? q.trim() : "*",
        time_range: tr || "24h",
        indices: Array.isArray(idx) && idx.length > 0 ? idx : ["*"],
        limit: 100
      };

      const res = await fetch("/api/v1/events/search", {
        method: "POST",
        headers: headers,
        body: JSON.stringify(payload)
      });

      if (res.ok) {
        const data = await res.json();
        const incomingEvents = Array.isArray(data.events) ? data.events : [];
        setEventResults(incomingEvents);
        setEventTotalHits(typeof data.total_hits === "number" ? data.total_hits : incomingEvents.length);
        setEventTookMs(typeof data.took_ms === "number" ? data.took_ms : (Date.now() - startMs));
        setEventIndicesSearched(Array.isArray(data.indices_searched) ? data.indices_searched : ["*"]);
        setEventHasSearched(true);
      } else {
        const errJson = await res.json().catch(() => ({}));
        setEventError(errJson.detail || `Search returned HTTP ${res.status}`);
      }
    } catch (err) {
      console.error("Event search request failed:", err);
      setEventError("Network error: Unable to reach search backend.");
    } finally {
      setEventLoading(false);
    }
  };

  const handleCopyEventJson = (eventObj) => {
    const jsonStr = JSON.stringify(eventObj ? (eventObj.raw || eventObj) : {}, null, 2);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(jsonStr).then(() => {
        setEventCopied(true);
        setTimeout(() => setEventCopied(false), 2000);
      }).catch(() => fallbackCopyText(jsonStr));
    } else {
      fallbackCopyText(jsonStr);
    }
  };

  const fallbackCopyText = (text) => {
    try {
      const el = document.createElement("textarea");
      el.value = text;
      el.style.position = "fixed";
      el.style.left = "-9999px";
      document.body.appendChild(el);
      el.select();
      document.execCommand("copy");
      document.body.removeChild(el);
      setEventCopied(true);
      setTimeout(() => setEventCopied(false), 2000);
    } catch (e) {
      console.warn("Fallback copy failed:", e);
    }
  };

  const getSourceBadgeClass = (sourceType, index) => {
    const s = `${sourceType || ""} ${index || ""}`.toLowerCase();
    if (s.includes("suricata")) return "bg-purple-500/10 text-purple-400 border-purple-500/30";
    if (s.includes("wazuh")) return "bg-sky-500/10 text-sky-400 border-sky-500/30";
    if (s.includes("syslog") || s.includes("auth")) return "bg-teal-500/10 text-teal-400 border-teal-500/30";
    if (s.includes("sim") || s.includes("atomic")) return "bg-amber-500/10 text-amber-400 border-amber-500/30";
    return "bg-slate-700/30 text-slate-300 border-slate-600";
  };

  const getSeverityBadgeClass = (severity) => {
    const sev = (severity || "").toUpperCase();
    if (sev === "CRITICAL") return "bg-rose-500/10 text-rose-400 border-rose-500/30";
    if (sev === "HIGH") return "bg-amber-500/10 text-amber-400 border-amber-500/30";
    if (sev === "MEDIUM") return "bg-yellow-500/10 text-yellow-400 border-yellow-500/30";
    return "bg-sky-500/10 text-sky-400 border-sky-500/30";
  };
```

### 6.2 Screen Replacement Code (replacing lines 2480–2518)
```javascript
currentScreen === "search" && /*#__PURE__*/React.createElement("div", {
  className: "space-y-4"
},
  /*#__PURE__*/React.createElement("div", {
    className: "flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-[#1f293d] pb-3"
  },
    /*#__PURE__*/React.createElement("div", null,
      /*#__PURE__*/React.createElement("h2", {
        className: "text-xl font-bold text-slate-100 flex items-center space-x-2"
      },
        /*#__PURE__*/React.createElement("span", null, "Event Investigation & Query Console"),
        /*#__PURE__*/React.createElement("span", {
          className: "px-2 py-0.5 text-[10px] rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-mono"
        }, "LIVE DATA ENGINE")
      ),
      /*#__PURE__*/React.createElement("p", {
        className: "text-xs text-slate-400 mt-0.5"
      }, "KQL/Lucene query syntax against normalized indices: ",
        /*#__PURE__*/React.createElement("code", { className: "text-emerald-400 font-mono" }, "suricata-*"), ", ",
        /*#__PURE__*/React.createElement("code", { className: "text-sky-400 font-mono" }, "wazuh-alerts-*"), ", ",
        /*#__PURE__*/React.createElement("code", { className: "text-teal-400 font-mono" }, "syslog-*"), "."
      )
    ),
    /*#__PURE__*/React.createElement("div", {
      className: "flex items-center space-x-2"
    },
      /*#__PURE__*/React.createElement("span", {
        className: "text-[11px] text-slate-400 font-mono hidden sm:inline"
      }, "Time Window:"),
      /*#__PURE__*/React.createElement("select", {
        value: eventTimeRange,
        onChange: (e) => {
          const nr = e.target.value;
          setEventTimeRange(nr);
          executeEventSearch(eventQuery, nr);
        },
        className: "bg-[#0e1422] border border-[#1f293d] text-xs px-2.5 py-1.5 rounded text-slate-200 font-mono focus:outline-none focus:border-emerald-500"
      },
        /*#__PURE__*/React.createElement("option", { value: "15m" }, "Last 15 Minutes"),
        /*#__PURE__*/React.createElement("option", { value: "1h" }, "Last 1 Hour"),
        /*#__PURE__*/React.createElement("option", { value: "24h" }, "Last 24 Hours"),
        /*#__PURE__*/React.createElement("option", { value: "7d" }, "Last 7 Days"),
        /*#__PURE__*/React.createElement("option", { value: "all" }, "All Telemetry")
      )
    )
  ),

  /* Search Input & Action Bar */
  /*#__PURE__*/React.createElement("div", {
    className: "flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-2"
  },
    /*#__PURE__*/React.createElement("div", {
      className: "relative flex-1"
    },
      /*#__PURE__*/React.createElement("input", {
        type: "text",
        value: eventQuery,
        onChange: (e) => setEventQuery(e.target.value),
        onKeyDown: (e) => {
          if (e.key === "Enter") executeEventSearch();
        },
        placeholder: "Enter KQL/Lucene query (e.g. host.name:\"web-app-dmz-01\", severity:CRITICAL, suricata-*, *)...",
        className: "w-full bg-[#0e1422] border border-[#1f293d] rounded px-3 py-2 text-xs font-mono text-emerald-400 focus:outline-none focus:border-emerald-500 pl-8"
      }),
      /*#__PURE__*/React.createElement("i", {
        "data-lucide": "search",
        className: "w-4 h-4 text-slate-500 absolute left-2.5 top-2.5"
      })
    ),
    /*#__PURE__*/React.createElement("button", {
      onClick: () => executeEventSearch(),
      disabled: eventLoading,
      className: `px-4 py-2 bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 text-slate-950 font-bold text-xs rounded font-mono flex items-center justify-center space-x-1.5 transition-colors shadow-lg shadow-emerald-500/10`
    },
      /*#__PURE__*/React.createElement("i", {
        "data-lucide": eventLoading ? "loader" : "zap",
        className: `w-3.5 h-3.5 ${eventLoading ? "animate-spin" : ""}`
      }),
      /*#__PURE__*/React.createElement("span", null, eventLoading ? "Searching..." : "Execute Query")
    )
  ),

  /* Preset Filter Chips */
  /*#__PURE__*/React.createElement("div", {
    className: "flex items-center space-x-1.5 overflow-x-auto pb-1 text-xs"
  },
    /*#__PURE__*/React.createElement("span", {
      className: "text-[10px] text-slate-500 font-mono uppercase font-bold shrink-0 mr-1"
    }, "Quick Presets:"),
    [
      { label: "All Telemetry (*)", query: "*" },
      { label: "Suricata NIDS", query: "suricata-*" },
      { label: "Wazuh Alerts", query: "wazuh-alerts-*" },
      { label: "Syslog Stream", query: "syslog-*" },
      { label: "Network Category", query: "event.category:network" },
      { label: "Critical Severity", query: "severity:CRITICAL" },
      { label: "DMZ Host", query: "host.name:\"web-app-dmz-01\"" },
      { label: "MITRE Execution", query: "mitre.tactic:Execution" }
    ].map((preset) => {
      const isActive = eventQuery === preset.query;
      return /*#__PURE__*/React.createElement("button", {
        key: preset.query,
        onClick: () => {
          setEventQuery(preset.query);
          executeEventSearch(preset.query, eventTimeRange);
        },
        className: `px-2.5 py-1 rounded text-[11px] font-mono whitespace-nowrap transition-all border ${
          isActive
            ? "bg-emerald-500/20 text-emerald-400 font-bold border-emerald-500/40"
            : "bg-[#0e1422] text-slate-400 hover:text-slate-200 hover:bg-[#131b2e] border-[#1f293d]"
        }`
      }, preset.label);
    })
  ),

  /* Search Error Banner (if any) */
  eventError && /*#__PURE__*/React.createElement("div", {
    className: "p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs flex items-center justify-between"
  },
    /*#__PURE__*/React.createElement("div", { className: "flex items-center space-x-2" },
      /*#__PURE__*/React.createElement("i", { "data-lucide": "alert-triangle", className: "w-4 h-4 shrink-0" }),
      /*#__PURE__*/React.createElement("span", null, eventError)
    ),
    /*#__PURE__*/React.createElement("button", {
      onClick: () => executeEventSearch(),
      className: "px-2.5 py-1 bg-rose-500/20 hover:bg-rose-500/30 rounded text-[10px] font-mono font-bold"
    }, "Retry")
  ),

  /* Results Container */
  /*#__PURE__*/React.createElement("div", {
    className: "bg-[#0e1422] p-4 rounded-lg border border-[#1f293d] space-y-3"
  },
    /* Results Timing & Metrics Header */
    /*#__PURE__*/React.createElement("div", {
      className: "flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-slate-400 border-b border-[#1f293d] pb-2.5"
    },
      /*#__PURE__*/React.createElement("div", {
        className: "flex items-center space-x-2"
      },
        eventLoading
          ? /*#__PURE__*/React.createElement("div", {
              className: "flex items-center space-x-2 text-emerald-400 font-mono"
            },
              /*#__PURE__*/React.createElement("i", { "data-lucide": "loader", className: "w-3.5 h-3.5 animate-spin" }),
              /*#__PURE__*/React.createElement("span", null, "Executing cluster query across datastores...")
            )
          : /*#__PURE__*/React.createElement("div", {
              className: "flex items-center space-x-2 flex-wrap gap-y-1 font-mono"
            },
              /*#__PURE__*/React.createElement("span", {
                className: "font-bold text-slate-200"
              }, `Query Results: ${eventTotalHits} hit${eventTotalHits === 1 ? "" : "s"} in ${eventTookMs}ms`),
              eventIndicesSearched && eventIndicesSearched.length > 0 && /*#__PURE__*/React.createElement("div", {
                className: "hidden md:inline-flex items-center space-x-1"
              },
                eventIndicesSearched.map((idx) => /*#__PURE__*/React.createElement("span", {
                  key: idx,
                  className: "px-1.5 py-0.2 text-[9px] bg-slate-800 border border-slate-700 text-slate-400 rounded"
                }, idx))
              )
            )
      ),
      /*#__PURE__*/React.createElement("div", {
        className: "flex items-center space-x-2 font-mono text-[11px]"
      },
        /*#__PURE__*/React.createElement("span", null, `Range: ${eventTimeRange === "all" ? "All Telemetry" : eventTimeRange}`),
        /*#__PURE__*/React.createElement("button", {
          onClick: () => executeEventSearch(),
          disabled: eventLoading,
          title: "Refresh Query Results",
          className: "p-1 rounded bg-[#131b2e] hover:bg-[#1f293d] border border-[#1f293d] text-slate-300 hover:text-white transition-colors"
        }, /*#__PURE__*/React.createElement("i", {
          "data-lucide": "refresh-cw",
          className: `w-3 h-3 ${eventLoading ? "animate-spin" : ""}`
        }))
      )
    ),

    /* Dynamic Event List / Empty State */
    (!eventLoading && eventResults.length === 0)
      ? /* Empty State */
        /*#__PURE__*/React.createElement("div", {
          className: "p-8 text-center bg-[#080c14]/40 border border-dashed border-[#1f293d] rounded-lg space-y-4"
        },
          /*#__PURE__*/React.createElement("div", {
            className: "w-12 h-12 mx-auto rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center text-slate-400"
          }, /*#__PURE__*/React.createElement("i", { "data-lucide": "search", className: "w-6 h-6 text-slate-400" })),
          /*#__PURE__*/React.createElement("div", { className: "space-y-1" },
            /*#__PURE__*/React.createElement("h3", {
              className: "text-sm font-bold text-slate-200"
            }, "No Telemetry Events Found"),
            /*#__PURE__*/React.createElement("p", {
              className: "text-xs text-slate-400 max-w-md mx-auto"
            }, `No events matched your query "${eventQuery}" within time range "${eventTimeRange}".`)
          ),
          /*#__PURE__*/React.createElement("div", {
            className: "p-3 bg-[#131b2e] border border-[#1f293d] rounded text-left max-w-md mx-auto text-xs text-slate-400 space-y-1 font-sans"
          },
            /*#__PURE__*/React.createElement("span", {
              className: "font-bold text-slate-300 block text-[11px]"
            }, "Actionable Suggestions:"),
            /*#__PURE__*/React.createElement("p", null, "• Broaden your search term or use wildcard ", /*#__PURE__*/React.createElement("code", { className: "text-emerald-400 font-mono" }, "*")),
            /*#__PURE__*/React.createElement("p", null, "• Increase time range to 'Last 7 Days' or 'All Telemetry'"),
            /*#__PURE__*/React.createElement("p", null, "• Click a preset chip above (e.g. suricata-* or wazuh-alerts-*)")
          ),
          /*#__PURE__*/React.createElement("button", {
            onClick: () => {
              setEventQuery("*");
              setEventTimeRange("all");
              executeEventSearch("*", "all");
            },
            className: "px-4 py-2 bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-emerald-400 font-mono text-xs rounded transition-colors"
          }, "Reset Search to All Events (*)")
        )
      : /* Dynamic Events List */
        /*#__PURE__*/React.createElement("div", {
          className: "space-y-2 font-mono text-xs max-h-[620px] overflow-y-auto pr-1"
        },
          eventResults.map((ev, idx) => /*#__PURE__*/React.createElement("div", {
            key: ev.id || `${ev.timestamp}-${idx}`,
            onClick: () => setSelectedEvent(ev),
            className: "p-3 rounded bg-[#131b2e] border border-[#1f293d] hover:border-emerald-500/40 hover:bg-[#162038] cursor-pointer transition-all space-y-1.5 group"
          },
            /* Card Header: Timestamp, Source, Host, Severity, Index */
            /*#__PURE__*/React.createElement("div", {
              className: "flex flex-wrap items-center justify-between gap-2 text-[11px]"
            },
              /*#__PURE__*/React.createElement("div", {
                className: "flex items-center space-x-2 flex-wrap gap-y-1"
              },
                /*#__PURE__*/React.createElement("span", {
                  className: "text-slate-400 font-mono text-[11px]"
                }, ev.timestamp || "-"),
                /*#__PURE__*/React.createElement("span", {
                  className: `px-2 py-0.5 rounded text-[10px] font-mono border ${getSourceBadgeClass(ev.source_type, ev.index)}`
                }, ev.source_type || ev.index || "telemetry"),
                /*#__PURE__*/React.createElement("span", {
                  className: "px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px] border border-slate-700"
                }, ev.host || "unknown-host")
              ),
              /*#__PURE__*/React.createElement("div", {
                className: "flex items-center space-x-2"
              },
                /*#__PURE__*/React.createElement("span", {
                  className: `px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadgeClass(ev.severity)}`
                }, (ev.severity || "INFO").toUpperCase()),
                ev.index && /*#__PURE__*/React.createElement("span", {
                  className: "text-[10px] text-slate-500 font-mono hidden sm:inline"
                }, ev.index)
              )
            ),
            /* Card Body: Summary */
            /*#__PURE__*/React.createElement("div", {
              className: "text-slate-200 text-xs font-sans group-hover:text-emerald-300 transition-colors line-clamp-2"
            }, ev.summary || ev.title || ev.message || "Telemetry event observed"),
            /* Card Footer: Quick Pivot Hint */
            /*#__PURE__*/React.createElement("div", {
              className: "flex justify-between items-center text-[10px] text-slate-500 font-mono pt-1 border-t border-[#1f293d]/50"
            },
              /*#__PURE__*/React.createElement("span", null, `ID: ${ev.id || "evt-raw"}`),
              /*#__PURE__*/React.createElement("span", {
                className: "text-emerald-400/80 group-hover:text-emerald-300 flex items-center space-x-1"
              }, "Click to inspect raw JSON payload \u2192")
            )
          ))
        )
  ),

  /* Event Detail Modal (Raw Formatted JSON with One-Click Copy) */
  selectedEvent && /*#__PURE__*/React.createElement("div", {
    className: "fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in",
    onClick: (e) => {
      if (e.target === e.currentTarget) setSelectedEvent(null);
    }
  },
    /*#__PURE__*/React.createElement("div", {
      className: "bg-[#0e1422] border border-[#1f293d] rounded-xl shadow-2xl max-w-4xl w-full p-6 space-y-4 text-slate-200 font-sans max-h-[90vh] flex flex-col"
    },
      /* Modal Header */
      /*#__PURE__*/React.createElement("div", {
        className: "flex items-start justify-between border-b border-[#1f293d] pb-3"
      },
        /*#__PURE__*/React.createElement("div", { className: "space-y-1" },
          /*#__PURE__*/React.createElement("div", {
            className: "flex items-center space-x-2"
          },
            /*#__PURE__*/React.createElement("span", {
              className: "text-xs font-mono text-emerald-400 font-bold"
            }, "EVENT TELEMETRY INSPECTOR"),
            /*#__PURE__*/React.createElement("span", {
              className: `px-2 py-0.5 rounded text-[10px] font-mono border ${getSourceBadgeClass(selectedEvent.source_type, selectedEvent.index)}`
            }, selectedEvent.source_type || selectedEvent.index || "event"),
            /*#__PURE__*/React.createElement("span", {
              className: `px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadgeClass(selectedEvent.severity)}`
            }, (selectedEvent.severity || "INFO").toUpperCase())
          ),
          /*#__PURE__*/React.createElement("h3", {
            className: "text-base font-bold text-slate-100"
          }, selectedEvent.summary || selectedEvent.title || "Raw Telemetry Event Record")
        ),
        /*#__PURE__*/React.createElement("button", {
          onClick: () => setSelectedEvent(null),
          className: "text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-[#1a2333] transition-colors"
        }, /*#__PURE__*/React.createElement("i", { "data-lucide": "x", className: "w-5 h-5" }))
      ),

      /* Modal Metadata Bar */
      /*#__PURE__*/React.createElement("div", {
        className: "grid grid-cols-2 md:grid-cols-4 gap-3 p-3 bg-[#131b2e] rounded-lg border border-[#1f293d] text-xs font-mono"
      },
        /*#__PURE__*/React.createElement("div", null,
          /*#__PURE__*/React.createElement("span", { className: "text-[10px] text-slate-500 block uppercase" }, "Event ID"),
          /*#__PURE__*/React.createElement("span", { className: "text-slate-200 font-bold truncate block" }, selectedEvent.id || "-")
        ),
        /*#__PURE__*/React.createElement("div", null,
          /*#__PURE__*/React.createElement("span", { className: "text-[10px] text-slate-500 block uppercase" }, "Timestamp"),
          /*#__PURE__*/React.createElement("span", { className: "text-slate-200 block truncate" }, selectedEvent.timestamp || "-")
        ),
        /*#__PURE__*/React.createElement("div", null,
          /*#__PURE__*/React.createElement("span", { className: "text-[10px] text-slate-500 block uppercase" }, "Host / Endpoint"),
          /*#__PURE__*/React.createElement("span", { className: "text-emerald-400 font-bold block truncate" }, selectedEvent.host || "unknown")
        ),
        /*#__PURE__*/React.createElement("div", null,
          /*#__PURE__*/React.createElement("span", { className: "text-[10px] text-slate-500 block uppercase" }, "Index Target"),
          /*#__PURE__*/React.createElement("span", { className: "text-purple-400 block truncate" }, selectedEvent.index || "-")
        )
      ),

      /* Modal Raw JSON Section */
      /*#__PURE__*/React.createElement("div", {
        className: "flex-1 min-h-0 space-y-2 flex flex-col"
      },
        /*#__PURE__*/React.createElement("div", {
          className: "flex items-center justify-between"
        },
          /*#__PURE__*/React.createElement("span", {
            className: "text-xs font-mono text-slate-400"
          }, "Normalized Raw Payload (JSON):"),
          /*#__PURE__*/React.createElement("button", {
            onClick: () => handleCopyEventJson(selectedEvent),
            className: `px-3 py-1 rounded text-xs font-mono font-bold flex items-center space-x-1.5 transition-colors ${
              eventCopied
                ? "bg-emerald-500 text-slate-950"
                : "bg-[#1f293d] hover:bg-[#2a3854] text-emerald-400 border border-emerald-500/30"
            }`
          },
            /*#__PURE__*/React.createElement("i", {
              "data-lucide": eventCopied ? "check" : "copy",
              className: "w-3.5 h-3.5"
            }),
            /*#__PURE__*/React.createElement("span", null, eventCopied ? "Copied to Clipboard!" : "Copy Raw JSON")
          )
        ),
        /*#__PURE__*/React.createElement("pre", {
          className: "p-4 rounded-lg bg-[#080c14] border border-[#1f293d] font-mono text-[11px] text-emerald-400 overflow-x-auto overflow-y-auto max-h-[380px] select-text"
        }, JSON.stringify(selectedEvent.raw || selectedEvent, null, 2))
      ),

      /* Modal Footer */
      /*#__PURE__*/React.createElement("div", {
        className: "flex justify-end pt-2 border-t border-[#1f293d]"
      },
        /*#__PURE__*/React.createElement("button", {
          onClick: () => setSelectedEvent(null),
          className: "px-4 py-2 bg-[#1f293d] hover:bg-slate-700 text-slate-200 text-xs rounded font-mono transition-colors"
        }, "Close Inspector")
      )
    )
  )
)
```

---

## 7. Verification & Implementation Guidance

### 7.1 Cross-Cutting Checks
1. **No External Bundler Needed**: Modifying `frontend/index.html` takes effect instantly upon page refresh or when FastAPI serves `/console/`.
2. **HTML & Tag Balancing**: Ensure comma separators and closing parentheses match the sibling structure of the main React layout.
3. **Backend Fallback Compatibility**: When Elasticsearch is offline, the backend returns simulated/local events from `eve.json` or `LIVE_SIMULATION_ALERTS`. The UI will receive valid events, matching the expected format seamlessly.
4. **Automated Static Assertions**: E2E and unit tests (`tests/unit/test_milestones_2_3_4.py`, `tests/e2e/test_tier3_cross_feature.py`) check strings like `"/api/v1/events/search"`. Our proposed implementation contains exact matches for all test assertions.

---

## 8. Conclusion
The proposed frontend architecture replaces the static mockup with a production-grade, highly reactive Event Investigation console. It requires zero new external libraries, maintains complete offline/air-gapped compatibility, implements all 8 functional requirements of R2, and seamlessly integrates with backend R1 endpoints.
