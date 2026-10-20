import re

content = open('frontend/index.html', encoding='utf-8').read()

req_states = [
    'const [eventQuery, setEventQuery] = useState("*")',
    'const [eventTimeRange, setEventTimeRange] = useState("24h")',
    'const [eventResults, setEventResults] = useState([])',
    'const [eventTotalHits, setEventTotalHits] = useState(0)',
    'const [eventTookMs, setEventTookMs] = useState(0)',
    'const [eventIndicesSearched, setEventIndicesSearched] = useState([])',
    'const [eventLoading, setEventLoading] = useState(false)',
    'const [eventError, setEventError] = useState(null)',
    'const [selectedEvent, setSelectedEvent] = useState(null)',
    'const [eventCopySuccess, setEventCopySuccess] = useState(false)'
]

print("Checking Required States:")
all_states = True
for s in req_states:
    present = s in content
    if not present:
        all_states = False
    print(f"  [{'PASS' if present else 'FAIL'}] {s}")

print("\nChecking Search Execution Handler:")
has_fetch = 'fetch("/api/v1/events/search"' in content or "fetch('/api/v1/events/search'" in content
print(f"  [{'PASS' if has_fetch else 'FAIL'}] fetch('/api/v1/events/search') present")

has_exec = 'const executeEventSearch = async (overrideQuery, overrideTimeRange)' in content
print(f"  [{'PASS' if has_exec else 'FAIL'}] executeEventSearch signature present")

print("\nChecking Auto-load on Screen Transition:")
has_screen_transition = 'if (currentScreen === "search") {\n      executeEventSearch();\n    }' in content
print(f"  [{'PASS' if has_screen_transition else 'FAIL'}] Screen transition auto-load trigger present")

print("\nChecking Lucide Dependency Hydration:")
has_lucide_deps = 'eventResults, eventLoading, selectedEvent, eventCopySuccess' in content
print(f"  [{'PASS' if has_lucide_deps else 'FAIL'}] Lucide dependencies updated")

print("\nChecking Interactive Elements:")
checks = [
    ("onKeyDown Enter", 'if (e.key === "Enter") executeEventSearch()'),
    ("Execute Query Button", '"Execute Query"'),
    ("Time Range Options", '"Last 15 Minutes"'),
    ("Hit Counter String", '"Query Results: " + eventTotalHits + " hits in " + eventTookMs + "ms"'),
    ("Preset suricata-*", '"suricata-*"'),
    ("Preset wazuh-alerts-*", '"wazuh-alerts-*"'),
    ("Preset severity:CRITICAL", '"severity:CRITICAL"'),
    ("Preset host:web-app-dmz-01", '"host:web-app-dmz-01"'),
    ("Preset event.category:network", '"event.category:network"'),
    ("Detail Modal Raw JSON", 'JSON.stringify(selectedEvent.raw || selectedEvent, null, 2)'),
    ("Clipboard Copy Helper", 'handleCopyEventJson'),
    ("Empty State Reset Button", '"Reset Search to All Events (*)"')
]
all_checks = True
for name, chk in checks:
    present = chk in content
    if not present:
        all_checks = False
    print(f"  [{'PASS' if present else 'FAIL'}] {name}")

assert all_states and has_fetch and has_exec and has_screen_transition and has_lucide_deps and all_checks, "Some checks failed!"
print("\nALL FRONTEND VERIFICATION CHECKS PASSED PERFECTLY!")
