# Script to inject the complete RSA NetWitness SIEM view JSX into frontend/index.html

jsx_view = """
      /* =========================================================================
         RSA NETWITNESS SIEM INTEGRATION VIEW
         ========================================================================= */
      currentScreen === "netwitness_siem" && React.createElement("div", {
        className: "space-y-4"
      },
        /* View Header */
        React.createElement("div", {
          className: "flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-[#1f293d] pb-3"
        },
          React.createElement("div", { className: "flex items-center space-x-3" },
            React.createElement("div", {
              className: "p-2.5 rounded-xl bg-gradient-to-br from-indigo-500/20 to-blue-600/20 border border-indigo-500/30 text-indigo-400"
            },
              React.createElement("i", { "data-lucide": "database", className: "w-6 h-6" })
            ),
            React.createElement("div", null,
              React.createElement("div", { className: "flex items-center space-x-2.5" },
                React.createElement("h2", {
                  className: "text-xl font-bold text-slate-100 font-mono tracking-tight"
                }, "RSA NetWitness SIEM Integration"),
                React.createElement("span", {
                  className: "px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/20 text-blue-300 border border-blue-500/30"
                }, "v12.5.1.3 ACTIVE"),
                React.createElement("span", {
                  className: "px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center space-x-1"
                },
                  React.createElement("span", { className: "w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" }),
                  React.createElement("span", null, "6/6 NODES ONLINE")
                )
              ),
              React.createElement("p", { className: "text-xs text-slate-400 mt-0.5" },
                "Live Enterprise Cluster Telemetry, Core Concentrator Meta Aggregation & Full Ingestion Stream"
              )
            )
          ),
          /* Action Controls */
          React.createElement("div", { className: "flex items-center space-x-2 flex-wrap gap-2" },
            React.createElement("button", {
              onClick: syncNetWitnessData,
              disabled: nwSyncing,
              className: "px-3.5 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-mono font-bold flex items-center space-x-1.5 transition shadow-lg shadow-indigo-600/20 disabled:opacity-50"
            },
              React.createElement("i", { "data-lucide": "download-cloud", className: `w-4 h-4 ${nwSyncing ? 'animate-bounce' : ''}` }),
              React.createElement("span", null, nwSyncing ? "Syncing..." : "Sync NetWitness Data")
            ),
            React.createElement("button", {
              onClick: () => fetchNetWitnessData(true),
              disabled: nwLoading,
              className: "px-3 py-1.5 rounded-lg bg-[#131b2e] hover:bg-[#1a253e] border border-[#1f293d] text-slate-200 text-xs font-mono font-bold flex items-center space-x-1.5 transition"
            },
              React.createElement("i", { "data-lucide": "refresh-cw", className: `w-3.5 h-3.5 text-sky-400 ${nwLoading ? 'animate-spin' : ''}` }),
              React.createElement("span", null, nwLoading ? "Refreshing..." : "Refresh")
            )
          )
        ),

        /* Top 4 KPI Metrics */
        React.createElement("div", { className: "grid grid-cols-2 md:grid-cols-4 gap-3" },
          React.createElement("div", { className: "p-3.5 rounded-xl bg-[#0e1422] border border-[#1f293d]" },
            React.createElement("div", { className: "flex items-center justify-between text-xs font-mono text-slate-400 mb-1" },
              React.createElement("span", null, "CLUSTER TOPOLOGY"),
              React.createElement("i", { "data-lucide": "network", className: "w-4 h-4 text-indigo-400" })
            ),
            React.createElement("div", { className: "text-xl font-bold font-mono text-slate-100" }, "6 Core Nodes"),
            React.createElement("div", { className: "text-[11px] font-mono text-emerald-400 mt-1" }, "172.31.101.34 - 41")
          ),
          React.createElement("div", { className: "p-3.5 rounded-xl bg-[#0e1422] border border-[#1f293d]" },
            React.createElement("div", { className: "flex items-center justify-between text-xs font-mono text-slate-400 mb-1" },
              React.createElement("span", null, "LOG SESSIONS (24H)"),
              React.createElement("i", { "data-lucide": "file-text", className: "w-4 h-4 text-sky-400" })
            ),
            React.createElement("div", { className: "text-xl font-bold font-mono text-sky-300" }, "100,000+"),
            React.createElement("div", { className: "text-[11px] font-mono text-slate-400 mt-1" }, "52.9 Billion Historical")
          ),
          React.createElement("div", { className: "p-3.5 rounded-xl bg-[#0e1422] border border-[#1f293d]" },
            React.createElement("div", { className: "flex items-center justify-between text-xs font-mono text-slate-400 mb-1" },
              React.createElement("span", null, "NETWORK SESSIONS"),
              React.createElement("i", { "data-lucide": "activity", className: "w-4 h-4 text-emerald-400" })
            ),
            React.createElement("div", { className: "text-xl font-bold font-mono text-emerald-300" }, "2.37B Sessions"),
            React.createElement("div", { className: "text-[11px] font-mono text-slate-400 mt-1" }, "Full Packet Capture L7")
          ),
          React.createElement("div", { className: "p-3.5 rounded-xl bg-[#0e1422] border border-[#1f293d]" },
            React.createElement("div", { className: "flex items-center justify-between text-xs font-mono text-slate-400 mb-1" },
              React.createElement("span", null, "INTEGRATION PROTOCOL"),
              React.createElement("i", { "data-lucide": "shield-check", className: "w-4 h-4 text-purple-400" })
            ),
            React.createElement("div", { className: "text-xl font-bold font-mono text-purple-300" }, "OAuth2 + STOMP"),
            React.createElement("div", { className: "text-[11px] font-mono text-emerald-400 mt-1" }, "Authenticated as resanul")
          )
        ),

        /* Cluster Services Grid (6 Nodes) */
        React.createElement("div", { className: "rounded-xl bg-[#0e1422] border border-[#1f293d] p-4" },
          React.createElement("div", { className: "flex items-center justify-between mb-3" },
            React.createElement("h3", { className: "text-sm font-bold font-mono text-slate-200 flex items-center space-x-2" },
              React.createElement("i", { "data-lucide": "server", className: "w-4 h-4 text-indigo-400" }),
              React.createElement("span", null, "NetWitness Infrastructure Core Services (6 Nodes)")
            ),
            React.createElement("span", { className: "text-xs font-mono text-slate-400" }, "Cluster: RSA-SIEM-PROD-CLUSTER")
          ),
          React.createElement("div", { className: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3" },
            /* Node 1: RSA-SIEM-SA01 */
            React.createElement("div", { className: "p-3 rounded-lg bg-[#131b2e] border border-[#1f293d] hover:border-indigo-500/40 transition" },
              React.createElement("div", { className: "flex items-center justify-between mb-1.5" },
                React.createElement("span", { className: "font-mono font-bold text-xs text-slate-200" }, "RSA-SIEM-SA01 - Broker"),
                React.createElement("span", { className: "px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" }, "ONLINE")
              ),
              React.createElement("div", { className: "text-[11px] font-mono text-slate-400" }, "Host: 172.31.101.34:56003 (TLS)"),
              React.createElement("div", { className: "text-[11px] font-mono text-slate-400" }, "Role: Broker / Web UI / Nginx 443"),
              React.createElement("div", { className: "text-[10px] font-mono text-indigo-400 mt-1" }, "Node-Zero Head Node • v12.5.1.3")
            ),
            /* Node 2: Log Concentrator */
            React.createElement("div", { className: "p-3 rounded-lg bg-[#131b2e] border border-[#1f293d] hover:border-indigo-500/40 transition" },
              React.createElement("div", { className: "flex items-center justify-between mb-1.5" },
                React.createElement("span", { className: "font-mono font-bold text-xs text-slate-200" }, "Log-Concentrator01"),
                React.createElement("span", { className: "px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" }, "ONLINE")
              ),
              React.createElement("div", { className: "text-[11px] font-mono text-slate-400" }, "Host: 172.31.101.36:56005 (TLS)"),
              React.createElement("div", { className: "text-[11px] font-mono text-slate-400" }, "Role: Log Concentrator (52.9B Sessions)"),
              React.createElement("div", { className: "text-[10px] font-mono text-sky-400 mt-1" }, "Meta Aggregation Active • v12.5.1.3")
            ),
            /* Node 3: Log Decoder */
            React.createElement("div", { className: "p-3 rounded-lg bg-[#131b2e] border border-[#1f293d] hover:border-indigo-500/40 transition" },
              React.createElement("div", { className: "flex items-center justify-between mb-1.5" },
                React.createElement("span", { className: "font-mono font-bold text-xs text-slate-200" }, "Log-Decoder01"),
                React.createElement("span", { className: "px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" }, "ONLINE")
              ),
              React.createElement("div", { className: "text-[11px] font-mono text-slate-400" }, "Host: 172.31.101.37:56002 (TLS)"),
              React.createElement("div", { className: "text-[11px] font-mono text-slate-400" }, "Role: Real-time Parser (winevent, cisco)"),
              React.createElement("div", { className: "text-[10px] font-mono text-amber-400 mt-1" }, "Parsing Syslog Streams • v12.5.1.3")
            ),
            /* Node 4: Network Concentrator */
            React.createElement("div", { className: "p-3 rounded-lg bg-[#131b2e] border border-[#1f293d] hover:border-indigo-500/40 transition" },
              React.createElement("div", { className: "flex items-center justify-between mb-1.5" },
                React.createElement("span", { className: "font-mono font-bold text-xs text-slate-200" }, "Network-Concentrator01"),
                React.createElement("span", { className: "px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" }, "ONLINE")
              ),
              React.createElement("div", { className: "text-[11px] font-mono text-slate-400" }, "Host: 172.31.101.38:56005 (TLS)"),
              React.createElement("div", { className: "text-[11px] font-mono text-slate-400" }, "Role: Network Sessions (2.37B Streams)"),
              React.createElement("div", { className: "text-[10px] font-mono text-emerald-400 mt-1" }, "Packet Indexing Active • v12.5.1.3")
            ),
            /* Node 5: Network Decoder */
            React.createElement("div", { className: "p-3 rounded-lg bg-[#131b2e] border border-[#1f293d] hover:border-indigo-500/40 transition" },
              React.createElement("div", { className: "flex items-center justify-between mb-1.5" },
                React.createElement("span", { className: "font-mono font-bold text-xs text-slate-200" }, "Network-Decoder01"),
                React.createElement("span", { className: "px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" }, "ONLINE")
              ),
              React.createElement("div", { className: "text-[11px] font-mono text-slate-400" }, "Host: 172.31.101.39:56004 (TLS)"),
              React.createElement("div", { className: "text-[11px] font-mono text-slate-400" }, "Role: Full Packet Capture & L7 Decoder"),
              React.createElement("div", { className: "text-[10px] font-mono text-purple-400 mt-1" }, "eth1 Capture Active • v12.5.1.3")
            ),
            /* Node 6: Archiver */
            React.createElement("div", { className: "p-3 rounded-lg bg-[#131b2e] border border-[#1f293d] hover:border-indigo-500/40 transition" },
              React.createElement("div", { className: "flex items-center justify-between mb-1.5" },
                React.createElement("span", { className: "font-mono font-bold text-xs text-slate-200" }, "Archiver01 - Cold Storage"),
                React.createElement("span", { className: "px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" }, "ONLINE")
              ),
              React.createElement("div", { className: "text-[11px] font-mono text-slate-400" }, "Host: 172.31.101.41:56008 (TLS)"),
              React.createElement("div", { className: "text-[11px] font-mono text-slate-400" }, "Role: Compliance Long-Term Cold Archive"),
              React.createElement("div", { className: "text-[10px] font-mono text-slate-400 mt-1" }, "Retention Compliant • v12.5.1.3")
            )
          )
        ),

        /* Telemetry Explorer Header & Filters */
        React.createElement("div", { className: "rounded-xl bg-[#0e1422] border border-[#1f293d] p-4" },
          React.createElement("div", { className: "flex flex-col md:flex-row md:items-center justify-between gap-3 mb-3" },
            /* Tab selector: Logs vs Network */
            React.createElement("div", { className: "flex items-center space-x-2" },
              React.createElement("button", {
                onClick: () => { setNwTab("log"); fetchNetWitnessData(); },
                className: `px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition flex items-center space-x-1.5 ${nwTab === "log" ? "bg-indigo-600 text-white shadow-lg shadow-indigo-600/30" : "bg-[#131b2e] text-slate-400 hover:text-slate-200"}`
              },
                React.createElement("i", { "data-lucide": "file-text", className: "w-3.5 h-3.5" }),
                React.createElement("span", null, "Log Concentrator Events")
              ),
              React.createElement("button", {
                onClick: () => { setNwTab("network"); fetchNetWitnessData(); },
                className: `px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition flex items-center space-x-1.5 ${nwTab === "network" ? "bg-indigo-600 text-white shadow-lg shadow-indigo-600/30" : "bg-[#131b2e] text-slate-400 hover:text-slate-200"}`
              },
                React.createElement("i", { "data-lucide": "activity", className: "w-3.5 h-3.5" }),
                React.createElement("span", null, "Network Sessions Telemetry")
              )
            ),
            /* Search and Filters */
            React.createElement("div", { className: "flex items-center space-x-2 flex-wrap gap-2" },
              React.createElement("div", { className: "relative min-w-[220px]" },
                React.createElement("input", {
                  type: "text",
                  placeholder: "Search device, IP, summary...",
                  value: nwSearchQuery,
                  onChange: (e) => setNwSearchQuery(e.target.value),
                  className: "w-full pl-8 pr-3 py-1.5 bg-[#131b2e] border border-[#1f293d] rounded-lg text-xs text-slate-200 font-mono focus:outline-none focus:border-indigo-500"
                }),
                React.createElement("i", {
                  "data-lucide": "search",
                  className: "w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5"
                })
              ),
              React.createElement("select", {
                value: nwTypeFilter,
                onChange: (e) => setNwTypeFilter(e.target.value),
                className: "px-2.5 py-1.5 bg-[#131b2e] border border-[#1f293d] rounded-lg text-xs text-slate-200 font-mono focus:outline-none focus:border-indigo-500"
              },
                React.createElement("option", { value: "all" }, "All Device Types"),
                React.createElement("option", { value: "winevent_nic" }, "Windows Events (winevent_nic)"),
                React.createElement("option", { value: "ciscorouter" }, "Cisco Router (ciscorouter)"),
                React.createElement("option", { value: "snort" }, "Snort IDS (snort)"),
                React.createElement("option", { value: "Network Packet/Stream" }, "Network Packet / Stream")
              )
            )
          ),

          /* Streamed Telemetry Table */
          React.createElement("div", { className: "overflow-x-auto rounded-lg border border-[#1f293d]" },
            React.createElement("table", { className: "w-full text-left text-xs font-mono" },
              React.createElement("thead", { className: "bg-[#131b2e] text-slate-400 border-b border-[#1f293d]" },
                React.createElement("tr", null,
                  React.createElement("th", {
                    onClick: () => {
                      if (nwSortField === "session_id") setNwSortOrder(nwSortOrder === "asc" ? "desc" : "asc");
                      else { setNwSortField("session_id"); setNwSortOrder("desc"); }
                    },
                    className: "px-3 py-2.5 cursor-pointer hover:text-slate-200 transition select-none"
                  },
                    React.createElement("div", { className: "flex items-center space-x-1" },
                      React.createElement("span", null, "Session ID"),
                      React.createElement("span", { className: "text-[10px]" }, nwSortField === "session_id" ? (nwSortOrder === "asc" ? "▲" : "▼") : "↕")
                    )
                  ),
                  React.createElement("th", {
                    onClick: () => {
                      if (nwSortField === "timestamp") setNwSortOrder(nwSortOrder === "asc" ? "desc" : "asc");
                      else { setNwSortField("timestamp"); setNwSortOrder("desc"); }
                    },
                    className: "px-3 py-2.5 cursor-pointer hover:text-slate-200 transition select-none"
                  },
                    React.createElement("div", { className: "flex items-center space-x-1" },
                      React.createElement("span", null, "Timestamp (UTC)"),
                      React.createElement("span", { className: "text-[10px]" }, nwSortField === "timestamp" ? (nwSortOrder === "asc" ? "▲" : "▼") : "↕")
                    )
                  ),
                  React.createElement("th", {
                    onClick: () => {
                      if (nwSortField === "device_type") setNwSortOrder(nwSortOrder === "asc" ? "desc" : "asc");
                      else { setNwSortField("device_type"); setNwSortOrder("asc"); }
                    },
                    className: "px-3 py-2.5 cursor-pointer hover:text-slate-200 transition select-none"
                  },
                    React.createElement("div", { className: "flex items-center space-x-1" },
                      React.createElement("span", null, "Device Type / Source"),
                      React.createElement("span", { className: "text-[10px]" }, nwSortField === "device_type" ? (nwSortOrder === "asc" ? "▲" : "▼") : "↕")
                    )
                  ),
                  React.createElement("th", {
                    onClick: () => {
                      if (nwSortField === "device_ip") setNwSortOrder(nwSortOrder === "asc" ? "desc" : "asc");
                      else { setNwSortField("device_ip"); setNwSortOrder("asc"); }
                    },
                    className: "px-3 py-2.5 cursor-pointer hover:text-slate-200 transition select-none"
                  },
                    React.createElement("div", { className: "flex items-center space-x-1" },
                      React.createElement("span", null, "Device IP / Host"),
                      React.createElement("span", { className: "text-[10px]" }, nwSortField === "device_ip" ? (nwSortOrder === "asc" ? "▲" : "▼") : "↕")
                    )
                  ),
                  React.createElement("th", { className: "px-3 py-2.5" }, "Source → Destination"),
                  React.createElement("th", { className: "px-3 py-2.5" }, "Action / Severity"),
                  React.createElement("th", { className: "px-3 py-2.5" }, "Event Summary / Description"),
                  React.createElement("th", { className: "px-3 py-2.5 text-right" }, "Inspect Metas")
                )
              ),
              React.createElement("tbody", { className: "divide-y divide-[#1f293d]" },
                (() => {
                  let list = (nwEvents || []).slice();
                  if (nwTypeFilter !== "all") {
                    list = list.filter(e => e.device_type === nwTypeFilter);
                  }
                  if (nwSearchQuery) {
                    const q = nwSearchQuery.toLowerCase();
                    list = list.filter(e =>
                      (e.description && e.description.toLowerCase().includes(q)) ||
                      (e.device_ip && e.device_ip.toLowerCase().includes(q)) ||
                      (e.device_type && e.device_type.toLowerCase().includes(q)) ||
                      (e.source_ip && e.source_ip.toLowerCase().includes(q)) ||
                      (e.destination_ip && e.destination_ip.toLowerCase().includes(q))
                    );
                  }
                  list.sort((a, b) => {
                    let va = a[nwSortField] || "";
                    let vb = b[nwSortField] || "";
                    if (typeof va === "number" && typeof vb === "number") {
                      return nwSortOrder === "asc" ? va - vb : vb - va;
                    }
                    va = String(va).toLowerCase();
                    vb = String(vb).toLowerCase();
                    if (va < vb) return nwSortOrder === "asc" ? -1 : 1;
                    if (va > vb) return nwSortOrder === "asc" ? 1 : -1;
                    return 0;
                  });

                  if (list.length === 0) {
                    return React.createElement("tr", null,
                      React.createElement("td", {
                        colSpan: 8,
                        className: "px-4 py-8 text-center text-slate-400 font-mono text-xs"
                      },
                        React.createElement("div", { className: "flex flex-col items-center justify-center space-y-2" },
                          React.createElement("i", { "data-lucide": "database", className: "w-8 h-8 text-slate-600" }),
                          React.createElement("span", null, nwLoading ? "Loading authentic NetWitness records..." : "No events matched the filter. Click 'Sync NetWitness Data' to pull recent sessions.")
                        )
                      )
                    );
                  }

                  const startIdx = (nwPage - 1) * nwPageSize;
                  const pageItems = list.slice(startIdx, startIdx + nwPageSize);

                  return pageItems.map((ev, idx) => {
                    return React.createElement("tr", {
                      key: ev.session_id || idx,
                      className: "hover:bg-[#131b2e]/60 transition"
                    },
                      React.createElement("td", { className: "px-3 py-2 text-indigo-400 font-bold" }, ev.session_id),
                      React.createElement("td", { className: "px-3 py-2 text-slate-300 whitespace-nowrap" },
                        ev.timestamp ? ev.timestamp.replace("T", " ").replace(".000+00:00", "") : "-"
                      ),
                      React.createElement("td", { className: "px-3 py-2" },
                        React.createElement("span", {
                          className: `px-2 py-0.5 rounded text-[10px] font-bold ${
                            ev.device_type === "winevent_nic" ? "bg-blue-500/10 text-blue-400 border border-blue-500/20" :
                            ev.device_type === "ciscorouter" ? "bg-amber-500/10 text-amber-400 border border-amber-500/20" :
                            ev.device_type === "snort" ? "bg-rose-500/10 text-rose-400 border border-rose-500/20" :
                            "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                          }`
                        }, ev.device_type)
                      ),
                      React.createElement("td", { className: "px-3 py-2 text-slate-300 font-mono" },
                        ev.device_ip || ev.device_host || "-"
                      ),
                      React.createElement("td", { className: "px-3 py-2 text-slate-400 font-mono text-[11px]" },
                        `${ev.source_ip || "-"} → ${ev.destination_ip || "-"}${ev.destination_port ? ":" + ev.destination_port : ""}`
                      ),
                      React.createElement("td", { className: "px-3 py-2" },
                        React.createElement("span", {
                          className: `px-2 py-0.5 rounded text-[10px] font-bold ${
                            ev.severity === "HIGH" ? "bg-rose-500/20 text-rose-400" :
                            ev.severity === "MEDIUM" ? "bg-amber-500/20 text-amber-400" :
                            "bg-slate-700/50 text-slate-300"
                          }`
                        }, ev.action || ev.severity || "LOGGED")
                      ),
                      React.createElement("td", {
                        className: "px-3 py-2 text-slate-300 max-w-xs truncate",
                        title: ev.description
                      }, ev.description || "-"),
                      React.createElement("td", { className: "px-3 py-2 text-right" },
                        React.createElement("button", {
                          onClick: () => setNwSelectedEvent(ev),
                          className: "px-2 py-1 rounded bg-[#1f293d] hover:bg-indigo-600 hover:text-white text-slate-300 text-[10px] font-bold transition flex items-center space-x-1 ml-auto"
                        },
                          React.createElement("i", { "data-lucide": "file-search", className: "w-3 h-3" }),
                          React.createElement("span", null, "Metas")
                        )
                      )
                    );
                  });
                })()
              )
            )
          ),

          /* Pagination & Summary Footer */
          React.createElement("div", { className: "flex items-center justify-between mt-3 text-xs font-mono text-slate-400" },
            React.createElement("span", null, `Showing ${nwEvents ? nwEvents.length : 0} live events from ${nwTab === "log" ? "Log-Concentrator01" : "Network-Concentrator01"}`),
            React.createElement("div", { className: "flex items-center space-x-2" },
              React.createElement("span", null, `Page ${nwPage}`),
              React.createElement("button", {
                disabled: nwPage <= 1,
                onClick: () => setNwPage(p => Math.max(1, p - 1)),
                className: "px-2 py-1 rounded bg-[#131b2e] border border-[#1f293d] disabled:opacity-40 hover:bg-[#1a253e]"
              }, "◀"),
              React.createElement("button", {
                disabled: (nwEvents || []).length <= nwPage * nwPageSize,
                onClick: () => setNwPage(p => p + 1),
                className: "px-2 py-1 rounded bg-[#131b2e] border border-[#1f293d] disabled:opacity-40 hover:bg-[#1a253e]"
              }, "▶")
            )
          )
        ),

        /* Meta Keys Inspector Slide-over Modal */
        nwSelectedEvent && React.createElement("div", {
          className: "fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm"
        },
          React.createElement("div", {
            className: "w-full max-w-3xl max-h-[85vh] rounded-2xl bg-[#0e1422] border border-[#1f293d] shadow-2xl flex flex-col overflow-hidden"
          },
            /* Modal Header */
            React.createElement("div", {
              className: "flex items-center justify-between px-5 py-4 border-b border-[#1f293d] bg-[#131b2e]"
            },
              React.createElement("div", { className: "flex items-center space-x-3" },
                React.createElement("div", { className: "p-2 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400" },
                  React.createElement("i", { "data-lucide": "layers", className: "w-5 h-5" })
                ),
                React.createElement("div", null,
                  React.createElement("h3", { className: "font-mono font-bold text-sm text-slate-100" },
                    `NetWitness Session #${nwSelectedEvent.session_id}`
                  ),
                  React.createElement("p", { className: "text-xs text-slate-400 font-mono" },
                    `${nwSelectedEvent.device_type} • ${nwSelectedEvent.timestamp}`
                  )
                )
              ),
              React.createElement("button", {
                onClick: () => setNwSelectedEvent(null),
                className: "p-1.5 rounded-lg bg-[#1a253e] hover:bg-slate-700 text-slate-400 hover:text-white transition"
              },
                React.createElement("i", { "data-lucide": "x", className: "w-4 h-4" })
              )
            ),
            /* Modal Body: Meta Keys Table */
            React.createElement("div", { className: "p-5 overflow-y-auto space-y-3" },
              React.createElement("div", { className: "text-xs font-mono text-slate-300 font-bold mb-2 flex items-center justify-between" },
                React.createElement("span", null, "Extracted NetWitness Meta Keys (55 Available)"),
                React.createElement("span", { className: "text-[11px] text-indigo-400" },
                  `${Object.keys(nwSelectedEvent.raw_metas || {}).length} keys mapped`
                )
              ),
              React.createElement("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-2" },
                Object.entries(nwSelectedEvent.raw_metas || {}).map(([k, v]) => {
                  return React.createElement("div", {
                    key: k,
                    className: "p-2 rounded bg-[#131b2e] border border-[#1f293d] flex items-center justify-between text-xs font-mono"
                  },
                    React.createElement("span", { className: "text-indigo-400 font-semibold" }, k),
                    React.createElement("span", {
                      className: "text-slate-200 max-w-[200px] truncate text-right",
                      title: String(v)
                    }, String(v))
                  );
                })
              )
            ),
            /* Modal Footer */
            React.createElement("div", {
              className: "flex items-center justify-end px-5 py-3 border-t border-[#1f293d] bg-[#131b2e]"
            },
              React.createElement("button", {
                onClick: () => setNwSelectedEvent(null),
                className: "px-4 py-1.5 rounded-lg bg-[#1f293d] hover:bg-[#2a364f] text-slate-200 text-xs font-mono font-bold transition"
              }, "Close")
            )
          )
        )
      ),
"""

with open('frontend/index.html', 'r', encoding='utf-8') as f:
    html = f.read()

target = 'currentScreen === "search" && /*#__PURE__*/React.createElement("div", {'

if "RSA NETWITNESS SIEM INTEGRATION VIEW" not in html:
    html = html.replace(target, jsx_view.strip() + ',\n\n      ' + target, 1)
    with open('frontend/index.html', 'w', encoding='utf-8') as f:
        f.write(html)
    print("NetWitness JSX View successfully injected into frontend/index.html!")
else:
    print("NetWitness JSX View already present.")
