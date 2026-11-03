with open('frontend/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Remove collapse-arrow from OPERATIONS (keep clean title)
target_ops = """      : /*#__PURE__*/React.createElement("p", {
          key: "title",
          className: "px-3 text-[10px] font-bold text-slate-400 tracking-wider mb-1.5 uppercase font-mono flex items-center justify-between"
        }, [
          /*#__PURE__*/React.createElement("span", null, sec.title),
          idx === 0 && /*#__PURE__*/React.createElement("button", {
            key: "collapse-arrow",
            onClick: () => {
              setSidebarCollapsed(true);
              try { localStorage.setItem("opensoc_sidebar_collapsed", "true"); } catch(e) {}
            },
            title: "Collapse Menu (Ctrl+B)",
            className: "p-0.5 rounded hover:bg-[#1a253e] text-slate-500 hover:text-cyan-400 transition cursor-pointer"
          }, [
            /*#__PURE__*/React.createElement("i", { "data-lucide": "chevrons-left", className: "w-3.5 h-3.5" })
          ])
        ]),"""

clean_ops = """      : /*#__PURE__*/React.createElement("p", {
          key: "title",
          className: "px-3 text-[10px] font-bold text-slate-400 tracking-wider mb-1.5 uppercase font-mono"
        }, sec.title),"""

if target_ops in content:
    content = content.replace(target_ops, clean_ops, 1)
    print("1. Cleaned OPERATIONS header (removed <<)")
else:
    print("WARNING: target_ops not found")

# 2. Remove duplicate button from the top navbar header
target_top_btn = """  }, /*#__PURE__*/React.createElement("header", {
    className: "h-16 bg-[#0b101d] border-b border-[#182338] px-6 flex items-center justify-between shrink-0 z-30"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center flex-1 max-w-xl mr-4"
  }, [
    /*#__PURE__*/React.createElement("button", {
      key: "sidebar-toggle-btn",
      onClick: () => {
        const next = !sidebarCollapsed;
        setSidebarCollapsed(next);
        try { localStorage.setItem("opensoc_sidebar_collapsed", String(next)); } catch(e) {}
      },
      title: sidebarCollapsed ? "Expand Sidebar (Ctrl+B)" : "Close / Collapse Sidebar (Ctrl+B)",
      className: "mr-3 p-1.5 rounded-lg border border-[#1f293d] bg-[#131b2e] hover:bg-[#1c2842] text-slate-400 hover:text-white transition flex items-center justify-center shrink-0 cursor-pointer"
    }, [
      /*#__PURE__*/React.createElement("i", {
        "data-lucide": sidebarCollapsed ? "panel-left-open" : "panel-left-close",
        className: "w-4 h-4 text-slate-300 hover:text-cyan-400 transition"
      })
    ]),
    /*#__PURE__*/React.createElement("div", {
      key: "search-box",
      className: "relative w-full flex items-center"
    },"""

clean_top_btn = """  }, /*#__PURE__*/React.createElement("header", {
    className: "h-16 bg-[#0b101d] border-b border-[#182338] px-6 flex items-center justify-between shrink-0 z-30"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center flex-1 max-w-xl mr-4"
  }, /*#__PURE__*/React.createElement("div", {
      key: "search-box",
      className: "relative w-full flex items-center"
    },"""

if target_top_btn in content:
    # Also find closing of the array in header div
    content = content.replace(target_top_btn, clean_top_btn, 1)
    # Fix the closing of the header search container: "}, "Ctrl + K"))])," -> "}, "Ctrl + K"))),"
    content = content.replace('}, "Ctrl + K"))]), /*#__PURE__*/React.createElement("div", {', '}, "Ctrl + K"))), /*#__PURE__*/React.createElement("div", {', 1)
    print("2. Removed duplicate sidebar-toggle-btn from top navbar header")
else:
    print("WARNING: target_top_btn not found")

with open('frontend/index.html', 'w', encoding='utf-8') as f:
    f.write(content)

print("Saved frontend/index.html")
