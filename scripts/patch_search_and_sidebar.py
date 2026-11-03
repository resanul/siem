with open('frontend/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add .search-icon-fixed CSS in <head> style
style_target = """    code, pre, .font-mono {

      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace !important;

    }

  </style>"""

style_replacement = """    code, pre, .font-mono {

      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace !important;

    }

    .search-icon-fixed {
      position: absolute !important;
      left: 0.75rem !important;
      top: 50% !important;
      transform: translateY(-50%) !important;
      pointer-events: none !important;
    }

  </style>"""

if style_target in content:
    content = content.replace(style_target, style_replacement, 1)
    print("Added .search-icon-fixed CSS")
else:
    print("WARNING: style_target not found")

# 2. Add collapse button on OPERATIONS section title (idx === 0)
sec_title_target = """      : /*#__PURE__*/React.createElement("p", {
          key: "title",
          className: "px-3 text-[10px] font-bold text-slate-400 tracking-wider mb-1.5 uppercase font-mono flex items-center justify-between"
        }, [
          /*#__PURE__*/React.createElement("span", null, sec.title)
        ]),"""

sec_title_replacement = """      : /*#__PURE__*/React.createElement("p", {
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

if sec_title_target in content:
    content = content.replace(sec_title_target, sec_title_replacement, 1)
    print("Added collapse arrow at OPERATIONS")
else:
    print("WARNING: sec_title_target not found")

# 3. Replace all "top-1/2 -translate-y-1/2" with "search-icon-fixed" for search icons
content = content.replace(
    'className: "w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"',
    'className: "w-3.5 h-3.5 text-slate-400 search-icon-fixed"'
)
content = content.replace(
    'className: "w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"',
    'className: "w-4 h-4 text-slate-400 search-icon-fixed"'
)
content = content.replace(
    'className: "w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none"',
    'className: "w-3.5 h-3.5 text-slate-400 search-icon-fixed"'
)
content = content.replace(
    'className: "w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none"',
    'className: "w-3.5 h-3.5 text-slate-400 search-icon-fixed"'
)

with open('frontend/index.html', 'w', encoding='utf-8') as f:
    f.write(content)

print("Saved frontend/index.html successfully!")
