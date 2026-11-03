with open('frontend/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

bad_segment = """  useEffect(() => {

    try {

      localStorage.setItem("opensoc_current_screen", currentScreen);

    } catch (e) {}

  }, [currentScreen]);

  useEffect(() => {
    const handleSidebarShortcut = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "b") {
        e.preventDefault();
        setSidebarCollapsed(prev => {
          const next = !prev;
          try { localStorage.setItem("opensoc_sidebar_collapsed", String(next)); } catch(err) {}
          return next;
        });
      }
    };
    window.addEventListener("keydown", handleSidebarShortcut);
    return () => window.removeEventListener("keydown", handleSidebarShortcut);
  }, []);"""

good_segment = """  useEffect(() => {
    const handleSidebarShortcut = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "b") {
        e.preventDefault();
        setSidebarCollapsed(prev => {
          const next = !prev;
          try { localStorage.setItem("opensoc_sidebar_collapsed", String(next)); } catch(err) {}
          return next;
        });
      }
    };
    window.addEventListener("keydown", handleSidebarShortcut);
    return () => window.removeEventListener("keydown", handleSidebarShortcut);
  }, []);

  useEffect(() => {

    try {

      localStorage.setItem("opensoc_current_screen", currentScreen);

    } catch (e) {}"""

if bad_segment in content:
    content = content.replace(bad_segment, good_segment, 1)
    with open('frontend/index.html', 'w', encoding='utf-8') as f:
        f.write(content)
    print("SUCCESS: Fixed useEffect order and brackets!")
else:
    print("ERROR: bad_segment not found!")
