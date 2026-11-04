import sys, os

html_path = os.path.abspath("frontend/index.html")
with open(html_path, "r", encoding="utf-8") as f:
    text = f.read()

# 1. First fallback in Events table:
target_1 = '"Src IP: " + (ev.source_ip || "10.102.11.222")'
replacement_1 = 'ev.source_ip ? "Src IP: " + ev.source_ip : (ev.source_workstation ? "Host: " + ev.source_workstation : "")'

# 2. Second fallback in Authentications table:
target_2 = '}, ev.source_ip || "10.102.11.222"), /*#__PURE__*/React.createElement("span",'
replacement_2 = '}, ev.source_ip || (ev.user_name === "resanul" ? "10.102.11.222" : "--")), /*#__PURE__*/React.createElement("span",'

# 3. Third fallback in Inspect modal:
target_3 = 'identitySelectedEvent.source_ip || "10.102.11.222"'
replacement_3 = 'identitySelectedEvent.source_ip || (identitySelectedEvent.user_name === "resanul" ? "10.102.11.222" : "--")'

target_4 = 'identitySelectedEvent.source_workstation || "ISRCD-0222"'
replacement_4 = 'identitySelectedEvent.source_workstation || (identitySelectedEvent.user_name === "resanul" ? "ISRCD-0222" : "Workstation")'

print("target_1 in text:", target_1 in text)
print("target_2 in text:", target_2 in text)
print("target_3 in text:", target_3 in text)
print("target_4 in text:", target_4 in text)

if target_1 in text and target_2 in text and target_3 in text and target_4 in text:
    text = text.replace(target_1, replacement_1)
    text = text.replace(target_2, replacement_2)
    text = text.replace(target_3, replacement_3)
    text = text.replace(target_4, replacement_4)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(text)
    print("Frontend index.html patched successfully!")
else:
    print("One or more targets not found!")
