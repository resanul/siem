import sys, os

html_path = os.path.abspath("frontend/index.html")
with open(html_path, "r", encoding="utf-8") as f:
    text = f.read()

text = text.replace("      } else {\n      } else {", "      } else {")
with open(html_path, "w", encoding="utf-8") as f:
    f.write(text)
print("Removed duplicate else block!")
