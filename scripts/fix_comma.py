with open('frontend/index.html', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace("      ),,\n", "      ),\n")

with open('frontend/index.html', 'w', encoding='utf-8') as f:
    f.write(text)

print("Double comma replaced!")
