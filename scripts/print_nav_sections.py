with open('frontend/index.html', 'r', encoding='utf-8') as f:
    text = f.read()

idx = text.find("const navSections = [")
print(text[idx:idx+2500])
