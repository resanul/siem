with open('frontend/index.html', 'r', encoding='utf-8') as f:
    text = f.read()

idx = text.find("sophosActiveFilter")
print(text[idx:idx+2500])
