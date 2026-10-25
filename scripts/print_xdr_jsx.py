with open('frontend/index.html', 'r', encoding='utf-8') as f:
    text = f.read()

idx = 307312
print(text[idx:idx+3500])
