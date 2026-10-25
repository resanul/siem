with open('frontend/index.html', 'r', encoding='utf-8') as f:
    text = f.read()

idx = text.find('currentScreen === "endpoint_xdr"')
if idx != -1:
    print("Found endpoint_xdr render at:", idx)
    print(text[idx:idx+2500])
