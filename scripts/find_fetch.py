with open('frontend/index.html', 'r', encoding='utf-8') as f:
    text = f.read()

idx = text.find("fetchSophosTelemetry")
if idx != -1:
    print("Found fetchSophosTelemetry around:", idx)
    print(text[max(0, idx-50):idx+350])
