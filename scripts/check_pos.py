with open('frontend/index.html', 'rb') as f:
    data = f.read()

pos = 361347
print("Bytes around 361347:", data[pos-20:pos+30])
try:
    data[pos-20:pos+30].decode('utf-8')
except Exception as e:
    print("Decode err around 361347:", e)
