with open('frontend/index.html', 'rb') as f:
    data = f.read()

print("File size:", len(data))
# Check for null bytes
null_indices = [i for i, b in enumerate(data) if b == 0]
print("Null bytes count:", len(null_indices))
if null_indices:
    print("First 10 null bytes at:", null_indices[:10])

# Check non-utf8 bytes
bad_bytes = []
for i in range(len(data)):
    try:
        data[i:i+4].decode('utf-8')
    except UnicodeDecodeError as e:
        if i not in bad_bytes:
            bad_bytes.append(i)
print("Invalid utf-8 sequence count:", len(bad_bytes))
if bad_bytes:
    print("First bad byte at:", bad_bytes[0])
    print("Surrounding bytes:", data[max(0, bad_bytes[0]-20):bad_bytes[0]+40])
