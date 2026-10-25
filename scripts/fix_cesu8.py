# Fix CESU-8 surrogate pairs in frontend/index.html to clean valid UTF-8
with open('frontend/index.html', 'rb') as f:
    raw = f.read()

# Decode using utf-8 with surrogatepass or errors='surrogatepass'
text = raw.decode('utf-8', errors='surrogatepass')
# Encode back to pure UTF-8 (converting surrogate pairs into valid 4-byte UTF-8 code points)
# In python, surrogate pairs can be encoded to utf-16 then decoded to get clean characters:
cleaned = text.encode('utf-16', 'surrogatepass').decode('utf-16')
encoded = cleaned.encode('utf-8')

# Verify pure UTF-8 decoding
encoded.decode('utf-8')
print("Successfully verified pure UTF-8! Size:", len(encoded))

with open('frontend/index.html', 'wb') as f:
    f.write(encoded)

print("Saved clean UTF-8 frontend/index.html!")
