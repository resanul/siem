with open('frontend/index.html', 'r', encoding='utf-8') as f:
    lines = f.readlines()

line_num = 7416
print("Lines around 7416:")
for i in range(max(0, line_num-15), min(len(lines), line_num+15)):
    print(f"{i+1}: {lines[i]}", end="")
