with open('frontend/index.html', 'r', encoding='utf-8') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if 'data-lucide' in line and 'search' in line:
        print(f"Line {i+1}:")
        print(''.join(lines[max(0, i-2):min(len(lines), i+6)]))
        print('-'*50)
