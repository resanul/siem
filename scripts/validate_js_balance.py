import re
import sys

target_file = sys.argv[1] if len(sys.argv) > 1 else 'frontend/index.html'

with open(target_file, 'r', encoding='utf-8') as f:
    html = f.read()

scripts = re.findall(r'<script(?![^>]*src=)[^>]*>(.*?)</script>', html, re.DOTALL)
print(f"Extracted {len(scripts)} inline script blocks.")

for idx, script in enumerate(scripts):
    # Check brace and paren balance (ignoring strings and comments)
    stack = []
    in_single = False
    in_double = False
    in_backtick = False
    in_line_comment = False
    in_block_comment = False
    
    error = None
    line_num = 1
    
    i = 0
    while i < len(script):
        ch = script[i]
        if ch == '\n':
            line_num += 1
            in_line_comment = False
            i += 1
            continue
            
        if in_line_comment:
            i += 1
            continue
            
        if in_block_comment:
            if ch == '*' and i + 1 < len(script) and script[i+1] == '/':
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
            
        if in_single:
            if ch == '\\':
                i += 2
                continue
            if ch == "'":
                in_single = False
            i += 1
            continue
            
        if in_double:
            if ch == '\\':
                i += 2
                continue
            if ch == '"':
                in_double = False
            i += 1
            continue
            
        if in_backtick:
            if ch == '\\':
                i += 2
                continue
            if ch == '`':
                in_backtick = False
            i += 1
            continue
            
        # Comments
        if ch == '/' and i + 1 < len(script):
            if script[i+1] == '/':
                in_line_comment = True
                i += 2
                continue
            elif script[i+1] == '*':
                in_block_comment = True
                i += 2
                continue
                
        # Strings
        if ch == "'":
            in_single = True
            i += 1
            continue
        if ch == '"':
            in_double = True
            i += 1
            continue
        if ch == '`':
            in_backtick = True
            i += 1
            continue
            
        # Brackets
        if ch in '({[':
            stack.append((ch, line_num))
        elif ch in ')}]':
            if not stack:
                error = f"Unmatched closing '{ch}' at relative line {line_num}"
                break
            opening, o_line = stack.pop()
            matches = {'(': ')', '{': '}', '[': ']'}
            if matches[opening] != ch:
                error = f"Mismatched bracket: opened '{opening}' at line {o_line}, closed with '{ch}' at line {line_num}"
                break
        i += 1
        
    if error:
        print(f"Script {idx}: ERROR - {error}")
    elif stack:
        print(f"Script {idx}: ERROR - Unclosed brackets: {stack[-5:]}")
    else:
        print(f"Script {idx}: Bracket and string balance PERFECT! Length: {len(script)} chars")
