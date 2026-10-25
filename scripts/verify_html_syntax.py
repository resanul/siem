# Lexical parenthesis, bracket and brace verifier for frontend/index.html
with open('frontend/index.html', 'r', encoding='utf-8') as f:
    code = f.read()

import re

# Find script blocks
scripts = re.findall(r'<script\b[^>]*>(.*?)</script>', code, re.DOTALL)
print(f"Total script tags: {len(scripts)}")

for idx, s in enumerate(scripts):
    paren = 0
    brace = 0
    bracket = 0
    
    in_single = False
    in_double = False
    in_backtick = False
    in_line_comment = False
    in_block_comment = False
    
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        c2 = s[i:i+2]
        
        if in_line_comment:
            if c == '\n':
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if c2 == '*/':
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_single:
            if c == '\\':
                i += 2
                continue
            if c == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if c == '\\':
                i += 2
                continue
            if c == '"':
                in_double = False
            i += 1
            continue
        if in_backtick:
            if c == '\\':
                i += 2
                continue
            if c == '`':
                in_backtick = False
            i += 1
            continue
            
        if c2 == '//':
            in_line_comment = True
            i += 2
            continue
        if c2 == '/*':
            in_block_comment = True
            i += 2
            continue
        if c == "'":
            in_single = True
            i += 1
            continue
        if c == '"':
            in_double = True
            i += 1
            continue
        if c == '`':
            in_backtick = True
            i += 1
            continue
            
        if c == '(': paren += 1
        elif c == ')': paren -= 1
        elif c == '{': brace += 1
        elif c == '}': brace -= 1
        elif c == '[': bracket += 1
        elif c == ']': bracket -= 1
        
        i += 1
        
    if paren != 0 or brace != 0 or bracket != 0:
        print(f"SCRIPT #{idx} MISMATCH -> paren: {paren}, brace: {brace}, bracket: {bracket}")
    else:
        if len(s) > 1000:
            print(f"SCRIPT #{idx} (Main App, {len(s)} chars): PERFECT BALANCED! (paren={paren}, brace={brace}, bracket={bracket})")
