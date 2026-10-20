import re
import sys

def main():
    with open('frontend/index.html', 'r', encoding='utf-8') as f:
        content = f.read()

    scripts = re.findall(r'<script\b[^>]*>(.*?)</script>', content, re.DOTALL)
    print(f"Total script tags: {len(scripts)}")
    
    # We want to check script 10 (the main app script)
    main_js = scripts[10]
    
    # Check for raw JSX tags outside strings
    # Regex looking for JSX like <div or </div or <span or <button
    # Notice in React.createElement, the tag name is a string literal "div", "span"
    # If there is raw JSX like <div> or </button>, it's broken UMD.
    
    # Simple lexical scan
    stack = []
    i = 0
    n = len(main_js)
    line = 1
    col = 1
    errors = []
    
    in_single_quote = False
    in_double_quote = False
    in_backtick = False
    in_line_comment = False
    in_block_comment = False
    escape = False

    while i < n:
        char = main_js[i]
        if char == '\n':
            line += 1
            col = 1
            if in_line_comment:
                in_line_comment = False
            i += 1
            continue
        else:
            col += 1

        if escape:
            escape = False
            i += 1
            continue

        if in_line_comment:
            i += 1
            continue

        if in_block_comment:
            if char == '*' and i + 1 < n and main_js[i+1] == '/':
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue

        if in_single_quote:
            if char == '\\':
                escape = True
            elif char == "'":
                in_single_quote = False
            i += 1
            continue

        if in_double_quote:
            if char == '\\':
                escape = True
            elif char == '"':
                in_double_quote = False
            i += 1
            continue

        if in_backtick:
            if char == '\\':
                escape = True
            elif char == '`':
                in_backtick = False
            i += 1
            continue

        # Start of comments
        if char == '/' and i + 1 < n:
            if main_js[i+1] == '/':
                in_line_comment = True
                i += 2
                continue
            elif main_js[i+1] == '*':
                in_block_comment = True
                i += 2
                continue

        # Strings
        if char == "'":
            in_single_quote = True
            i += 1
            continue
        if char == '"':
            in_double_quote = True
            i += 1
            continue
        if char == '`':
            in_backtick = True
            i += 1
            continue

        # Brackets
        if char in '({[':
            stack.append((char, line, col))
        elif char in ')}]':
            if not stack:
                errors.append(f"Unmatched closing {char} at line {line}:{col}")
            else:
                last_open, o_line, o_col = stack.pop()
                expected = {'(': ')', '{': '}', '[': ']'}[last_open]
                if char != expected:
                    errors.append(f"Mismatched closing {char} at line {line}:{col}, expected {expected} for open at {o_line}:{o_col}")

        # Check for unexpected raw JSX outside strings
        if char == '<' and i + 1 < n and (main_js[i+1].isalpha() or main_js[i+1] == '/'):
            # Check if this might be comparison like x < y or raw JSX tag
            # If tag looks like <div or </div
            tag_match = re.match(r'</?([a-zA-Z][a-zA-Z0-9-]*)\b', main_js[i:])
            if tag_match:
                tag_name = tag_match.group(1)
                # Known html elements
                if tag_name in ['div', 'span', 'button', 'input', 'select', 'option', 'h1', 'h2', 'h3', 'p', 'i', 'code', 'pre']:
                    errors.append(f"Potential raw JSX tag '<{tag_name}>' found at line {line}:{col}")

        i += 1

    print(f"Validation finished.")
    print(f"Remaining open brackets: {len(stack)}")
    print(f"Errors encountered: {len(errors)}")
    for e in errors[:10]:
        print("  ERROR:", e)
    for o in stack[-5:]:
        print("  UNCLOSED:", o)
        
    return 0 if (len(stack) == 0 and len(errors) == 0) else 1

if __name__ == '__main__':
    sys.exit(main())
