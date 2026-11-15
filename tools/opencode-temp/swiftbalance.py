#!/usr/bin/env python3
"""Swift-aware brace/paren balance tracker.

Handles:
  * line comments  //
  * block comments /* */
  * simple strings "..."  with backslash escapes and ( ... ) interpolation
  * raw strings #"..."#
  * multiline strings
"""
import io
import sys


def scan(text, label=''):
    i = 0
    n = len(text)
    line = 1
    depth = 0
    pdepth = 0
    stack = []          # (char, line)
    interp = []         # stack of interpolation paren depths
    out = []
    while i < n:
        c = text[i]
        if c == '\n':
            line += 1
            i += 1
            continue
        if c == '/' and i + 1 < n and text[i+1] == '/':
            while i < n and text[i] != '\n':
                i += 1
            continue
        if c == '/' and i + 1 < n and text[i+1] == '*':
            i += 2
            while i + 1 < n and not (text[i] == '*' and text[i+1] == '/'):
                if text[i] == '\n':
                    line += 1
                i += 1
            i += 2
            continue
        # raw string
        if c == '#' and i + 1 < n and text[i+1] == '"':
            i += 2
            hashes = 1
            while i < n:
                if text[i] == '"':
                    j = i + 1
                    while j < n and text[j] == '#' and j - i - 1 < hashes:
                        j += 1
                    if j - i - 1 >= hashes:
                        i = j
                        break
                if text[i] == '\n':
                    line += 1
                i += 1
            continue
        # multiline string
        if text.startswith('"""', i):
            i += 3
            while i < n and not text.startswith('"""', i):
                if text[i] == '\\' and i + 1 < n:
                    if text[i+1] == '\n':
                        line += 1
                    i += 2
                    continue
                if text[i] == '\n':
                    line += 1
                i += 1
            i += 3
            continue
        if c == '"':
            i += 1
            while i < n:
                if text[i] == '\\':
                    if i + 1 < n:
                        if text[i+1] == '(':
                            # interpolation: scan balanced parens, recursively
                            i += 2
                            pd = 0
                            while i < n:
                                ch = text[i]
                                if ch == '\n':
                                    line += 1
                                if ch == '"':
                                    # nested string inside interpolation
                                    i += 1
                                    while i < n:
                                        if text[i] == '\\':
                                            i += 2
                                            continue
                                        if text[i] == '"':
                                            i += 1
                                            break
                                        if text[i] == '\n':
                                            line += 1
                                        i += 1
                                    continue
                                if ch == '(':
                                    pd += 1
                                elif ch == ')':
                                    if pd == 0:
                                        break
                                    pd -= 1
                                elif ch == '{':
                                    depth += 1
                                    stack.append(('{', line))
                                    out.append((line, depth, pdepth, 'open brace'))
                                elif ch == '}':
                                    depth -= 1
                                    if stack:
                                        stack.pop()
                                    out.append((line, depth, pdepth, 'close brace'))
                                i += 1
                            i += 1
                            continue
                        i += 2
                        continue
                    i += 1
                    continue
                if text[i] == '"':
                    i += 1
                    break
                if text[i] == '\n':
                    line += 1
                i += 1
            continue
        if c == '(':
            pdepth += 1
        elif c == ')':
            pdepth -= 1
        elif c == '{':
            depth += 1
            stack.append(('{', line))
            out.append((line, depth, pdepth, 'open brace'))
        elif c == '}':
            depth -= 1
            if stack:
                stack.pop()
            out.append((line, depth, pdepth, 'close brace'))
        i += 1
    print('%s: final brace depth=%d paren depth=%d' % (label, depth, pdepth))
    if stack:
        print('  UNCLOSED:', stack[:10])
    return depth, pdepth, out


if __name__ == '__main__':
    for path in sys.argv[1:]:
        text = io.open(path, encoding='utf-8').read()
        d, p, out = scan(text, path)
        # print any line where depth returns to 1 (class body) and suspicious spots
        for (ln, dep, pd, kind) in out:
            if dep < 0:
                print('  NEGATIVE at line %d' % ln)
        print('  lines with brace events:', len(out))
