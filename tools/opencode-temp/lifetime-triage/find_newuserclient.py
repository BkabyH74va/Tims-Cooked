import re

with open(r'G:/REPO\tools\opencode-temp\lifetime-triage\disasm\com_apple_driver_AppleJPEGDriver.__TEXT_EXEC___text.txt') as f:
    lines = f.readlines()

# Search for functions that call kalloc with a specific size and then init
# newUserClient typically: kalloc(size) → init(task, securityID, type, properties) → return
# Look for functions that call stub 0xb7fd210 (kalloc) and then call another function

for i, line in enumerate(lines):
    if 'bl\t__stub_fffffe000b7fd210' in line:
        # Check if this is followed by init-like pattern
        for j in range(i+1, min(i+6, len(lines))):
            if 'bl\t0xfffffe000900' in lines[j] or 'bl\t__stub' in lines[j]:
                # Print context
                print(f'kalloc at {lines[i].strip()[:100]}')
                for k in range(max(0,i-2), min(len(lines), j+2)):
                    print(f'  {lines[k].rstrip()}')
                print()
                break
