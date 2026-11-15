import re

with open(r'G:/REPO\tools\opencode-temp\lifetime-triage\disasm\com_apple_driver_AppleJPEGDriver.__TEXT_EXEC___text.txt') as f:
    lines = f.readlines()

# Read each unknown function start
func_addrs = [
    0xfffffe000900b13c,
    0xfffffe000900b5a8,
    0xfffffe000900b878,
    0xfffffe000900b930,
    0xfffffe000900b970,
    0xfffffe000900bc44,
    0xfffffe000900c178,
    0xfffffe000900c1d0,
    0xfffffe000900cf18,
]

for va in func_addrs:
    va_str = f'{va:#018x}:'
    found = False
    for i, line in enumerate(lines):
        if line.startswith(va_str):
            found = True
            print(f'=== Function at {va_str} ===')
            for j in range(i, min(i+25, len(lines))):
                print(f'  {lines[j].rstrip()}')
                if 'ret' in lines[j] and j > i + 3:
                    break
            print()
            break
    if not found:
        print(f'=== Function at {va_str} NOT FOUND ===\n')
