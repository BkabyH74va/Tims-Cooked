import re

with open(r'G:/REPO\tools\opencode-temp\lifetime-triage\disasm\com_apple_driver_AppleJPEGDriver.__TEXT_EXEC___text.txt') as f:
    lines = f.readlines()

# Find functions that reference newUserClient string (0x752e0d6) or clientClosedGated (0x752e13f)
for i, line in enumerate(lines):
    m = re.match(r'(0x[0-9a-f]+):\s+.*adrp\s+x(\d+),\s+(0x752e000)', line)
    if m:
        reg = m.group(2)
        for j in range(i+1, min(i+4, len(lines))):
            m2 = re.match(r'(0x[0-9a-f]+):\s+.*add\s+x' + reg + r',\s+x' + reg + r',\s+#0x(d6|13f)', lines[j])
            if m2:
                print(f'Ref at {m2.group(1)}:')
                for k in range(max(0,i-2), min(len(lines), j+3)):
                    print(f'  {lines[k].rstrip()}')
                print()
                break
