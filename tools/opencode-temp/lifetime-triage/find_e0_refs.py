import re

with open(r'G:/REPO\tools\opencode-temp\lifetime-triage\disasm\com_apple_driver_AppleJPEGDriver.__TEXT_EXEC___text.txt') as f:
    lines = f.readlines()

# Search for references to [x, #0xe0] or [x, #0xf0] pattern (driver+0xe0 array)
# These would be ldr/str with offset 0xe0 or 0xf0
for i, line in enumerate(lines):
    m = re.match(r'(0x[0-9a-f]+):\s+.*(?:ldr|str)\s+(?:w|d|q|x)?(\d+),\s+\[(x\d+),\s+#0x(e0|f0)\]', line)
    if m:
        addr = m.group(1)
        reg_dest = m.group(2)
        reg_base = m.group(3)
        offset = m.group(4)
        print(f'{addr}: offset=0x{offset} base={reg_base} dest={reg_dest} {line.strip()[:100]}')
