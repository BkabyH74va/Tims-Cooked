import re

with open(r'G:/REPO\tools\opencode-temp\lifetime-triage\disasm\com_apple_driver_AppleJPEGDriver.__TEXT_EXEC___text.txt') as f:
    lines = f.readlines()

# Find all adrp to 0x752e000, then check following add instructions
targets = {
    0xd6: 'newUserClient',
    0x13f: 'clientClosedGated',
    0x18c: 'turnOnJPEGHW_gated',
    0x21d: 'doRestOfBufferSetupForDecode_gated',
    0x269: 'doRestOfBufferSetupForEncode_gated',
    0x2fa: 'setupBuffersForCoding_gated',
    0x77c: 'queue_io_gated',
    0x927: 'convertToRequestSubSampleMode',
    0x3b7: 'startDecoder (logging)',
}

for i, line in enumerate(lines):
    if 'adrp' in line and '752e000' in line:
        # Parse the register
        m = re.match(r'(0x[0-9a-f]+):\s+.*adrp\t(x\d+),\s+(0x752e000)', line)
        if not m:
            continue
        addr = m.group(1)
        reg = m.group(2)
        # Look at next 6 lines for add with this register
        for j in range(i+1, min(i+7, len(lines))):
            m2 = re.match(r'(0x[0-9a-f]+):\s+.*add\t' + reg + r',\s+' + reg + r',\s+#0x([0-9a-f]+)', lines[j])
            if m2:
                off = int(m2.group(3), 16)
                if off in targets:
                    print(f'{targets[off]} referenced at {m2.group(1)} (adrp at {addr})')
                break
