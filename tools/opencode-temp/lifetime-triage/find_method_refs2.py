with open(r'G:/REPO\tools\opencode-temp\lifetime-triage\disasm\com_apple_driver_AppleJPEGDriver.__TEXT_EXEC___text.txt') as f:
    lines = f.readlines()

# Find all adrp to 0x752e000, then check following add instructions for specific offsets
target_offsets = {
    '0xd6': 'newUserClient',
    '0x13f': 'clientClosedGated',
    '0x18c': 'turnOnJPEGHW_gated',
    '0x21d': 'doRestOfBufferSetupForDecode_gated',
    '0x269': 'doRestOfBufferSetupForEncode_gated',
    '0x2fa': 'setupBuffersForCoding_gated',
    '0x77c': 'queue_io_gated',
    '0x927': 'convertToRequestSubSampleMode',
}

for i, line in enumerate(lines):
    if 'adrp' in line and '752e000' in line:
        # Extract the register
        parts = line.split()
        # Find 'adrp' then next token is register
        for idx, p in enumerate(parts):
            if p == 'adrp':
                reg = parts[idx + 1].rstrip(',')
                break
        else:
            continue
        
        # Check next 6 lines for add with this register and target offset
        for j in range(i+1, min(i+7, len(lines))):
            next_line = lines[j]
            if f'add\t{reg}, {reg}, #' in next_line:
                # Extract the offset
                hash_idx = next_line.index('#')
                offset_str = next_line[hash_idx+1:].split()[0]
                # Remove comment
                if ';' in offset_str:
                    offset_str = offset_str.split(';')[0]
                try:
                    off = int(offset_str, 16)
                except:
                    continue
                if f'0x{off:x}' in target_offsets:
                    print(f'{target_offsets[f"0x{off:x}"]} referenced at {next_line.strip()[:120]}')
                    print(f'  adrp at line {i}: {lines[i].strip()[:120]}')
                    print(f'  add  at line {j}: {next_line.strip()[:120]}')
                    print()
                break
