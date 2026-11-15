#!/usr/bin/env python3
"""AGXG18P kext string extraction for reachability analysis."""
import re
from pathlib import Path

p = Path('G:/REPO/analysis/agx/2701/com.apple.AGXG18P')
data = p.read_bytes()
print('size:', len(data))

strings = re.findall(rb'[\x20-\x7e]{4,}', data)
print('total strings:', len(strings))

keywords = [
    b'UserClient', b'ConnectMethod', b'ExternalMethod', b'TargetAndMethod',
    b'AGXDevice', b'AGXCommand', b'AGXCLChannel', b'AGXBitmap', b'AGX',
    b'IOUserClient', b'IOService', b'OSMetaClass', b'vtable',
    b'OSArray', b'OSDictionary', b'OSSet', b'OSNumber', b'OSString',
    b'IOConnect', b'submitBuffer', b'channel', b'index', b'count',
    b'kAGXMaxChannelCount',
]
for s in strings:
    low = s.lower()
    if any(k in low for k in keywords):
        print(s.decode('ascii', 'replace'))
