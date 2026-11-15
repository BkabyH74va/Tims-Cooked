import json
with open('/tmp/procs_v44.json') as f:
    d = json.load(f)
found = False
for p in d.get('processes', []):
    name = p.get('executablePath', '') or p.get('name', '')
    if 'AGXProbe' in name or 'Bench27' in name:
        print(f'PID={p.get("pid")} name={name} state={p.get("state")}')
        found = True
if not found:
    print("AGXProbe/Bench27 not found in process list")
