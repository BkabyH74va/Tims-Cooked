import json
with open('/tmp/procs_pri.json') as f:
    d = json.load(f)
for p in d.get('processes', []):
    name = p.get('executablePath', '') or p.get('name', '')
    if 'AGXProbe' in name or 'Bench27' in name:
        print(f'PID={p.get("pid")} name={name} state={p.get("state")}')
