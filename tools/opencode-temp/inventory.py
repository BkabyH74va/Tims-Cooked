#!/usr/bin/env python3
"""Function-level change inventory, pass-1 (own-body) alignment."""
import sys, json, re, difflib, bisect, hashlib
sys.path.insert(0, r'G:/REPO\tools\opencode-temp')
import fdiff2

A = r'G:/REPO\analysis\agx\2701.disasm.txt'
SA = r'G:/REPO\tools\opencode-temp\starts2701.txt'
B = r'G:/REPO\analysis\agx\272.disasm.txt'
SB = r'G:/REPO\tools\opencode-temp\starts272.txt'

ia = fdiff2.load_insns(A); sa = fdiff2.load_starts(SA)
ib = fdiff2.load_insns(B); sb = fdiff2.load_starts(SB)
ga = fdiff2.group(ia, sa); gb = fdiff2.group(ib, sb)

def build(g, starts):
    out = []
    for s, ins in g:
        idx = {a: i for i, (a, _, _) in enumerate(ins)}
        body = fdiff2.norm_func(ins, set(starts), None, idx)
        out.append(dict(start=s, ins=ins, body=body, h=hashlib.sha1('\n'.join(body).encode()).hexdigest(),
                        n=len(body), size=(ins[-1][0]+4-s)))
    return out

pa = build(ga, sa); pb = build(gb, sb)
ha = [x['h'] for x in pa]; hb = [x['h'] for x in pb]
sm = difflib.SequenceMatcher(a=ha, b=hb, autojunk=False)
changed = []; added = []; removed = []
for tag, a0, a1, b0, b1 in sm.get_opcodes():
    if tag == 'equal':
        continue
    if tag == 'delete':
        removed.extend(pa[a0:a1]); continue
    if tag == 'insert':
        added.extend(pb[b0:b1]); continue
    na, nb = a1-a0, b1-b0
    for k in range(max(na, nb)):
        x, y = a0+k, b0+k
        if x < a1 and y < b1:
            sim = difflib.SequenceMatcher(a=pa[x]['body'], b=pb[y]['body'], autojunk=False).ratio()
            changed.append(dict(a=pa[x]['start'], b=pb[y]['start'], na=pa[x]['n'], nb=pb[y]['n'],
                                sa=pa[x]['size'], sb=pb[y]['size'], sim=sim,
                                amb=(na != nb)))
        elif x < a1:
            removed.append(pa[x])
        else:
            added.append(pb[y])

print('A funcs', len(pa), 'B funcs', len(pb), 'changed', len(changed), 'added', len(added), 'removed', len(removed))

# ---- instruction diff for each changed pair
def opbody(x):
    return x['body']

def diff_summary(ca, cb):
    la = opbody(ca); lb = opbody(cb)
    sm2 = difflib.SequenceMatcher(a=la, b=lb, autojunk=False)
    adds = []; dels = []; reps = []
    for t, i0, i1, j0, j1 in sm2.get_opcodes():
        if t == 'insert':
            adds.extend(lb[j0:j1])
        elif t == 'delete':
            dels.extend(la[i0:i1])
        elif t == 'replace':
            for k in range(max(i1-i0, j1-j0)):
                if i0+k < i1 and j0+k < j1:
                    reps.append((la[i0+k], lb[j0+k]))
                elif i0+k < i1:
                    dels.append(la[i0+k])
                else:
                    adds.append(lb[j0+k])
    return adds, dels, reps

CHECK_OPS = ('cmp', 'cmn', 'tst', 'cbz', 'cbnz', 'tbz', 'tbnz', 'and', 'ands', 'orr', 'eor',
             'ubfx', 'sbfx', 'bfi', 'bfxil', 'lsr', 'lsl', 'asr', 'mul', 'madd', 'umull', 'smull',
             'brk', 'udf', 'casp', 'cas', 'ldaxr', 'stlxr', 'ldxr', 'stxr', 'ldadd', 'swpal',
             'ldar', 'stlr', 'ccmp', 'ccmn')
COND = ('b.',)

def score(adds, dels, reps, ca, cb):
    s = 0; why = []
    for ins in adds:
        op = ins.split(' ', 1)[0]
        if op in ('cbz', 'cbnz'):
            s += 5; why.append('new null/zero check: ' + ins)
        elif op in ('tbz', 'tbnz'):
            s += 4; why.append('new bit test: ' + ins)
        elif op.startswith('b.') or op in ('b', 'bl'):
            s += 3; why.append('new branch/call: ' + ins)
        elif op in ('cmp', 'cmn', 'tst', 'ccmp', 'ccmn'):
            s += 5; why.append('new compare: ' + ins)
        elif op.startswith('ldr') or op.startswith('ldur'):
            s += 2; why.append('new load (count/size?): ' + ins)
        elif op in ('and', 'ands', 'ubfx', 'sbfx', 'lsr', 'asr', 'lsl'):
            s += 2; why.append('new mask/shift: ' + ins)
        elif op in ('casp', 'cas', 'ldaxr', 'stlxr', 'ldxr', 'stxr', 'ldadd', 'swpal', 'ldar', 'stlr'):
            s += 6; why.append('new atomic/refcount op: ' + ins)
        elif op in ('brk', 'udf'):
            s += 8; why.append('new trap: ' + ins)
    for a, b in reps:
        oa = a.split(' ', 1)[0]; ob = b.split(' ', 1)[0]
        if oa != ob:
            if ob in ('cmp', 'cmn', 'tst', 'cbz', 'cbnz', 'tbz', 'tbnz') or ob.startswith('b.'):
                s += 4; why.append('opcode change %s -> %s' % (a, b))
        else:
            imm_a = re.findall(r'#(-?0x[0-9a-fA-F]+|-?\d+)', a)
            imm_b = re.findall(r'#(-?0x[0-9a-fA-F]+|-?\d+)', b)
            if imm_a != imm_b and oa in CHECK_OPS:
                s += 5; why.append('immediate change: %s  ->  %s' % (a, b))
    for ins in dels:
        op = ins.split(' ', 1)[0]
        if op in ('cmp', 'cmn', 'tst', 'cbz', 'cbnz', 'tbz', 'tbnz', 'brk', 'udf'):
            s += 2; why.append('removed check/trap: ' + ins)
    return s, why

out = []
for c in changed:
    ca = next(x for x in pa if x['start'] == c['a'])
    cb = next(x for x in pb if x['start'] == c['b'])
    adds, dels, reps = diff_summary(ca, cb)
    sc, why = score(adds, dels, reps, ca, cb)
    out.append(dict(**c, score=sc, why=why, adds=adds, dels=dels, reps=[[a, b] for a, b in reps]))

out.sort(key=lambda x: (-x['score'], x['sim'], -max(x['na'], x['nb'])))
json.dump(dict(changed=out, added=[dict(start=x['start'], n=x['n']) for x in added],
               removed=[dict(start=x['start'], n=x['n']) for x in removed],
               n_a=len(pa), n_b=len(pb)), open(r'G:/REPO\tools\opencode-temp\inv.json', 'w'))
print('wrote inv.json')
for x in out[:25]:
    print(f"score={x['score']:3d} a={x['a']:#x} b={x['b']:#x} insn {x['na']}->{x['nb']} sim={x['sim']:.3f} amb={x['amb']}")
    for w in x['why'][:6]:
        print('   ', w)
