#!/usr/bin/env python3
"""Function-level normalized diff between two stripped arm64e kexts.

Normalization:
  - strip address + raw-byte columns
  - mask direct branch / adr / adrp targets (internal -> LOCAL_<index>)
  - mask adrp-page-relative displacements (adrp+add, adrp+ldr)
  - KEEP every other immediate verbatim (cmp/and/tst/mov immediates, struct offsets)
Second pass:
  - replace external in-image branch targets with the sha1 of the callee's
    pass-1 normalized body, so callee-identity changes survive layout shifts.
"""
import re, sys, json, hashlib, difflib, bisect

LINE_RE = re.compile(r'^\s*(0x[0-9a-fA-F]+):\s*(.*)$')
BYTES_RE = re.compile(r'^(?:(?:[0-9a-fA-F]{2})\s+)+')
BR = {'b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz', 'adr', 'adrp', 'br', 'blr', 'ret'}

def load_insns(path):
    ins = []
    with open(path, encoding='utf-16') as f:
        for line in f:
            m = LINE_RE.match(line)
            if not m:
                continue
            a = int(m.group(1), 16)
            body = BYTES_RE.sub('', m.group(2).strip())
            body = body.replace('\t', ' ').strip()
            body = re.sub(r'\s+', ' ', body)
            if not body:
                continue
            parts = body.split(' ', 1)
            op = parts[0]
            args = parts[1] if len(parts) > 1 else ''
            ins.append((a, op, args))
    return ins

def load_starts(path):
    with open(path, encoding='utf-16') as f:
        return sorted(int(x.strip(), 16) for x in f if x.strip())

def split_operands(args):
    # operands do not contain commas inside brackets/immediates here
    return [x.strip() for x in args.split(',')]

def is_addr(tok):
    return re.fullmatch(r'#?0x[0-9a-fA-F]+', tok) is not None

def norm_func(insns, starts_set, h1=None, addr_index=None):
    """insns: list of (addr, op, args). Returns list of normalized strings."""
    addrs = [a for a, _, _ in insns]
    out = []
    pages = set()      # regs currently holding a raw adrp page base
    for i, (a, op, args) in enumerate(insns):
        ops = split_operands(args) if args else []
        # --- adrp / adr: record page register, mask target
        if op == 'adrp':
            dst = ops[0]
            out.append('adrp %s, PAGE' % dst)
            pages.add(dst)
            continue
        if op == 'adr':
            dst = ops[0]
            out.append('adr %s, ADDR' % dst)
            pages.discard(dst)
            continue
        # --- branch family: mask target
        if op in ('b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz') or op.startswith('b.'):
            if ops and is_addr(ops[-1]):
                t = int(ops[-1].lstrip('#'), 16)
                if t in addr_index:
                    tok = 'LOCAL_%d' % addr_index[t]
                elif h1 is not None and t in h1:
                    tok = 'CALLEE_' + h1[t][:10]
                else:
                    tok = 'EXTERNAL'
                ops[-1] = tok
            out.append(op + ' ' + ', '.join(ops))
            continue
        # --- page-relative add: add xN, xN, #imm
        if op in ('add', 'sub') and len(ops) == 3 and ops[0] in pages and ops[1] == ops[0] \
           and ops[2].startswith('#'):
            out.append('%s %s, %s, #PAGEOFF' % (op, ops[0], ops[1]))
            pages.discard(ops[0])   # now a full address; keep struct offsets
            continue
        # --- load/store from a page register: mask displacement
        if op.startswith(('ldr', 'str', 'ldur', 'stur')) and ops:
            mem = ops[-1]
            m = re.match(r'\[([^,\]]+)(?:, #(0x[0-9a-fA-F]+))?\]$', mem)
            if m and m.group(1) in pages and m.group(2):
                ops[-1] = '[%s, #PAGEOFF]' % m.group(1)
                out.append(op + ' ' + ', '.join(ops))
                # destination/base write handling below still applies
                # fall through to write-tracking
                dst = ops[0]
                if not op.startswith('str') and not op.startswith('stur'):
                    pages.discard(dst)
                continue
        out.append(op + (' ' + ', '.join(ops) if ops else ''))
        # --- track register writes to invalidate page marks
        if ops:
            writes = False
            if op in ('str', 'stur', 'stp', 'stnp', 'cmp', 'cmn', 'tst', 'tbz', 'tbnz',
                      'cbz', 'cbnz', 'b', 'bl', 'ret', 'br', 'blr'):
                writes = False
            elif op.startswith('st'):
                writes = False
            else:
                writes = True
            if writes:
                dst = ops[0].lstrip('!')
                # post-indexed store uses [x], #imm
                pages.discard(dst)
    return out

def group(insns, starts):
    addrs = [a for a, _, _ in insns]
    out = []
    for i, s in enumerate(starts):
        e = starts[i+1] if i+1 < len(starts) else (addrs[-1] + 4)
        lo = bisect.bisect_left(addrs, s)
        hi = bisect.bisect_left(addrs, e)
        if hi > lo:
            out.append((s, insns[lo:hi]))
    return out

def hbody(body):
    return hashlib.sha1('\n'.join(body).encode()).hexdigest()

def run(path_a, starts_a, path_b, starts_b):
    ia = load_insns(path_a); sa = load_starts(starts_a)
    ib = load_insns(path_b); sb = load_starts(starts_b)
    ga = group(ia, sa); gb = group(ib, sb)
    print('funcs', len(ga), len(gb), file=sys.stderr)

    def pass1(g):
        res = []
        for s, ins in g:
            idx = {a: i for i, (a, _, _) in enumerate(ins)}
            body = norm_func(ins, set(sa) if g is ga else set(sb), None, idx)
            res.append((s, body, hbody(body)))
        return res

    pa = pass1(ga); pb = pass1(gb)
    h1a = {s: h for s, _, h in pa}
    h1b = {s: h for s, _, h in pb}

    def pass2(g, starts_set, h1):
        res = []
        for s, ins in g:
            idx = {a: i for i, (a, _, _) in enumerate(ins)}
            body = norm_func(ins, starts_set, h1, idx)
            res.append((s, body, hbody(body)))
        return res

    qa = pass2(ga, set(sa), h1a); qb = pass2(gb, set(sb), h1b)
    return qa, qb

if __name__ == '__main__':
    qa, qb = run(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    ha = [h for _, _, h in qa]; hb = [h for _, _, h in qb]
    sm = difflib.SequenceMatcher(a=ha, b=hb, autojunk=False)
    changed = []
    stats = dict(equal=0, replace_a=0, replace_b=0, insert=0, delete=0)
    for tag, a0, a1, b0, b1 in sm.get_opcodes():
        if tag == 'equal':
            stats['equal'] += a1 - a0
        elif tag == 'insert':
            stats['insert'] += b1 - b0
        elif tag == 'delete':
            stats['delete'] += a1 - a0
        else:
            stats['replace_a'] += a1 - a0
            stats['replace_b'] += b1 - b0
            n = max(a1 - a0, b1 - b0)
            for k in range(n):
                x, y = a0 + k, b0 + k
                if x < a1 and y < b1:
                    sim = difflib.SequenceMatcher(a=qa[x][1], b=qb[y][1], autojunk=False).ratio()
                    changed.append(dict(a=qa[x][0], b=qb[y][0], na=len(qa[x][1]), nb=len(qb[y][1]), sim=sim))
    print(json.dumps(dict(stats=stats, changed=changed, funcs_a=len(qa), funcs_b=len(qb)), indent=1))
