"""Derive GP v0.8.1 expectations of vectors/pvm from their GP v0.8.0 expectations, by rule only:
#554 (r_D = min(12, zeta mod 16)) with the §A.9 cost recomputed by an independent transcription of
the gas model and the v0.8.1 cost table; #559 (z <= 4, else the blob is invalid). Never uses the
model's output as an expectation; compares with it afterwards. Input: the v0.8.0 files (commit
671f256 of jam-lean-target); run from the repository root with the target built."""
import json, re, sys, subprocess, copy
TEX = sys.argv[1]; FILES = sys.argv[2]; MODE = sys.argv[3]  # pvm.tex of graypaper tag v0.8.1; a file listing the vectors; check | write
tex = open(TEX).read()
# opcode -> name
opname = {int(m.group(1)): m.group(2).replace('\\_', '_') for m in re.finditer(r'^\s*(\d+)&\\token\{([^}]*)\}&', tex, re.M)}
macros = {m.group(1): m.group(2) for m in re.finditer(r'\\newcommand\*\{\\(\w+)\}\{([^\n]*)\}\s*$', tex, re.M)}
costrow = {}
for m in re.finditer(r'^\s*\\token\{([^}]*)\}&(.*?)\s*\\\\ \\mrule', tex, re.M):
    name = m.group(1).replace('\\_', '_'); row = m.group(2).strip()
    mm = re.fullmatch(r'\\(\w+)', row)
    if mm and mm.group(1) in macros: row = macros[mm.group(1)]
    costrow[name] = row
def parse_row(row, src, dst, rA, rD):
    def ev(x):
        x = x.strip()
        m = re.fullmatch(r'\\ifdstandsrcoverlap\{(\d+)\}\{(\d+)\}', x)
        if m: return int(m.group(1)) if (src & dst) else int(m.group(2))
        m = re.fullmatch(r'\\ifdstandsrcoverlapshift\{(\d+)\}\{(\d+)\}', x)
        if m: return int(m.group(1)) if rA == rD else int(m.group(2))
        return int(x)
    p = [ev(x) for x in row.split('&')]
    return p[0], p[1], tuple(p[2:7])
MAXDEC, MAXSTART = 4, 5
def blockcost(instrs):
    i = 0; cyc = 0; dec = MAXDEC; start = MAXSTART; units = [4, 4, 4, 1, 1]; rob = []
    def ready():
        for j, e in enumerate(rob):
            if e['state'] == 'wait' and all(e['units'][k] <= units[k] for k in range(5)) and all(rob[k]['left'] == 0 for k in e['deps']):
                return j
    while True:
        l = len([e for e in rob if e['state'] is not None])
        if i is not None and instrs[i]['slots'] <= dec and l < 32:
            ins = instrs[i]
            for e in rob: e['regs'] = e['regs'] - ins['dst']
            deps = {j for j, e in enumerate(rob) if ins['src'] & e['regs']}
            rob.append(dict(state='decoding', left=ins['cycles'], deps=deps, regs=set(ins['dst']), units=ins['units']))
            dec -= ins['slots']; i = None if ins['term'] else i + 1
        elif ready() is not None and start > 0:
            n = ready(); start -= 1; units = [units[k] - rob[n]['units'][k] for k in range(5)]; rob[n]['state'] = 'exec'
        elif i is None and l == 0:
            break
        else:
            dec = MAXDEC; start = MAXSTART; cyc += 1
            for e in rob:
                if e['state'] == 'exec' and e['left'] == 1: units = [units[k] + e['units'][k] for k in range(5)]
            new = []
            for j, e in enumerate(rob):
                st = e['state']
                if all(rob[k]['state'] in ('executed', None) for k in range(j + 1)): ns = None
                elif st == 'decoding': ns = 'wait'
                elif st == 'exec' and e['left'] == 0: ns = 'executed'
                else: ns = st
                new.append(dict(e, state=ns, left=e['left'] - 1 if (st == 'exec' and e['left'] > 0) else e['left']))
            rob = new
    return max(cyc - 3, 1)
CMOV = {'cmov_iz', 'cmov_nz'}
def threereg(prog, old_rule):
    # blob: |j|=0, z=0, |c|, c, k ; c = [op, regbyte, zeta, (ignored skip octets), 0 (trap)]
    assert prog[0] == 0 and prog[1] == 0, prog
    n = prog[2]; c = prog[3:3 + n]; k = prog[3 + n:]
    bits = [i for i in range(n) if (k[i // 8] >> (i % 8)) & 1]
    assert bits == [0, n - 1] and c[-1] == 0 and n >= 4, prog
    op, rb, zeta = c[0], c[1], c[2]
    name = opname[op]
    rA, rB = min(12, rb % 16), min(12, rb // 16)
    rD = min(12, zeta) if old_rule else min(12, zeta % 16)
    src = {rA, rB} | ({rD} if name in CMOV else set()); dst = {rD}
    cyc, slots, units = parse_row(costrow[name], src, dst, rA, rD)
    trap = dict(cycles=2, slots=1, units=(0, 0, 0, 0, 0), src=set(), dst=set(), term=True)
    ins = dict(cycles=cyc, slots=slots, units=units, src=src, dst=dst, term=False)
    return name, rA, rB, rD, blockcost([ins, trap])
out = {}; bad = []
for f in open(FILES).read().split():
    old = json.load(open(f)); new = copy.deepcopy(old); prog = old['program']
    init = [0] * 13
    for s in old['steps']:
        if 'set-reg' in s: init[s['set-reg']['reg']] = s['set-reg']['value']
    ai = [i for i, s in enumerate(old['steps']) if 'assert' in s]
    assert len(ai) == 1, f
    a = old['steps'][ai[0]]['assert']; b = new['steps'][ai[0]]['assert']
    if prog[1] > 4:  # #559: z > 4, the blob is invalid: panic before any step
        b['status'] = 'panic'; b['pc'] = 0; b['regs'] = init; b['gas'] = old['initial-gas']
        assert a['memory'] == [] and not any('write' in s for s in old['steps']), f
        new['block-gas-costs'] = []
        rule = '#559'
    else:  # #554
        name, rA, rB, rD0, c0 = threereg(prog, True)
        _, _, _, rD1, c1 = threereg(prog, False)
        assert rD0 == 12 and rD1 != 12, (f, rD0, rD1)
        assert old['block-gas-costs'] == [{'cost': c0, 'pc': 0}] and a['gas'] == old['initial-gas'] - c0, (f, 'old cost not reproduced', c0)
        if name in CMOV: assert init[rA] != 0 if name == 'cmov_nz' else init[rA] == 0, f  # result does not read r_D
        regs = list(a['regs']); res = regs[12]; regs[12] = init[12]; regs[rD1] = res
        b['regs'] = regs; b['gas'] = old['initial-gas'] - c1; new['block-gas-costs'] = [{'cost': c1, 'pc': 0}]
        rule = f'#554 {name} rD {rD0}->{rD1} cost {c0}->{c1}'
    model = json.loads(subprocess.run(['.lake/build/bin/pvmrun', 'run', f], capture_output=True, text=True).stdout)
    ma = [s['assert'] for s in model['steps'] if 'assert' in s][0]
    ok = all(ma.get(k) == b[k] for k in b) and model.get('block-gas-costs') == new['block-gas-costs']
    print(f.split('/')[-1], rule, 'model agrees' if ok else 'MODEL DIFFERS')
    if not ok: bad.append(f)
    out[f] = new
if bad: print('MISMATCH', len(bad)); sys.exit(1)
if MODE == 'write':
    import importlib.util
    spec = importlib.util.spec_from_file_location('export', 'tools/pvm-gen/export.py'); ex = importlib.util.module_from_spec(spec); spec.loader.exec_module(ex)
    for f, tc in out.items():
        text = json.dumps(ex.ordered(tc), indent=2)
        text = re.sub(r"\[\s*(-?\d+(?:,\s*-?\d+)*)\s*\]", lambda m: "[" + ", ".join(re.split(r",\s*", m.group(1))) + "]", text)
        open(f, 'w').write(text + "\n")
    print('wrote', len(out))
