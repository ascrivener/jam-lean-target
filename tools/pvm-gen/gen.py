#!/usr/bin/env python3
"""Deterministic PVM edge-case generators (GP v0.8.0 Appendix A).

    python3 tools/pvm-gen/gen.py OUTDIR [--seed N] [--families a,b,...]

Writes one JSONL file per family into OUTDIR, one testcase per line, in the koute/jamtestvectors
`pvm/programs` format without `assert` steps (the runners fill them in). Same seed, same output.
"""
import argparse
import json
import os
import random

from asm import (BY_FMT, FMT, HALT, I, M64, OP, OPCODES, RUN, TERMINATORS, VALID, blob, enc_nat, layout,
                 le, mapp, pack_mask, program, setregs, testcase, write)

# Boundary values for registers.
B64 = [0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 33, 63, 64, 65, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF,
       2**31 - 1, 2**31, 2**31 + 1, 2**32 - 1, 2**32, 2**32 + 1, 2**63 - 1, 2**63, 2**63 + 1,
       M64, M64 - 1, 0xFFFFFFFF80000000, 0x8000000080000000, 0x0123456789ABCDEF]
# Immediates (each is sign-extended from at most 4 octets).
IMMS = [0, 1, 2, 31, 32, 33, 63, 64, 65, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFF, 0x800000,
        2**31 - 1, M64, M64 - 1, (-0x80) & M64, (-0x8000) & M64, (-2**31) & M64, (-32) & M64, (-64) & M64]

RW = 0x20000   # read-write page
RO = 0x21000   # read-only page
UN = 0x22000   # unmapped page (also 0x1F000 below RW)


def mem_setup():
    return [mapp(RW, 4096, True), mapp(RO, 4096, False),
            write(RW, range(1, 33)), write(RW + 4096 - 16, range(0xF0, 0x100)),
            write(RO, range(0x81, 0xA1)), write(RO + 4096 - 16, range(0x10, 0x20))]


def fam_threereg(rng):
    out = []
    ops = BY_FMT["threeReg"]
    for name in ops:
        pairs = [(a, b) for a in B64 for b in B64]
        # every op: the full cross product would be 34^2; take a deterministic sample plus edges
        rng.shuffle(pairs)
        pairs = pairs[:300]
        for k, (a, b) in enumerate(pairs):
            prog, _ = program([I(name, 7, 8, 9), I("trap")])
            out.append(testcase(f"threereg_{name}_{k}", prog, setregs({7: a, 8: b, 9: 0xDEADBEEF}) + [RUN]))
        # aliasing: d = a, d = b, a = b
        for k, (a, b) in enumerate(pairs[:20]):
            for tag, (ra, rb, rd) in {"da": (7, 8, 7), "db": (7, 8, 8), "ab": (7, 7, 9), "all": (7, 7, 7)}.items():
                prog, _ = program([I(name, ra, rb, rd), I("trap")])
                out.append(testcase(f"threereg_{name}_alias{tag}_{k}", prog, setregs({7: a, 8: b, 9: 5}) + [RUN]))
        # register nibbles 13..15 (clamped to 12) and third-register octets >= 13 (GP #554)
        for rd in [12, 13, 15, 16, 0x17, 0x1C, 0x80, 0xFF]:
            prog, _ = program([I(name, 7, 8, rd), I("trap")])
            out.append(testcase(f"threereg_{name}_rd{rd}", prog, setregs({7: 0x1234, 8: 3, 12: 0x77, 0: 0x99}) + [RUN]))
        for ra, rb in [(13, 8), (7, 14), (15, 15)]:
            prog, _ = program([I(name, ra, rb, 9), I("trap")])
            out.append(testcase(f"threereg_{name}_ra{ra}_rb{rb}", prog, setregs({7: 0x1234, 8: 3, 12: 0x55}) + [RUN]))
    return out


def fam_tworeg(rng):
    out = []
    for name in BY_FMT["twoReg"]:
        for k, a in enumerate(B64):
            prog, _ = program([I(name, 9, 7), I("trap")])
            out.append(testcase(f"tworeg_{name}_{k}", prog, setregs({7: a, 9: 0xDEAD}) + [RUN]))
        for k in range(10):
            a = rng.getrandbits(64)
            prog, _ = program([I(name, 7, 7), I("trap")])
            out.append(testcase(f"tworeg_{name}_same_{k}", prog, setregs({7: a}) + [RUN]))
        for rd, ra in [(13, 7), (7, 13), (15, 14)]:
            prog, _ = program([I(name, rd, ra), I("trap")])
            out.append(testcase(f"tworeg_{name}_nib_{rd}_{ra}", prog, setregs({7: 0x8081, 12: 0xFF00FF}) + [RUN]))
    return out


def fam_tworegimm(rng):
    out = []
    alu = [n for n in BY_FMT["twoRegImm"] if not n.startswith(("load_ind", "store_ind"))]
    for name in alu:
        k = 0
        for a in B64:
            for x in IMMS:
                if rng.random() < 0.35:
                    prog, _ = program([I(name, 9, 7, x), I("trap")])
                    out.append(testcase(f"tworegimm_{name}_{k}", prog, setregs({7: a, 9: 0x5555}) + [RUN]))
                    k += 1
        # immediate lengths: explicit 0..4 octets of the same low bits, and same register
        for n in range(5):
            prog, _ = program([I(name, 9, 7, 0xFFFFFF80 & ((1 << (8 * n)) - 1), lx=n), I("trap")])
            out.append(testcase(f"tworegimm_{name}_len{n}", prog, setregs({7: 0x8000000000000001, 9: 3}) + [RUN]))
        prog, _ = program([I(name, 7, 7, 0x21), I("trap")])
        out.append(testcase(f"tworegimm_{name}_same", prog, setregs({7: 0xF0F0F0F0F0F0F0F0}) + [RUN]))
    return out


def fam_regimm(rng):
    out = []
    # load_imm / load_imm_64
    for k, x in enumerate(IMMS):
        prog, _ = program([I("load_imm", 7, x), I("trap")])
        out.append(testcase(f"loadimm_{k}", prog, setregs({7: 5}) + [RUN]))
    for k, x in enumerate(B64):
        prog, _ = program([I("load_imm_64", 7, x), I("trap")])
        out.append(testcase(f"loadimm64_{k}", prog, [RUN]))
    for n in range(5):
        prog, _ = program([I("load_imm", 7, 0x80808080 & ((1 << (8 * n)) - 1), lx=n), I("trap")])
        out.append(testcase(f"loadimm_len{n}", prog, setregs({7: 5}) + [RUN]))
    return out


def addr_cases():
    """(tag, address) at page edges; widths straddle where address + w crosses a page."""
    return [("rw0", RW), ("rw1", RW + 1), ("rwend", RW + 4095), ("rwend3", RW + 4093), ("rwend7", RW + 4089),
            ("ro0", RO), ("roend", RO + 4095), ("roend7", RO + 4089), ("un0", UN), ("unm1", UN - 1),
            ("unm4", UN - 4), ("below", RW - 1), ("below4", RW - 4), ("low0", 0), ("low1", 0xFFFF),
            ("low2", 0x10000), ("lowedge", 0x10000 - 2), ("top", 0xFFFFFFFF), ("top7", 0xFFFFFFF9),
            ("halt", HALT), ("big", 2**32 + RW), ("neg", (RW - 2**32) & M64)]


def fam_memory(rng):
    out = []
    loads = ["load_u8", "load_i8", "load_u16", "load_i16", "load_u32", "load_i32", "load_u64"]
    stores = ["store_u8", "store_u16", "store_u32", "store_u64"]
    for tag, a in addr_cases():
        if a < 2**31 or a >= 2**64 - 2**31:   # representable as a 4-octet sign-extended immediate
            for name in loads + stores:
                prog, _ = program([I(name, 7, a), I("trap")])
                out.append(testcase(f"mem_{name}_{tag}", prog, mem_setup() + setregs({7: 0x1122334455667788}) + [RUN]))
            for name, w in [("store_imm_u8", 1), ("store_imm_u16", 2), ("store_imm_u32", 4), ("store_imm_u64", 8)]:
                prog, _ = program([I(name, a, (-2) & M64), I("trap")])
                out.append(testcase(f"mem_{name}_{tag}", prog, mem_setup() + [RUN]))
        # indirect forms: base register + immediate
        for name in [n for n in BY_FMT["twoRegImm"] if n.startswith(("load_ind", "store_ind"))]:
            for imm in [0, 1, (-1) & M64]:
                prog, _ = program([I(name, 7, 8, imm), I("trap")])
                out.append(testcase(f"mem_{name}_{tag}_i{imm & 0xF}", prog,
                                    mem_setup() + setregs({7: 0xA1B2C3D4E5F60718, 8: (a - imm) & M64}) + [RUN]))
        for name in BY_FMT["regTwoImm"]:
            prog, _ = program([I(name, 8, 0, 0x7B)])
            prog, _ = program([I(name, 8, 0, (-3) & M64), I("trap")])
            out.append(testcase(f"mem_{name}_{tag}", prog, mem_setup() + setregs({8: a}) + [RUN]))
    # same-register indirect: load_ind into its own base
    for name in ["load_ind_u64", "load_ind_u8", "store_ind_u64"]:
        prog, _ = program([I(name, 7, 7, 8), I("trap")])
        out.append(testcase(f"mem_{name}_selfbase", prog, mem_setup() + setregs({7: RW}) + [RUN]))
    # multi-page mapping, store straddling RW->RW (both writable) and RW->RO
    steps = [mapp(0x30000, 8192, True), mapp(0x32000, 4096, False)]
    for name in stores:
        for a in [0x30FFD, 0x31FFD, 0x31FFF]:
            prog, _ = program([I(name, 7, a), I("trap")])
            out.append(testcase(f"mem_multi_{name}_{a:x}", prog, steps + setregs({7: M64}) + [RUN]))
    # page mapped below 2^16 (GP prose vs formula, jam-lean note 3)
    for name in ["load_u8", "store_u8", "load_u64", "store_u64"]:
        for a in [0, 0x1000, 0xFFF8, 0xFFFF]:
            prog, _ = program([I(name, 7, a), I("trap")])
            out.append(testcase(f"mem_lowmapped_{name}_{a:x}", prog,
                                [mapp(0, 0x11000, True)] + setregs({7: 0xFF}) + [RUN]))
    # store then fault in the same block: memory must be unchanged by the faulting instruction only
    prog, _ = program([I("store_u32", 7, RW), I("store_u32", 7, UN - 2), I("trap")])
    out.append(testcase("mem_store_then_fault", prog, mem_setup() + setregs({7: 0xAABBCCDD}) + [RUN]))
    # fault, then resume after mapping the page
    prog, _ = program([I("load_u32", 7, UN), I("trap")])
    out.append(testcase("mem_fault_resume", prog, mem_setup() + [RUN, mapp(UN, 4096, False), RUN]))
    return out


def fam_gas(rng):
    out = []
    progs = {
        "one": [I("add_64", 7, 8, 9), I("trap")],
        "trap": [I("trap")],
        "fall": [I("fallthrough"), I("trap")],
        "two_blocks": [I("add_64", 7, 8, 9), I("fallthrough"), I("mul_64", 7, 8, 9), I("trap")],
        "jump": [I("jump", "b"), I("trap"), I("add_64", 7, 7, 7), I("trap")],
        "branch": [I("branch_eq_imm", 7, 0, "b"), I("trap"), I("add_64", 7, 7, 7), I("trap")],
        "div": [I("div_u_64", 7, 8, 9), I("rem_s_64", 7, 8, 9), I("mul_upper_s_s", 1, 2, 3), I("trap")],
        "mem": [I("load_u64", 7, RW), I("store_u64", 7, RW + 8), I("trap")],
        "ecalli": [I("ecalli", 3), I("add_64", 7, 8, 9), I("trap")],
        "loop": [I("add_imm_64", 7, 7, 1), I("branch_ne_imm", 7, 5, "top"), I("trap")],
        "cmov": [I("cmov_iz", 7, 8, 9), I("cmov_nz", 9, 8, 7), I("trap")],
        "unlikely": [I("unlikely"), I("add_64", 7, 8, 9), I("trap")],
        "halt": [I("load_imm", 0, (-2**16) & M64), I("jump_ind", 0, 0)],
        "long": [I("add_64", 7, 8, 9)] * 40 + [I("trap")],
    }
    labels = {"jump": {"b": 2}, "branch": {"b": 2}, "loop": {"top": 0}}
    for tag, instrs in progs.items():
        prog, _ = program(instrs, labels=labels.get(tag))
        steps = (mem_setup() if tag == "mem" else []) + setregs({8: 3, 9: 7})
        top = 120 if tag in ("long", "loop") else 60
        for g in list(range(0, top)) + [10000, 2**63 - 1]:
            run = [RUN, RUN] if tag == "ecalli" else [RUN]
            out.append(testcase(f"gas_{tag}_{g}", prog, steps + run, gas=g))
    return out


def fam_jumps(rng):
    out = []
    # jump table: entries pointing at block starts, mid-instruction, non-block-start, out of range
    body = [I("jump_ind", 7, 0), I("load_imm", 8, 1), I("trap"), I("load_imm", 8, 2), I("add_64", 8, 8, 8),
            I("trap"), I("load_imm", 8, 3), I("trap")]
    code, mask, starts = layout(body)
    # starts: 0 jump_ind(2-3 bytes), ... ; block starts are after terminators
    jt_variants = {
        "valid": [starts[1], starts[3], starts[6]],
        "nonblock": [starts[4]],
        "mid": [starts[3] + 1],
        "oob": [len(code) + 5],
        "end": [len(code)],
        "zero": [0],
        "big": [2**31 + starts[1]],
    }
    for jtag, jt in jt_variants.items():
        for z in sorted({max(1, (max(jt).bit_length() + 7) // 8), 4}):
            if max(jt) >= 256**z:
                continue
            p = blob(code, mask, jt, z=z)
            for v in dict.fromkeys([0, 1, 2, 3, 4, 5, 6, 8, 2 * len(jt), 2 * len(jt) + 1, 2 * len(jt) + 2, HALT,
                                    HALT - 2, HALT + 2, HALT + 1, 2**32 + 2, M64 - 1, M64, 2**32 - 2, 2**31]):
                out.append(testcase(f"jt_{jtag}_z{z}_v{v:x}", p, setregs({7: v, 8: 9}) + [RUN]))
    # jump_ind with immediate wrap (ω_A + ν_X mod 2^32)
    p = blob(code, mask, jt_variants["valid"], z=1)
    for a, x in [(HALT - 1, 1), (2**32 - 1, 3), (2**64 - 2, 4), (HALT + 2**32, 0)]:
        prog, _ = program([I("jump_ind", 7, x)] + body[1:], jump_table=jt_variants["valid"], z=1)
        out.append(testcase(f"jt_wrap_{a:x}_{x}", prog, setregs({7: a}) + [RUN]))
    # load_imm_jump_ind (sets ω_A, jumps to ω_B + ν_Y), incl. ra == rb
    for ra, rb in [(9, 7), (7, 7)]:
        for v in [2, 4, 3, HALT, 0, 100]:
            prog, _ = program([I("load_imm_jump_ind", ra, rb, 0x42, 0)] + body[1:], jump_table=jt_variants["valid"], z=1)
            out.append(testcase(f"lijind_{ra}_{rb}_{v:x}", prog, setregs({7: v}) + [RUN]))
    # static jumps and branches to: valid block start, non-block-start, mid-instruction, beyond end,
    # negative, own address (loop until out of gas)
    seq = [I("load_imm", 9, 1), I("trap"), I("add_64", 9, 9, 9), I("add_64", 9, 9, 9), I("trap")]
    code0, mask0, st = layout([I("jump", 0)] + seq)
    targets = {"block": st[2], "nonblock": st[4], "mid": st[3] + 1, "end": len(code0), "past": len(code0) + 10,
               "self": 0, "neg": (-5) & 0xFFFFFFFF}
    for name in ["jump"] + BY_FMT["regImmOffset"] + BY_FMT["twoRegOffset"]:
        for ttag, t in targets.items():
            if FMT[name] == "oneOffset":
                first = I(name, t, lx=4)
            elif FMT[name] == "regImmOffset":
                first = I(name, 7, 0, t, ly=4)
            else:
                first = I(name, 7, 8, t, lx=4)
            code, mask, _ = layout([first] + seq)
            p = blob(code, mask)
            for regs in [{7: 0, 8: 0}, {7: 1, 8: M64}]:
                out.append(testcase(f"branch_{name}_{ttag}_{regs[7]}", p, setregs(regs) + [RUN], gas=200))
    # branch comparisons at sign boundaries
    for name in BY_FMT["twoRegOffset"]:
        for k, (a, b) in enumerate([(0, M64), (M64, 0), (2**63, 2**63 - 1), (2**63 - 1, 2**63), (5, 5), (0, 0)]):
            prog, _ = program([I(name, 7, 8, "t"), I("load_imm", 9, 1), I("trap"), I("load_imm", 9, 2), I("trap")],
                              labels={"t": 3})
            out.append(testcase(f"cmp_{name}_{k}", prog, setregs({7: a, 8: b}) + [RUN]))
    for name in BY_FMT["regImmOffset"]:
        if name == "load_imm_jump":
            continue
        for k, (a, x) in enumerate([(0, M64), (M64, 0), (M64, M64), (2**63, (-2**31) & M64), (2**31, 2**31 - 1),
                                    (2**31 - 1, 2**31 - 1), ((-2**31) & M64, (-2**31) & M64), (0x80, 0x80)]):
            prog, _ = program([I(name, 7, x, "t"), I("load_imm", 9, 1), I("trap"), I("load_imm", 9, 2), I("trap")],
                              labels={"t": 3})
            out.append(testcase(f"cmpi_{name}_{k}", prog, setregs({7: a}) + [RUN]))
    return out


def fam_code(rng):
    """Invalid, truncated and odd code."""
    out = []
    def tc(name, p, steps=None, pc=0, gas=1000):
        out.append(testcase(name, p, (steps or setregs({7: 0x1234, 8: 3})) + [RUN], pc=pc, gas=gas))
    base = [I("add_64", 7, 8, 9), I("trap")]
    code, mask, _ = layout(base)
    tc("code_ok", blob(code, mask))
    # every octet value as an opcode (valid or not), followed by trap
    for op in range(256):
        tc(f"code_op{op}", blob([op, 0x87, 0x09, 0], [1, 0, 0, 1]))
        tc(f"code_oponly{op}", blob([op], [1]))
    # program not ending in a terminator; ending mid-instruction (mask bits beyond)
    tc("code_noterm", blob(code[:-1], mask[:-1]))
    tc("code_empty", blob([], []))
    tc("code_trunc_imm", blob([OP["load_imm"], 7, 0x34], [1, 0, 0]))
    tc("code_trunc_threereg", blob([OP["add_64"], 0x87], [1, 0]))
    tc("code_trunc_threereg_term", blob([OP["add_64"], 0x87, 0], [1, 0, 1]))
    tc("code_trunc_ext", blob([OP["load_imm_64"], 7, 1, 2, 3], [1, 0, 0, 0, 0]))
    tc("code_trunc_ext_trap", blob([OP["load_imm_64"], 7, 1, 2, 3, 0], [1, 0, 0, 0, 0, 1]))
    tc("code_ext_short_skip", blob([OP["load_imm_64"], 7, 1, 2, 0, 0, 0, 0, 0, 0], [1, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
    # first mask bit zero; extra mask bits set inside an instruction; non-zero padding
    tc("code_mask0", blob(code, [0] + mask[1:]))
    tc("code_mask_inside", blob(code, [1, 1, 0, 1]))
    tc("code_mask_pad", blob(code, mask, mask_bytes=pack_mask(mask, pad=0x80)))
    tc("code_mask_short", blob(code, mask, mask_bytes=[]))
    tc("code_mask_long", blob(code, mask, mask_bytes=pack_mask(mask) + [0]))
    tc("code_mask_long1", blob(code, mask, mask_bytes=pack_mask(mask) + [1]))
    # 8-, 9-, 16-octet code for bitmask byte boundaries
    for n in [7, 8, 9, 15, 16, 17]:
        c = [OP["fallthrough"]] * (n - 1) + [0]
        tc(f"code_len{n}", blob(c, [1] * n))
        tc(f"code_len{n}_pad", blob(c, [1] * n, mask_bytes=pack_mask([1] * n, pad=0x80 if n % 8 else 0)))
    # skip lengths: argument runs of 0..30 octets (skip is capped at 24)
    for n in [0, 1, 2, 3, 4, 5, 8, 9, 10, 12, 16, 23, 24, 25, 26, 30]:
        for op in ["add_64", "load_imm", "load_imm_64", "store_imm_u32", "branch_eq_imm", "jump", "ecalli",
                   "load_imm_jump_ind", "trap", "fallthrough", "move_reg", "add_imm_64", "store_imm_ind_u32"]:
            args = [0x87, 0x29, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86] + [0x11] * 30
            c = [OP[op]] + args[:n] + [0]
            tc(f"skip_{op}_{n}", blob(c, [1] + [0] * n + [1]),
               mem_setup() + setregs({7: RW, 8: 3, 9: 4, 2: 5}), gas=1000)
            # same, but the run of arguments reaches the end of code (no trailing trap)
            if n in (0, 3, 24, 25):
                c2 = [OP[op]] + args[:n]
                tc(f"skipend_{op}_{n}", blob(c2, [1] + [0] * n), mem_setup() + setregs({7: RW, 8: 3}))
    # jump table header edge cases
    code, mask, st = layout([I("jump_ind", 7, 0), I("trap"), I("load_imm", 8, 5), I("trap")])
    for z in range(0, 9):
        jt = [st[2]] * 2
        jtb = sum((le(e, z) for e in jt), []) if z <= 8 else []
        tc(f"jthdr_z{z}", blob(code, mask, jt, z=z, raw_jt=jtb), setregs({7: 2}))
    tc("jthdr_len_too_long", blob(code, mask, [st[2]], z=1, jlen=5), setregs({7: 2}))
    tc("jthdr_len_big", blob(code, mask, [], z=1, jlen=2**20), setregs({7: 2}))
    tc("jthdr_z0_entries", blob(code, mask, [], z=0, jlen=3, raw_jt=[]), setregs({7: 2}))
    tc("jthdr_z255", blob(code, mask, [], z=255, jlen=0, raw_jt=[]), setregs({7: 2}))
    tc("jthdr_z5_one", blob(code, mask, [st[2]], z=5, raw_jt=le(st[2], 5)), setregs({7: 2}))
    tc("jthdr_many", blob(code, mask, [st[2]] * 1000, z=1), setregs({7: 2000}))
    # code length field wrong
    tc("clen_short", blob(code, mask, clen=len(code) - 1))
    tc("clen_long", blob(code, mask, clen=len(code) + 1))
    tc("clen_zero", blob(code, mask, clen=0))
    # non-canonical varints (E requires the canonical encoding)
    good = blob(code, mask)
    tc("varint_noncanon_jlen", [0x80, 0x00] + good[1:])
    tc("varint_noncanon_clen", good[:2] + [0x80, len(code)] + good[3:])
    tc("varint_trailing", good + [0])
    tc("varint_truncated", good[:2])
    tc("blob_empty", [])
    # initial pc: mid-instruction, at end, past end, at a non-block-start instruction, at trap
    code, mask, st = layout([I("load_imm", 7, 1), I("load_imm", 8, 2), I("add_64", 7, 8, 9), I("trap")])
    for pc in [0, 1, st[1], st[2], st[3], len(code), len(code) + 1, 2**31]:
        tc(f"initpc_{pc}", blob(code, mask), pc=pc)
    # code with an invalid opcode after the last terminator (unreachable) and in the middle
    tc("code_bad_after_term", blob([0, 0xFF], [1, 1]))
    tc("code_bad_unreachable", blob([OP["jump"], 3, 0xFF, 0], [1, 0, 1, 1]))
    tc("code_unlikely_end", blob([OP["unlikely"]], [1]))
    tc("code_ecalli_end", blob([OP["ecalli"], 1], [1, 0]))
    return out


def fam_ecalli(rng):
    out = []
    for x in [0, 1, 0x7F, 0x80, 0xFFFF, 2**31 - 1, M64, (-2**31) & M64]:
        prog, _ = program([I("ecalli", x), I("load_imm", 7, 9), I("ecalli", 1), I("trap")])
        out.append(testcase(f"ecalli_{x:x}", prog, [RUN, RUN, RUN]))
    # ecalli as last instruction (not a terminator in T)
    prog, _ = program([I("load_imm", 7, 9), I("ecalli", 5)])
    out.append(testcase("ecalli_last", prog, [RUN, RUN]))
    # gas: ecalli at exactly the end of the block's gas
    for g in range(0, 12):
        prog, _ = program([I("ecalli", 1), I("ecalli", 2), I("trap")])
        out.append(testcase(f"ecalli_gas_{g}", prog, [RUN, RUN, RUN], gas=g))
    # resume after ecalli with modified registers / jump after ecalli
    prog, _ = program([I("ecalli", 0), I("jump_ind", 7, 0)])
    out.append(testcase("ecalli_then_halt", prog, [RUN, {"set-reg": {"reg": 7, "value": HALT}}, RUN]))
    return out


def fam_random(rng, n=6000):
    """Random straight-line/branchy programs over all valid opcodes, with memory."""
    out = []
    names = [nm for _, nm, _ in OPCODES]
    for k in range(n):
        instrs = []
        for _ in range(rng.randint(1, 12)):
            nm = rng.choice(names)
            f = FMT[nm]
            r = lambda: rng.choice([0, 1, 7, 8, 9, 12, rng.randrange(16)])
            v = lambda: rng.choice(IMMS + [rng.getrandbits(31), RW + rng.randrange(-8, 4100), RO + rng.randrange(4096)]) & M64
            tgt = lambda: rng.randrange(0, 40)
            if f == "noArgs": ins = I(nm)
            elif f == "oneImm": ins = I(nm, v())
            elif f == "regExtImm": ins = I(nm, r(), rng.choice(B64))
            elif f == "twoImm": ins = I(nm, v(), v())
            elif f == "oneOffset": ins = I(nm, tgt(), lx=rng.choice([None, 4]))
            elif f == "regImm": ins = I(nm, r(), v())
            elif f == "regTwoImm": ins = I(nm, r(), v(), v())
            elif f == "regImmOffset": ins = I(nm, r(), v(), tgt())
            elif f == "twoReg": ins = I(nm, r(), r())
            elif f == "twoRegImm": ins = I(nm, r(), r(), v())
            elif f == "twoRegOffset": ins = I(nm, r(), r(), tgt())
            elif f == "twoRegTwoImm": ins = I(nm, r(), r(), v(), v())
            else: ins = I(nm, r(), r(), r())  # third-register octets >= 16: GP #554, see fam_threereg
            instrs.append(ins)
        if rng.random() < 0.9:
            instrs.append(I("trap"))
        code, mask, st = layout(instrs)
        jt = [rng.choice(st + [len(code), 1]) for _ in range(rng.randint(0, 3))]
        p = blob(code, mask, jt)
        regs = {i: rng.choice(B64 + [RW, RW + 4090, RO, UN, HALT, 2, 4]) for i in range(13) if rng.random() < 0.6}
        out.append(testcase(f"random_{k}", p, mem_setup() + setregs(regs) + [RUN, RUN],
                            gas=rng.choice([10000, 10000, rng.randrange(0, 200)])))
    return out


FAMILIES = {"threereg": fam_threereg, "tworeg": fam_tworeg, "tworegimm": fam_tworegimm, "regimm": fam_regimm,
            "memory": fam_memory, "gas": fam_gas, "jumps": fam_jumps, "code": fam_code, "ecalli": fam_ecalli,
            "random": fam_random}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--seed", type=int, default=20261115)
    ap.add_argument("--families", default=",".join(FAMILIES))
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    for fam in a.families.split(","):
        rng = random.Random(f"{a.seed}:{fam}")
        cases = FAMILIES[fam](rng)
        names = [c["name"] for c in cases]
        assert len(names) == len(set(names)), f"duplicate names in {fam}"
        with open(os.path.join(a.outdir, f"{fam}.jsonl"), "w") as f:
            for c in cases:
                f.write(json.dumps(c, separators=(",", ":")) + "\n")
        print(f"{fam}: {len(cases)} cases")


if __name__ == "__main__":
    main()
