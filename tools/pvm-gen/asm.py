"""A small assembler for JAM PVM programs (GP v0.8.0, Appendix A), used by the case generators.

Programs are lists of instructions; each instruction is a list of octets whose first octet is the
opcode. `blob` lays them out as the program blob p = E(|j|) ++ E_1(z) ++ E(|c|) ++ E_z(j) ++ E(c) ++ E(k)
(GP §A.1); every field can be overridden to build malformed blobs.
"""

# (opcode, name, argument format) for every opcode of GP v0.8.0 §A.5 (same set as PolkaVM's JamV1).
OPCODES = [
    (0, "trap", "noArgs"), (1, "fallthrough", "noArgs"), (2, "unlikely", "noArgs"),
    (10, "ecalli", "oneImm"), (20, "load_imm_64", "regExtImm"),
    (30, "store_imm_u8", "twoImm"), (31, "store_imm_u16", "twoImm"), (32, "store_imm_u32", "twoImm"),
    (33, "store_imm_u64", "twoImm"), (40, "jump", "oneOffset"),
    (50, "jump_ind", "regImm"), (51, "load_imm", "regImm"), (52, "load_u8", "regImm"),
    (53, "load_i8", "regImm"), (54, "load_u16", "regImm"), (55, "load_i16", "regImm"),
    (56, "load_u32", "regImm"), (57, "load_i32", "regImm"), (58, "load_u64", "regImm"),
    (59, "store_u8", "regImm"), (60, "store_u16", "regImm"), (61, "store_u32", "regImm"),
    (62, "store_u64", "regImm"),
    (70, "store_imm_ind_u8", "regTwoImm"), (71, "store_imm_ind_u16", "regTwoImm"),
    (72, "store_imm_ind_u32", "regTwoImm"), (73, "store_imm_ind_u64", "regTwoImm"),
    (80, "load_imm_jump", "regImmOffset"), (81, "branch_eq_imm", "regImmOffset"),
    (82, "branch_ne_imm", "regImmOffset"), (83, "branch_lt_u_imm", "regImmOffset"),
    (84, "branch_le_u_imm", "regImmOffset"), (85, "branch_ge_u_imm", "regImmOffset"),
    (86, "branch_gt_u_imm", "regImmOffset"), (87, "branch_lt_s_imm", "regImmOffset"),
    (88, "branch_le_s_imm", "regImmOffset"), (89, "branch_ge_s_imm", "regImmOffset"),
    (90, "branch_gt_s_imm", "regImmOffset"),
    (100, "move_reg", "twoReg"), (101, "count_set_bits_64", "twoReg"), (102, "count_set_bits_32", "twoReg"),
    (103, "leading_zero_bits_64", "twoReg"), (104, "leading_zero_bits_32", "twoReg"),
    (105, "trailing_zero_bits_64", "twoReg"), (106, "trailing_zero_bits_32", "twoReg"),
    (107, "sign_extend_8", "twoReg"), (108, "sign_extend_16", "twoReg"), (109, "zero_extend_16", "twoReg"),
    (110, "reverse_bytes", "twoReg"),
    (120, "store_ind_u8", "twoRegImm"), (121, "store_ind_u16", "twoRegImm"), (122, "store_ind_u32", "twoRegImm"),
    (123, "store_ind_u64", "twoRegImm"), (124, "load_ind_u8", "twoRegImm"), (125, "load_ind_i8", "twoRegImm"),
    (126, "load_ind_u16", "twoRegImm"), (127, "load_ind_i16", "twoRegImm"), (128, "load_ind_u32", "twoRegImm"),
    (129, "load_ind_i32", "twoRegImm"), (130, "load_ind_u64", "twoRegImm"), (131, "add_imm_32", "twoRegImm"),
    (132, "and_imm", "twoRegImm"), (133, "xor_imm", "twoRegImm"), (134, "or_imm", "twoRegImm"),
    (135, "mul_imm_32", "twoRegImm"), (136, "set_lt_u_imm", "twoRegImm"), (137, "set_lt_s_imm", "twoRegImm"),
    (138, "shlo_l_imm_32", "twoRegImm"), (139, "shlo_r_imm_32", "twoRegImm"), (140, "shar_r_imm_32", "twoRegImm"),
    (141, "neg_add_imm_32", "twoRegImm"), (142, "set_gt_u_imm", "twoRegImm"), (143, "set_gt_s_imm", "twoRegImm"),
    (144, "shlo_l_imm_alt_32", "twoRegImm"), (145, "shlo_r_imm_alt_32", "twoRegImm"),
    (146, "shar_r_imm_alt_32", "twoRegImm"), (147, "cmov_iz_imm", "twoRegImm"), (148, "cmov_nz_imm", "twoRegImm"),
    (149, "add_imm_64", "twoRegImm"), (150, "mul_imm_64", "twoRegImm"), (151, "shlo_l_imm_64", "twoRegImm"),
    (152, "shlo_r_imm_64", "twoRegImm"), (153, "shar_r_imm_64", "twoRegImm"), (154, "neg_add_imm_64", "twoRegImm"),
    (155, "shlo_l_imm_alt_64", "twoRegImm"), (156, "shlo_r_imm_alt_64", "twoRegImm"),
    (157, "shar_r_imm_alt_64", "twoRegImm"), (158, "rot_r_64_imm", "twoRegImm"), (159, "rot_r_64_imm_alt", "twoRegImm"),
    (160, "rot_r_32_imm", "twoRegImm"), (161, "rot_r_32_imm_alt", "twoRegImm"),
    (170, "branch_eq", "twoRegOffset"), (171, "branch_ne", "twoRegOffset"), (172, "branch_lt_u", "twoRegOffset"),
    (173, "branch_lt_s", "twoRegOffset"), (174, "branch_ge_u", "twoRegOffset"), (175, "branch_ge_s", "twoRegOffset"),
    (180, "load_imm_jump_ind", "twoRegTwoImm"),
    (190, "add_32", "threeReg"), (191, "sub_32", "threeReg"), (192, "mul_32", "threeReg"), (193, "div_u_32", "threeReg"),
    (194, "div_s_32", "threeReg"), (195, "rem_u_32", "threeReg"), (196, "rem_s_32", "threeReg"),
    (197, "shlo_l_32", "threeReg"), (198, "shlo_r_32", "threeReg"), (199, "shar_r_32", "threeReg"),
    (200, "add_64", "threeReg"), (201, "sub_64", "threeReg"), (202, "mul_64", "threeReg"), (203, "div_u_64", "threeReg"),
    (204, "div_s_64", "threeReg"), (205, "rem_u_64", "threeReg"), (206, "rem_s_64", "threeReg"),
    (207, "shlo_l_64", "threeReg"), (208, "shlo_r_64", "threeReg"), (209, "shar_r_64", "threeReg"),
    (210, "and", "threeReg"), (211, "xor", "threeReg"), (212, "or", "threeReg"), (213, "mul_upper_s_s", "threeReg"),
    (214, "mul_upper_u_u", "threeReg"), (215, "mul_upper_s_u", "threeReg"), (216, "set_lt_u", "threeReg"),
    (217, "set_lt_s", "threeReg"), (218, "cmov_iz", "threeReg"), (219, "cmov_nz", "threeReg"),
    (220, "rot_l_64", "threeReg"), (221, "rot_l_32", "threeReg"), (222, "rot_r_64", "threeReg"),
    (223, "rot_r_32", "threeReg"), (224, "and_inv", "threeReg"), (225, "or_inv", "threeReg"), (226, "xnor", "threeReg"),
    (227, "max", "threeReg"), (228, "max_u", "threeReg"), (229, "min", "threeReg"), (230, "min_u", "threeReg"),
]
OP = {name: code for code, name, _ in OPCODES}
FMT = {name: fmt for _, name, fmt in OPCODES}
BY_FMT = {}
for _c, _n, _f in OPCODES:
    BY_FMT.setdefault(_f, []).append(_n)
VALID = {code for code, _, _ in OPCODES}
# GP v0.8.0 T (terminators).
TERMINATORS = {0, 1, 40, 50, 80, 180, 170, 171, 174, 175, 172, 173, 81, 82, 83, 87, 84, 88, 85, 89, 86, 90}
HALT = 2**32 - 2**16
M64 = 2**64 - 1


def enc_nat(x):
    """E, the general natural-number serialization (GP Appendix C)."""
    if x == 0:
        return [0]
    for l in range(8):
        if 2 ** (7 * l) <= x < 2 ** (7 * (l + 1)):
            return [2**8 - 2 ** (8 - l) + x // 2 ** (8 * l)] + le(x % 2 ** (8 * l), l)
    return [255] + le(x, 8)


def le(x, n):
    return [(x >> (8 * i)) & 0xFF for i in range(n)]


def sext(n, x):
    x %= 2 ** (8 * n) if n else 1
    if n == 0:
        return 0
    return x + (x >> (8 * n - 1)) * (2**64 - 2 ** (8 * n))


def imm_bytes(v, n=None):
    """Shortest (or exactly `n`-octet) little-endian immediate whose sign extension is `v`."""
    v &= M64
    if n is not None:
        return le(v, n)
    for k in range(5):
        if sext(k, v) == v:
            return le(v, k)
    return le(v, 4)  # not representable: the low 4 octets (decodes to their sign extension)


def off_bytes(target, here, n=None):
    d = (target - here) % 2**32
    if n is not None:
        return le(d, n)
    for k in range(5):
        if (sext(k, d) - d) % 2**32 == 0 and sext(k, d) % 2**32 == d:
            return le(d, k)
    return le(d, 4)


# Instruction builders. Register operands are raw nibbles (0..15); offsets are absolute targets,
# resolved against the instruction's own index when the program is laid out.
def I(name, *args, lx=None, ly=None):
    return (name, args, lx, ly)


def encode(ins, here):
    if isinstance(ins, (bytes, list)):  # raw octets
        return list(ins)
    name, args, lx, ly = ins
    op = OP[name]
    f = FMT[name]
    if f == "noArgs":
        return [op]
    if f == "oneImm":
        return [op] + imm_bytes(args[0], lx)
    if f == "regExtImm":
        return [op, args[0]] + le(args[1] & M64, 8)
    if f == "twoImm":
        x = imm_bytes(args[0], lx)
        y = imm_bytes(args[1], ly)
        return [op, len(x)] + x + y
    if f == "oneOffset":
        return [op] + off_bytes(args[0], here, lx)
    if f == "regImm":
        return [op, args[0]] + imm_bytes(args[1], lx)
    if f == "regTwoImm":
        x = imm_bytes(args[1], lx)
        y = imm_bytes(args[2], ly)
        return [op, args[0] | (len(x) << 4)] + x + y
    if f == "regImmOffset":
        x = imm_bytes(args[1], lx)
        y = off_bytes(args[2], here, ly)
        return [op, args[0] | (len(x) << 4)] + x + y
    if f == "twoReg":
        return [op, args[0] | (args[1] << 4)]
    if f == "twoRegImm":
        return [op, args[0] | (args[1] << 4)] + imm_bytes(args[2], lx)
    if f == "twoRegOffset":
        return [op, args[0] | (args[1] << 4)] + off_bytes(args[2], here, lx)
    if f == "twoRegTwoImm":
        x = imm_bytes(args[2], lx)
        y = imm_bytes(args[3], ly)
        return [op, args[0] | (args[1] << 4), len(x)] + x + y
    if f == "threeReg":
        return [op, args[0] | (args[1] << 4), args[2]]
    raise ValueError(f)


def layout(instrs, labels=None):
    """Code octets, mask bits and the start index of each instruction. Offsets in branch/jump
    instructions may name labels (strings), resolved in a second pass (offset lengths are fixed
    at 4 octets for label references)."""
    labels = labels or {}
    # first pass with placeholder targets to fix sizes
    def resolve(ins, here, table):
        if isinstance(ins, tuple):
            name, args, lx, ly = ins
            f = FMT[name]
            if f in ("oneOffset", "regImmOffset", "twoRegOffset"):
                k = {"oneOffset": 0, "regImmOffset": 2, "twoRegOffset": 2}[f]
                t = args[k]
                if isinstance(t, str):
                    args = list(args)
                    args[k] = table.get(t, here)
                    if f == "oneOffset":
                        lx = 4
                    else:
                        ly = 4
                    return (name, tuple(args), lx, ly)
        return ins

    starts = []
    pos = 0
    for ins in instrs:
        starts.append(pos)
        pos += len(encode(resolve(ins, pos, {}), pos))
    table = {k: starts[v] if v < len(starts) else pos for k, v in labels.items()}
    code, mask = [], []
    for ins, s in zip(instrs, starts):
        b = encode(resolve(ins, s, table), s)
        code += b
        mask += [1] + [0] * (len(b) - 1)
    return code, mask, starts


def pack_mask(mask, length=None, pad=0):
    n = len(mask)
    nbytes = (n + 7) // 8 if length is None else length
    out = [0] * nbytes
    for i, b in enumerate(mask):
        if b and i // 8 < nbytes:
            out[i // 8] |= 1 << (i % 8)
    if pad and nbytes:
        out[-1] |= pad & 0xFF
    return out


def blob(code, mask, jump_table=(), z=None, jlen=None, clen=None, mask_bytes=None, raw_jt=None):
    jt = list(jump_table)
    if z is None:
        m = max(jt, default=0)
        z = 0 if not jt else next(k for k in range(1, 5) if m < 256**k)
        if not jt:
            z = 0
    jtb = raw_jt if raw_jt is not None else sum((le(e, z) for e in jt), [])
    out = enc_nat(len(jt) if jlen is None else jlen) + [z] + enc_nat(len(code) if clen is None else clen)
    out += jtb + list(code)
    out += pack_mask(mask) if mask_bytes is None else list(mask_bytes)
    return out


def program(instrs, jump_table=(), labels=None, **kw):
    code, mask, starts = layout(instrs, labels)
    return blob(code, mask, jump_table, **kw), starts


def testcase(name, prog, steps, pc=0, gas=10000):
    return {"name": name, "initial-pc": pc, "initial-gas": gas, "program": prog, "steps": steps,
            "block-gas-costs": []}


def setregs(regs):
    return [{"set-reg": {"reg": r, "value": v & M64}} for r, v in sorted(regs.items()) if v & M64]


def mapp(addr, length, w):
    return {"map": {"address": addr, "length": length, "is-writable": w}}


def write(addr, contents):
    return {"write": {"address": addr, "contents": list(contents)}}


RUN = {"run": {}}
