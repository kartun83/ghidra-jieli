#!/usr/bin/env python3
"""
Differential gap-finder between the real LLVM/clang ground-truth objdump
disassembly of app.bin and a Ghidra pi32v2q (Quarkslab SLEIGH module) forced
linear-decode dump.

Ground truth format (research/disasm/app_full_disasm_llvm.txt), one insn/line:
    ' 2000120:    04 81             \tgoto 2 <.text+0x4 : 2000124 >\n'
Continuation lines (rep-block bodies, closing braces) have extra leading tabs
in the mnemonic column but the same "<addr>:  <bytes>" prefix; lines with no
address (just spaces before the tab) are pure formatting continuations and are
skipped.

Ghidra dump format (research/ghidra/ghidra_disasm_dump.txt), one line per
decoded (or failed) address, produced by research/ghidra/scripts/DumpDisasm.java:
    '02000120\t2\tFORCED\tgoto 0x02000124\n'
    '02003c3c\t1\tBAD\tbad-instruction\n'

This script walks every ground-truth address, looks up the corresponding
Ghidra decode at the same address, and flags:
  - BAD:  Ghidra could not decode anything at that address at all.
  - LEN_MISMATCH: Ghidra decoded *something* but at a different length than
    the real instruction -- the most reliable desync signal, since it means
    subsequent addresses would decode against the wrong byte alignment.

Ground-truth lines with "<unknown instruction>" (a real limitation of the
LLVM-side objdump table, not a byte-count-bearing instruction) are skipped --
we have no ground truth to compare against there.

Output: a ranked list (by encoding-pattern frequency, not raw address count)
of the byte patterns most responsible for gaps, plus per-address detail.
"""
import argparse
import re
import sys
from collections import Counter, defaultdict

GT_LINE_RE = re.compile(r'^ ([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*\t(\t*)(.*)$')
# "<unknown instruction>" lines have NO leading tab before the text (unlike
# every other objdump line, which separates bytes from mnemonic with a tab) --
# they need a separate pattern.
GT_UNKNOWN_RE = re.compile(r'^ ([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*<unknown instruction>\s*$')
GHIDRA_LINE_RE = re.compile(r'^([0-9a-f]{8})\t(\d+)\t(OK|FORCED|BAD)\t(.*)$')


def parse_ground_truth(path):
    """Returns dict: addr(int) -> (length_bytes:int, byte_hex:str, mnemonic:str)"""
    gt = {}
    order = []
    with open(path, 'r', errors='replace') as f:
        for line in f:
            m = GT_LINE_RE.match(line)
            if m:
                addr = int(m.group(1), 16)
                byte_str = m.group(2).strip()
                nbytes = len(byte_str.split())
                mnem = m.group(4).strip()
                gt[addr] = (nbytes, byte_str, mnem)
                order.append(addr)
                continue
            mu = GT_UNKNOWN_RE.match(line)
            if mu:
                addr = int(mu.group(1), 16)
                byte_str = mu.group(2).strip()
                nbytes = len(byte_str.split())
                gt[addr] = (nbytes, byte_str, '<unknown instruction>')
                order.append(addr)
    return gt, order


def compute_unknown_proximity(gt, order, window=6):
    """For each address in `order`, returns True if it is within `window`
    ground-truth instructions (either direction) of an
    '<unknown instruction>' line. objdump itself only hits that on data /
    misaligned regions (e.g. jump tables, literal pools) mixed into .text --
    real code that both toolchains can align on doesn't produce it. Gaps found
    near such addresses are much more likely to be artifacts of comparing
    against misdecoded data than genuine SLEIGH module bugs.
    """
    n = len(order)
    is_unknown = [gt[a][2] == '<unknown instruction>' for a in order]
    near = [False] * n
    last_unknown = -10**9
    for i in range(n):
        if is_unknown[i]:
            last_unknown = i
        if i - last_unknown <= window:
            near[i] = True
    next_unknown = 10**9
    for i in range(n - 1, -1, -1):
        if is_unknown[i]:
            next_unknown = i
        if next_unknown - i <= window:
            near[i] = True
    return {order[i]: near[i] for i in range(n)}


def parse_ghidra_dump(path):
    """Returns dict: addr(int) -> (length:int, status:str, text:str)"""
    gh = {}
    with open(path, 'r', errors='replace') as f:
        for line in f:
            m = GHIDRA_LINE_RE.match(line)
            if not m:
                continue
            addr = int(m.group(1), 16)
            length = int(m.group(2))
            status = m.group(3)
            text = m.group(4).strip()
            gh[addr] = (length, status, text)
    return gh


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--ground-truth', required=True,
                     help='path to the real-toolchain objdump ground truth '
                          '(e.g. <target-project>/research/disasm/app_full_disasm_llvm.txt)')
    ap.add_argument('--ghidra-dump', required=True,
                     help='path to the Ghidra DumpDisasm.java output '
                          '(e.g. <target-project>/research/ghidra/ghidra_disasm_dump.txt)')
    ap.add_argument('--top', type=int, default=30, help='how many top gap patterns to print')
    ap.add_argument('--detail-addr', type=lambda x: int(x, 16), default=None,
                     help='dump full context for one specific gap address (hex)')
    ap.add_argument('--unknown-window', type=int, default=6,
                     help='exclude gap addresses within this many ground-truth '
                          'instructions of an "<unknown instruction>" line (data/'
                          'misaligned-region proxy). 0 disables filtering.')
    args = ap.parse_args()

    gt, order = parse_ground_truth(args.ground_truth)
    gh = parse_ghidra_dump(args.ghidra_dump)
    near_unknown = compute_unknown_proximity(gt, order, args.unknown_window) if args.unknown_window > 0 else {}

    print(f"Ground truth: {len(gt)} addressed instructions", file=sys.stderr)
    print(f"Ghidra dump:  {len(gh)} addressed decode records", file=sys.stderr)

    total_compared = 0
    skipped_unknown = 0
    n_missing_in_gh = 0
    n_bad = 0
    n_len_mismatch = 0
    n_ok = 0
    n_excluded_near_unknown = 0

    # pattern -> count of *addresses* affected (for ranking)
    pattern_addr_count = Counter()
    # pattern -> list of (addr, gt_mnem, gh_status, gh_text)
    pattern_examples = defaultdict(list)
    # first two bytes (opcode byte(s)) -> count, coarser bucket for ranking
    opcode_addr_count = Counter()
    opcode_examples = defaultdict(list)

    gap_addrs = []

    for addr in order:
        nbytes, byte_str, mnem = gt[addr]
        if mnem == '<unknown instruction>':
            skipped_unknown += 1
            continue
        total_compared += 1
        if near_unknown.get(addr):
            n_excluded_near_unknown += 1
            continue
        rec = gh.get(addr)
        if rec is None:
            n_missing_in_gh += 1
            gap_addrs.append(addr)
            pattern_addr_count[byte_str] += 1
            pattern_examples[byte_str].append((addr, mnem, 'MISSING', ''))
            opcode_addr_count[byte_str.split()[0]] += 1
            opcode_examples[byte_str.split()[0]].append((addr, mnem, 'MISSING', ''))
            continue
        length, status, text = rec
        if status == 'BAD':
            n_bad += 1
            gap_addrs.append(addr)
            pattern_addr_count[byte_str] += 1
            pattern_examples[byte_str].append((addr, mnem, status, text))
            opcode_addr_count[byte_str.split()[0]] += 1
            opcode_examples[byte_str.split()[0]].append((addr, mnem, status, text))
        elif length != nbytes:
            n_len_mismatch += 1
            gap_addrs.append(addr)
            pattern_addr_count[byte_str] += 1
            pattern_examples[byte_str].append((addr, mnem, status, text))
            opcode_addr_count[byte_str.split()[0]] += 1
            opcode_examples[byte_str.split()[0]].append((addr, mnem, status, text))
        else:
            n_ok += 1

    print(f"\n=== Summary ===")
    print(f"Ground-truth instructions total:      {len(gt)}")
    print(f"  skipped (<unknown instruction>):    {skipped_unknown}")
    print(f"  compared:                           {total_compared}")
    print(f"    OK (same length, present):        {n_ok}")
    print(f"    BAD (ghidra decode failure):      {n_bad}")
    print(f"    LEN_MISMATCH:                     {n_len_mismatch}")
    print(f"    MISSING (no ghidra record at all):{n_missing_in_gh}")
    print(f"  excluded (near <unknown instr>):    {n_excluded_near_unknown}")
    print(f"  total gap addresses:                {len(gap_addrs)}")

    print(f"\n=== Top {args.top} gap byte-encodings ranked by address-frequency ===")
    print(f"{'byte pattern':<20} {'#addrs':>7}  example gt mnemonic -> ghidra status")
    for pattern, count in pattern_addr_count.most_common(args.top):
        examples = pattern_examples[pattern]
        addr0, mnem0, status0, text0 = examples[0]
        print(f"{pattern:<20} {count:>7}  0x{addr0:08x}: {mnem0!r} -> {status0} {text0!r}")

    print(f"\n=== Top {min(args.top,15)} gap FIRST-BYTE opcode buckets (coarser) ===")
    for opcode, count in opcode_addr_count.most_common(min(args.top, 15)):
        examples = opcode_examples[opcode]
        addr0, mnem0, status0, text0 = examples[0]
        print(f"first-byte 0x{opcode:<4} {count:>7} addrs  e.g. 0x{addr0:08x}: {mnem0!r} -> {status0} {text0!r}")

    if args.detail_addr is not None:
        addr = args.detail_addr
        print(f"\n=== Detail for 0x{addr:08x} ===")
        if addr in gt:
            print("ground truth:", gt[addr])
        if addr in gh:
            print("ghidra:      ", gh[addr])
        print("context (ground truth, +/- 5 instrs):")
        near = sorted(a for a in order if abs(a - addr) < 40)
        for a in near:
            marker = ' <=== ' if a == addr else ''
            ghrec = gh.get(a)
            print(f"  0x{a:08x} gt={gt[a]!r} gh={ghrec!r}{marker}")


if __name__ == '__main__':
    main()
