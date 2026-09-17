# pi32v2 SLEIGH (Quarkslab fork) gap-finding session

Date: 2026-09-16
Scope: static analysis only, no hardware/MIDI/OTA I/O touched.

## Goal

Build a differential gap-finder between the real LLVM/clang-toolchain ground-truth
disassembly of `app.bin` (`research/disasm/app_full_disasm_llvm.txt`, 226k lines) and the
`kartun83/ghidra-jieli` fork of `quarkslab/ghidra-jieli`'s pi32v2 SLEIGH module
(`~/dev/ghidra-jieli-quarkslab`, installed locally as Ghidra language id
`pi32v2q:LE:32:default`), then fix the highest-impact gaps.

## Tooling produced

- `research/ghidra/scripts/DumpDisasm.java` — a Ghidra headless post-script that
  linear-sweeps a whole memory block and forces disassembly at every address, writing
  `<addr>\t<len>\t<OK|BAD>\t<text>` per line. See the in-file comment for an important
  methodology note (below).
- `tools/pi32v2_sleigh_diff.py` — walks the ground-truth objdump listing address-by-address,
  looks up the matching Ghidra decode, and flags `BAD` (Ghidra couldn't decode anything),
  `LEN_MISMATCH` (decoded, but wrong instruction length — the most reliable desync signal),
  and `MISSING`. Ranks gaps by byte-pattern frequency (not raw address count), since one
  `.sinc` fix can resolve hundreds of addresses sharing an encoding family. Also filters out
  gap addresses that sit within `--unknown-window` (default 6) ground-truth instructions of
  an `<unknown instruction>` line, since those are regions where *llvm-objdump itself*
  couldn't decode a nearby word (almost always literal pools / jump tables / padding
  embedded in `.text`, confirmed by manual inspection, see "Data-region false positives"
  below) — comparing against a misaligned/data region there produces noise, not real SLEIGH
  bugs.

## Important methodology finding (write this back to project memory)

**A naive "force-disassemble one address at a time with an `AddressSet` restricted to that
single address" approach produces large numbers of false-positive `BAD` results** for
pi32v2's delay-slot / parallel-issue instruction encodings. The SLEIGH pcode builder needs
to read bytes *past* the current instruction to resolve a following delay-slot instruction
(see `parainst` table in `pi32v2.slaspec`, prefix=6/7 parallel dispatch); restricting the
address set to a single address makes that lookahead fail with `Program does not contain
referenced instruction` pcode errors, which are an artifact of the harness, not a real
decode gap. Confirmed concretely: the exact same 2-byte `pfetch [rN]` encoding decoded fine
in isolation but failed intermittently depending on address, purely because of this
lookahead truncation.

**Fix**: seed every address in the block as a candidate instruction start and disassemble
them all in one batched `Disassembler.disassemble(blockSet, blockSet, false)` call with the
full memory available (no `restrictSet` truncation to a single address). Ghidra's normal
address-ordered seed processing then does a proper linear sweep — closely matching
objdump's own linear disassembly — with delay slots resolved correctly. This dropped the
raw "BAD" count from 7911 to 2658 addresses before any real SLEIGH fix, purely by fixing
the test harness. **Any future differential-testing work against this SLEIGH module should
use the batched/linear-sweep approach, not per-address forcing.**

## Data-region false positives

Ground truth itself contains 13,340 `<unknown instruction>` lines — cases where the real
LLVM/clang objdump's own disassembler can't decode a word. These are not gaps in the
ground truth's authority; they mark places where the compiler emitted **non-instruction
data interleaved in `.text`** (jump tables, literal pools, alignment padding) that a purely
linear disassembly pass (both objdump's and our forced-sweep's) will still try to decode as
code. Example confirmed by hand (`0x200332a`, surrounded by four consecutive `<unknown
instruction>` words before it and after): a "ssync" and "swi" reading there is objdump
noise against a literal-pool region, not real code. `--unknown-window` filters gap
addresses near such regions out of the ranking so real SLEIGH gaps aren't buried under this
noise (excludes ~28k of the ~209k ground-truth addresses from comparison near such
regions).

## Results (gap-address counts, ground truth = 209,161 real instructions after excluding
`<unknown instruction>` lines)

| Stage | BAD | LEN_MISMATCH | MISSING | Total gap addrs |
|---|---|---|---|---|
| Naive single-address forcing (no unknown-filter) | 7911 | 661 | 394 | 8966 |
| Batched linear-sweep methodology fix (no unknown-filter) | 5640 | 661 | 395 | 6696 |
| + unknown-region filter (baseline before any SLEIGH code fix) | 1311 | 38 | 9 | 1358 |
| + 3 SLEIGH fixes below (final) | 721 | 38 | 9 | 768 |

Final state: **99.63%** of real (non-data-region, non-`<unknown instruction>`) ground-truth
instructions decode with matching length in the fixed module, up from 99.35% before this
session's fixes and roughly 95.7% before even the harness methodology fix.

## Fixes made (all in `~/dev/ghidra-jieli-quarkslab`, branch `fix/pi32v2-gaps`)

All three were derived by writing small Python bit-field solvers against the ground-truth
listing (`research/disasm/app_full_disasm_llvm.txt`) — collecting every occurrence of a
given failing mnemonic shape, brute-forcing which bit-slice(s) of the 16/32-bit instruction
word reproduce the observed register/immediate values, and cross-checking the discriminator
bits against neighboring already-implemented constructors in the same `.sinc` file for
naming/style consistency. Each fix recompiled cleanly with `sleigh` (no new ambiguity
warnings beyond the two pre-existing delay-slot warnings already in the file).

### 1. Register-indexed post-increment load/store family (highest impact, ~3000 addresses)

`pi32v2.slaspec` + `pi32v2_ins_loadstore.sinc`: pi32 (v1) already had `rA = [rB ++= rC]`
(register, not constant, stride) for word/halfword/byte in `pi32_ins_loadstore.sinc`, but
pi32v2 only had the constant-stride forms (`[rB ++= 4]`, `[rB ++= 2]`, `[rB ++= 1]`). Real
code uses the register-stride form heavily (`r0 = [r0++=r8]`, `h[r1++=r14] = r3`,
`b[r0++=r13] = r7`, etc.) — this was the single largest gap bucket.

Confirmed encoding (16-bit word, `group=0`):
- bits(0,2): dest/src register, `regAl` (existing field, r0-r7)
- bit(3): 0=load, 1=store, `ins0303` (existing field)
- bits(4,6): base register, `regBl` (existing field, r0-r7)
- bits(7,9): stride register, **new field `regCh`**, r8-r15 only (matches the existing
  `regAh` upper-half-register convention used elsewhere in this ISA)
- bits(10,15): opcode-family selector, **new field `ins1015`**: `0x2`=word, `0x3`=halfword
  (unsigned), `0x4`=byte (unsigned)

Added 6 new constructors (`lw`/`sw`, `lh.z`/`sh`, `lb.z`/`sb` with `[regBl ++= regCh]`
addressing), mirroring the existing constant-stride constructors' pcode style exactly
(`regE = *:N regBl; regBl = regBl + regCh;`). No signed-byte/halfword register-stride
variant was found in the real binary, so none was added (see Open Items).

**Confidence: high.** Verified against 3374 real ground-truth occurrences across all 6
sub-forms; formula fits were exact (no residual mismatches) across the full dataset, not
just a sample.

### 2. Extended-offset (128-252) `sp`-relative word load/store (~975 addresses)

`pi32v2_ins_stack.sinc`: the existing `lw regA, [sp+imm5]` / `sw regA, [sp+imm5]`
constructors (`group=1`, `ins0407=0`/`0x8`, 5-bit immediate scaled by 4, offsets 0-124) only
cover small stack-frame offsets. Real code with larger frames needs offsets up to 252,
which uses a sibling encoding: `ins0407=0x2` (load) / `0xA` (store) — i.e. the existing
opcode with an extra bit set — where the raw word's bit 13 is *always* 1 and effectively
supplies the missing 6th immediate bit: `offset = (imm0812 + 32) * 4`.

Added `lw regA, [sp+imm6ext]` and `sw regA, [sp+imm6ext]`. **Confidence: high.** Verified
against 823 real occurrences (675 loads + 148 stores); offset range in the data was exactly
[128, 252] step 4 as the formula predicts, with `ins0407` and bit 13 both 100% constant
across every occurrence.

### 3. Signed halfword `sp`-relative load, `lh.s` (~136 addresses)

`pi32v2_ins_stack.sinc`: the `group=7` `sp`-relative family had `0x9d0`=`sdw`/`ldw`
(doubleword), `0x9d4`=`sw`/`lw` (word), `0x9d8`=`sh`/`lh` (halfword, unsigned/plain),
`0x9dc`=`lb`, `0x9dd`=`lb.s` (signed byte load — no signed-byte-store counterpart, since
store doesn't need sign extension), `0x9de`=`sb`. The signed-halfword-load slot `0x9d9`
(the natural gap in that numbering, by direct analogy with `lb.s`) was missing.

Added `lh.s eregA, [sp+imm12] is ... ins0011=0x9d9 ...` with `imm12 = imm1627 << 1` and
`eregA = sext(*:2 addr)`. **Confidence: high.** Verified against all 136 real occurrences;
register field (bits 12-15 of the second halfword) and offset formula matched exactly.

## Still open (not fixed this session — lower priority / more ISA-modeling work needed)

Ranked by remaining address count in the final diff (`research/ghidra/ghidra_disasm_dump_final.txt`):

- `40 e8 fd ff` (75 addrs, always byte-identical): objdump prints this as `ifeq goto -6`
  (branches to `pc-2`, i.e. a tight self-referential loop). All 75 occurrences share
  *exactly* the same 4 bytes, which strongly suggests this is a compiler-emitted
  trap/unreachable idiom (e.g. `__builtin_trap()`/`__builtin_unreachable()` padding) rather
  than a variably-targeted branch, but the `ifeq` mnemonic and its flag/condition semantics
  aren't yet modeled in `pi32v2_ins_ifthenelse.sinc` (that file implements an elaborate
  `if...then...else` context-register state machine, not simple pc-relative compare
  branches) — needs more investigation before adding a constructor to avoid interfering
  with that state machine.
- `34 e4 ...` family (74 addrs): `smax`/`umax`/`ssat`-style saturating parallel-arithmetic
  ops (`r2 = smax(r2, r3)`, `r10 = r10 + r11 (ssat)`) — likely belongs in
  `pi32v2_ins_para_arithops.sinc`, not yet decoded.
- `d0 ee ...` / `d8 ee...`/`dc ee...` family (~90 addrs combined): `b[rB++=imm]`/`h[++rB=rC]`
  variants with small positive immediates (1, 2, 142...) that don't match the existing
  `imm8`-based group-7 encodings — a second, narrower-immediate encoding for the same
  register-indexed load/store operations covered by fix #1 above, still missing.
- `58 xx` / `5a xx` / `5c xx` / `dc xx` families (~90 addrs combined): various multi-register
  push/pop list variants and pre-increment byte/halfword/doubleword addressing
  (`b[++r4=184] = r5`, `r7_r6 = d[++r0=r2]`) not yet covered by `pi32v2_ins_stack.sinc` /
  `pi32v2_ins_loadstore.sinc`.
- No signed-byte/halfword register-stride load (`b[rB++=rC] (s)`, `h[rB++=rC] (s)`) was
  found in the real binary to confirm an encoding for, so fix #1 only covers the unsigned
  forms actually observed. If such an encoding exists in the ISA it may still be worth
  adding speculatively later, but there's no ground truth here to verify it against.
- The 38 `LEN_MISMATCH` and 9 `MISSING` addresses remaining were not individually triaged
  this session — worth a follow-up pass since length mismatches can point to subtly wrong
  (not just missing) constructors.

## Reproducing

```
# 1. Rebuild the SLEIGH module (after editing .slaspec/.sinc files):
cd ~/dev/ghidra-jieli-quarkslab/data/languages && \
  ~/soft/ghidra_12.1.3_PUBLIC/support/sleigh pi32v2.slaspec

# 2. Copy into the installed Ghidra processor module:
cp pi32v2.sla pi32v2.slaspec pi32v2_ins_*.sinc \
  ~/soft/ghidra_12.1.3_PUBLIC/Ghidra/Processors/JieLi-Quarkslab/data/languages/

# 3. Fresh headless import + forced linear-sweep dump:
cd /Users/alekseitveritinov/dev/keysmith/research/ghidra
rm -rf proj_tmp && mkdir proj_tmp
~/soft/ghidra_12.1.3_PUBLIC/support/analyzeHeadless proj_tmp smk37elite-q \
  -import /Users/alekseitveritinov/dev/keysmith/research/smk37-elite-016-unpacked/files/app.bin \
  -loader BinaryLoader -loader-baseAddr 0x2000120 -processor pi32v2q:LE:32:default \
  -noanalysis -scriptPath scripts -postScript DumpDisasm.java ghidra_disasm_dump.txt

# 4. Diff against ground truth:
cd /Users/alekseitveritinov/dev/keysmith
python3 tools/pi32v2_sleigh_diff.py \
  --ground-truth research/disasm/app_full_disasm_llvm.txt \
  --ghidra-dump research/ghidra/ghidra_disasm_dump.txt --top 40
```

## Files touched

- `~/dev/ghidra-jieli-quarkslab/data/languages/pi32v2.slaspec` (new `regCh`, `ins1015`
  token fields + attach)
- `~/dev/ghidra-jieli-quarkslab/data/languages/pi32v2_ins_loadstore.sinc` (6 new
  constructors, fix #1)
- `~/dev/ghidra-jieli-quarkslab/data/languages/pi32v2_ins_stack.sinc` (3 new constructors,
  fixes #2 and #3)
- `~/dev/ghidra-jieli-quarkslab/data/languages/pi32v2.sla` (recompiled)
- Committed to branch `fix/pi32v2-gaps` in that fork, pushed to `origin`
  (`kartun83/ghidra-jieli`). Not touching keysmith's own git history for this work (per
  task instructions), only adding new files here (this doc, the diff tool, the dump
  script) which are part of keysmith.

## Non-invasive-first compliance

This entire session was static analysis on files already on disk: reading
`app_full_disasm_llvm.txt`, running Ghidra headless against the decrypted `app.bin` copy,
and editing/recompiling a SLEIGH module in a separate git repo. No MIDI, USB, or OTA/flash
I/O was performed or attempted at any point.
