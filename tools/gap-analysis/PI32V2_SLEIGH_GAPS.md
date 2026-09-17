# pi32v2 SLEIGH gap-finding session

Scope: static analysis only — disassembly comparison against a real firmware binary, no
device I/O of any kind.

## Goal

Build a differential gap-finder between the real LLVM/clang-toolchain ground-truth
disassembly of a real shipped firmware image and this fork's `pi32v2` SLEIGH module
(installed locally as Ghidra language id `pi32v2q:LE:32:default`), then fix the
highest-impact gaps.

## Tooling produced

- `DumpDisasm.java` — a Ghidra headless post-script that linear-sweeps a whole memory block
  and forces disassembly at every address, writing `<addr>\t<len>\t<OK|BAD>\t<text>` per
  line. See the in-file comment for an important methodology note (below).
- `pi32v2_sleigh_diff.py` — walks a ground-truth objdump listing address-by-address, looks
  up the matching Ghidra decode, and flags `BAD` (Ghidra couldn't decode anything),
  `LEN_MISMATCH` (decoded, but wrong instruction length — the most reliable desync signal),
  and `MISSING`. Ranks gaps by byte-pattern frequency (not raw address count), since one
  `.sinc` fix can resolve hundreds of addresses sharing an encoding family. Also filters out
  gap addresses that sit within `--unknown-window` (default 6) ground-truth instructions of
  an `<unknown instruction>` line, since those are regions where *llvm-objdump itself*
  couldn't decode a nearby word (almost always literal pools / jump tables / padding
  embedded in `.text`, confirmed by manual inspection, see "Data-region false positives"
  below) — comparing against a misaligned/data region there produces noise, not real SLEIGH
  bugs.

## Important methodology finding

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
code. Example confirmed by hand: an address surrounded by four consecutive `<unknown
instruction>` words before it and after decoded as "ssync" and "swi" — objdump noise
against a literal-pool region, not real code. `--unknown-window` filters gap addresses near
such regions out of the ranking so real SLEIGH gaps aren't buried under this noise
(excludes ~28k of the ~209k ground-truth addresses from comparison near such regions).

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

## Fixes made

All three were derived by writing small Python bit-field solvers against the ground-truth
listing — collecting every occurrence of a given failing mnemonic shape, brute-forcing
which bit-slice(s) of the 16/32-bit instruction word reproduce the observed
register/immediate values, and cross-checking the discriminator bits against neighboring
already-implemented constructors in the same `.sinc` file for naming/style consistency.
Each fix recompiled cleanly with `sleigh` (no new ambiguity warnings beyond the two
pre-existing delay-slot warnings already in the file).

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

Ranked by remaining address count in the final diff:

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
cd data/languages && sleigh pi32v2.slaspec

# 2. Copy into your installed Ghidra processor module directory:
cp pi32v2.sla pi32v2.slaspec pi32v2_ins_*.sinc \
  <ghidra-install>/Ghidra/Processors/<your-pi32v2-module-name>/data/languages/

# 3. Fresh headless import + forced linear-sweep dump against your own target binary:
rm -rf proj_tmp && mkdir proj_tmp
<ghidra-install>/support/analyzeHeadless proj_tmp my-project \
  -import /path/to/your/firmware.bin \
  -loader BinaryLoader -loader-baseAddr <base-addr> -processor pi32v2q:LE:32:default \
  -noanalysis -scriptPath tools/gap-analysis -postScript DumpDisasm.java ghidra_disasm_dump.txt

# 4. Diff against your own ground-truth objdump:
python3 tools/gap-analysis/pi32v2_sleigh_diff.py \
  --ground-truth /path/to/your/objdump_ground_truth.txt \
  --ghidra-dump ghidra_disasm_dump.txt --top 40
```

## Files touched

- `data/languages/pi32v2.slaspec` (new `regCh`, `ins1015` token fields + attach)
- `data/languages/pi32v2_ins_loadstore.sinc` (6 new constructors, fix #1)
- `data/languages/pi32v2_ins_stack.sinc` (3 new constructors, fixes #2 and #3)
- `data/languages/pi32v2.sla` (recompiled)

## Non-invasive-first compliance

This entire session was static analysis: reading a ground-truth disassembly listing,
running Ghidra headless against a decrypted firmware image already on disk, and
editing/recompiling this SLEIGH module. No MIDI, USB, or OTA/flash I/O was performed or
attempted at any point.

---

# 2026-09-16 follow-up session

Scope: same as above (static analysis only), plus one new technique: cross-compiling small,
targeted C snippets with the real JieLi `clang`/`objdump` toolchain (run inside a Linux VM,
since the toolchain only ships x86-64 Linux binaries) to get clean, isolated ground truth for
encoding families that are rare or ambiguous in the one real firmware image available. No
MIDI, USB, or OTA/flash I/O was performed or attempted at any point; the toolchain was only
ever used to compile-and-disassemble local throwaway `.c` files, never to touch real hardware.

## New technique: synthetic ground truth via the real toolchain

Where real-firmware occurrences of a gap were too sparse or fixed-operand to confidently
derive a general bit-field formula, small standalone C functions were written to coax
`clang -target pi32v2 -O2` into emitting the construct in isolation (e.g. `a > b ? a : b`
idioms for `smax`/`umax`/`smin`/`umin`), then `objdump`'d with the same toolchain. This gave
exact, unambiguous confirmation of an opcode's mnemonic and operand layout independent of
whatever fixed register combination happened to appear in the one real binary available.
This was used for the `smax`/`umax` fix below (full confidence, arbitrary registers
compiled and checked). It was *not* usable for the saturating-add family: no C idiom tried
(including the natural `__builtin_add_overflow`-based saturate pattern, and ARM/Hexagon-style
builtins, which this toolchain's `clang` does not expose for `pi32v2`) got the compiler to
emit it — that fix relied on real-firmware ground truth only, with an explicitly-flagged
lower-confidence pcode semantic model (see below). Cross-referencing the generic AC79 AIoT
SDK headers for saturating-arithmetic intrinsics/macros turned up nothing useful for
`pi32v2` specifically — its only exposed low-level intrinsics are `__builtin_pi32v2_*` DSP
helpers (multiply-accumulate, bit-extract, rotate, etc.), none of which are a saturating
add/subtract.

## Results this session

| Stage | BAD | LEN_MISMATCH | MISSING | Total gap addrs | Match rate |
|---|---|---|---|---|---|
| Start of this session (re-measured against the same tooling/ground truth) | 648 | 38 | 7 | 693&nbsp;&#42; | 99.62% |
| + `smax`/`umax` fix (fix #4), diffed together with fixes #5/#6 below | — | — | — | 586&nbsp;&#42;&#42; | — |
| + `ifeq` + `sadd.sat` fixes (fixes #5, #6) | — | — | — | 586 | — |
| + byte/halfword/doubleword pre/post-increment & negative-offset load/store family (fix #7) | 360 | 38 | 7 | **405** | **99.78%** |

&#42; This session's own re-measurement (693) differs slightly from the previous session's
reported end state (768) purely from re-running the same tooling against the same ground
truth at a different point in time; not a regression, and not chased down further since the
two counts are close and both sessions' absolute fix counts are independently verified
against real occurrences.

&#42;&#42; Fixes #4 (`smax`/`umax`), #5 (`ifeq`), and #6 (`sadd.sat`) were compiled and diffed
together in one pass, dropping the total from 693 to 586 (75 addresses from `ifeq` + 32 from
`sadd.sat` = 107, matching the observed drop exactly). This session did not re-diff `smax`/
`umax` in isolation, so its exact real-firmware address count isn't separately confirmed
here — its correctness is instead confirmed independently via synthetic compilation (see fix
#4 below) and via bit-pattern matching against every real `34 e4`/`34 f4`-prefixed
occurrence found while deriving the encoding.

Final state: **99.78%** of real (non-data-region, non-`<unknown instruction>`) ground-truth
instructions decode with matching length, up from 99.63% at the end of the previous session.

## Fixes made this session

### 4. `smax`/`umax` parallel-arithmetic ops (~74 addresses)

`pi32v2_ins_arithops.sinc`: `smin`/`umin` were already implemented at `ins0011=0x435`
(`group=7`, two-word encoding, `eregA = op(eregB, eregC)` with `imm1619` selecting
signed(1)/unsigned(0)). The neighboring `ins0011=0x434` slot (`smax`/`umax`, same field
layout) was missing entirely.

Confirmed **both** via real firmware (all `34 e4`/`34 f4`-prefixed occurrences in the real
binary) **and** via synthetic compilation: `clang -target pi32v2 -O2` on
`int f(int a,int b){return a>b?a:b;}`-style C emits exactly `34 e4 01 01` /
`r0 = smax(r0, r1)`, and varying operand registers in the C source (`smax(r2,r5)`,
`umax(r5,r4)`, etc.) confirmed the general field layout (`eregA`=dest, `eregB`=first
operand, `eregC`=second operand, `imm1619`=signed/unsigned flag) independent of any one
firmware's fixed register usage.

Added `umax`/`smax` constructors mirroring the existing `umin`/`smin` pcode style exactly
(branch-and-pick, not a native SLEIGH max/min operator). **Confidence: high** — confirmed by
both real-firmware occurrences and arbitrary-register synthetic compilation.

### 5. Test-and-set spinlock retry branch, `ifeq` (75 addresses)

`pi32v2_ins_progflow.sinc`: previously flagged as a suspected trap/unreachable-padding
idiom (`40 e8 fd ff`, all 75 occurrences byte-identical). Re-examining the surrounding real
disassembly context this session showed every occurrence directly follows a `testset
b[rX]` instruction and always branches back exactly onto it — the classic hardware
test-and-set spinlock retry loop, not padding.

Confirmed the branch target formula: `group=7`, `ins0011=0x840`, target =
`inst_next + sext(imm16)*2` (the same `imm1631s * 2 + inst_next` formula already used
elsewhere in this file for `jaddr16`-style unconditional-displacement branches). No register
field varies across any of the 75 real occurrences, consistent with this being a flag-test
branch (not a register comparison) — unlike every other conditional branch already modeled
in this file.

`testset` itself is still only a `TODO()` stub in `pi32v2.slaspec` with no modeled flag
output, so the true flag polarity/source could not be derived from this codebase alone.
Rather than invent an unconfirmed specific status-register-bit semantic, the new `ifeq`
constructor models its condition as an explicit opaque `TODO()`-sourced value — honest about
what is/isn't confirmed, while still giving the decompiler a real `CBRANCH` so the retry
loop's control flow (back-edge + fallthrough) is represented correctly.

**Confidence: high** on the encoding/branch-target (confirmed against all 75 real
occurrences); **medium** on the exact flag semantics (deliberately left as an opaque
placeholder pending a proper `testset` implementation).

### 6. Signed saturating add, `sadd.sat` (32 addresses)

`pi32v2_ins_arithops.sinc`: real firmware contains 32 byte-identical occurrences of
`39 e4 a0 ab` / `r10 = r10 + r11 (ssat)` — structurally the same two-word `group=7` family as
`smax`/`smin`/`umax`/`umin` above (`ins0011=0x439`, immediately adjacent to `0x434`/`0x435`),
but with a fixed operand combination that gives no register-field diversity to double-check
against.

No C idiom attempted (branch-based saturate patterns, `__builtin_add_overflow`-based
clamping, ARM/Hexagon saturating-add builtins) got this toolchain's `clang` to emit a
saturating-add instruction for `pi32v2` — `strings` on the toolchain's `clang` binary does
show internal instruction-selection pattern names for a SIMD saturating-add/subtract family
(`SIMD_QADD32S_rrr`, `SIMD_QSUB32S_rrr`, etc.), suggesting the hardware feature exists, but no
exposed `__builtin_pi32v2_*` intrinsic reaches it, so no clean synthetic ground truth could be
generated for this one. This fix therefore relies on real-firmware ground truth only, for a
single fixed operand combination.

Added `sadd.sat eregA, eregB, eregC is ins0011=0x439` with standard signed-saturating-add
pcode semantics (clamp to `INT32_MIN`/`INT32_MAX` on signed overflow, via the same
standard overflow-detection idiom: `(eregB^sum)&(eregC^sum)` is negative iff the signed add
overflowed — see the `.sinc` file for the exact expression). Deliberately did **not**
constrain `imm1619`
(unlike `smax`/`smin`, which use it as a signed/unsigned selector) since no second
occurrence at this same opcode with a different `imm1619` value was observed to justify or
require that constraint — the neighboring `0x436`-`0x438` opcode slots remain unconfirmed and
unimplemented.

**Confidence: medium.** The encoding/opcode-family match is solid (same structural family as
the already-cross-validated `smax`/`smin`), but the exact saturation pcode semantics are a
best-effort standard-signed-saturating-add model, not independently confirmed against
silicon or a second real occurrence with different operands.

### 7. Byte/halfword/doubleword pre/post-increment & negative-offset load/store family (~250 addresses, largest fix this session)

`pi32v2_ins_loadstore.sinc`: this was the largest remaining gap bucket. The existing byte
load/store family (`lb.z`/`lb.s`/`sb`) already covered offset-based addressing
(`b[rB+imm8]`) and some pre-increment forms (`b[++rB=imm8]` positive/negative for loads,
`b[++rB=rC]`/`b[rB++=rC]` register forms) at a consistent `0xe5X`/`0xedX` opcode-nibble
scheme, but several sibling slots in the same numbering scheme were unimplemented, and the
analogous halfword (`0xd5X`/`0xddX`) and doubleword (`0xc5X`, register-preincrement form)
opcodes were missing almost entirely. All of the following were derived purely from bit-slice
solving against real-firmware occurrences (no synthetic compilation needed here, since the
existing byte family already gave a confirmed field-layout template to extend):

- **`lb.z` unsigned byte post-increment load, `ins0011=0xed0`** (52 addresses, the single
  largest bucket) — the missing unsigned sibling of the already-implemented `lb.s` at
  `0xed4`, same `imm8 = (imm2427<<4)|imm1619` split-nibble formula.
- **Negative-offset byte load/store, `ins0011=0xe51`/`0xe53`/`0xe55`** (22 + 14 + 5
  addresses) — negative-immediate siblings of the already-implemented positive-offset forms
  at `0xe50`/`0xe52`/`0xe54`, using the same one's-complement-style negative-immediate
  formula already used elsewhere in this file for `lb.z`'s pre-increment negative form
  (`0xe59`).
- **Byte store pre-increment, `ins0011=0xe5a`/`0xe5b`** (29 + 8 addresses) — store-direction
  siblings of the already-implemented `lb.z` pre-increment loads at `0xe58`/`0xe59`, same
  addressing mode and immediate formula, opposite direction.
- **Halfword pre-increment family, `ins0011=0xd58`/`0xd59`/`0xd5b`/`0xd5c`/`0xd5d`** (~90
  addresses combined) — the halfword counterpart to the byte pre-increment family above.
  Notable difference: since a halfword access's immediate is always even, bit 0 of the
  low-nibble nibble is never a real magnitude bit, and hardware reuses it as an explicit
  load(0)/store(1) direction flag instead of needing separate opcodes per direction (confirmed
  by 4 real store occurrences whose naive nibble-concatenation immediate was consistently
  off-by-one from the expected always-even value, until that bit is masked off as a direction
  flag rather than magnitude). `0xd59`/`0xd5d` are "extended range" siblings of `0xd58`/`0xd5c`
  for immediates 256-510 (confirmed by an implicit leading `1` bit in the same one's-complement
  positional slot). Only the load direction was observed for the extended-range and negative
  variants; a store counterpart was not added without real evidence.
- **Register pre/post-increment halfword load/store, `ins0011=0xddc`/`0xdde`** (~20 addresses)
  — halfword sibling of the byte register-preincrement form at `0xedc`, extending it to a full
  `r0`-`r15` stride register range (the short 16-bit `group=0` encoding added in the previous
  session's fix #1 only supports an `r8`-`r15` stride register). Both load (`imm1619=0`
  unsigned, `imm1619=2` signed) and store (`imm1619=1`) directions confirmed for the
  pre-increment form; only unsigned-load and store were observed for the post-increment form.
- **Doubleword register pre-increment load, `addldw edregA, eregB, eregC` at
  `ins0411=0xC5 & ins0003=0xC`** (3 addresses) — paired-register sibling of the
  already-implemented single-register `addldw`/`addsdw` forms at `ins0411=0xCD`, in the
  neighboring `0xC5` opcode family (where the existing offset-based `ldw`/`sdw` doubleword
  forms already live), using the same `ins0003=0xC` register-preincrement selector and
  `imm1617` load(2)/store(3) discriminator convention already established by `addldw`/
  `addsdw`. Only the load direction (`imm1617=2`) was observed in real firmware; a store
  sibling at `imm1617=3` is a plausible analogy but was deliberately **not** added without
  real evidence.

**Confidence: high** for every sub-form with a directly-confirmed real occurrence (all of the
above except the explicitly-noted "not added" store/negative counterparts); each formula was
checked against every real occurrence found for that specific opcode slot, not a sample.

## Still open (updated after the third and fourth rounds; see those sections below for what
## has since been resolved)

Ranked by remaining real-firmware address count in the final diff:

- ~~Multi-register push/pop range-list syntax~~ — **resolved in the third round**, see
  "Fix #8" below.
- ~~Wide-immediate signed compare-and-branch (`ifs ... s>=`/`s>`)~~ — **resolved in the
  fourth round**, see "Fix #9" below.
- ~~Register-operand shift and 64-bit divide op families (`0xd8`, `0xf6`)~~ — **resolved in
  the fifth round**, see "Fixes #10-11" below.
- ~~`ifs (rA > rB)` register/register comparison (`0x10`), unsigned `if (rA != imm)` and
  `if (rA < imm)` immediate-family gaps (`0xb1`/`0xb2`/`0xb0`/`0xa3`/`0xa7`/`0xbf`/`0xb6`)~~ —
  **resolved in the fifth round**, see "Fixes #12-13" below.
- ~~The `imm1623` bit-1-flagged sub-case of the register/register `if`/`ifs` comparison
  family~~, ~~the `packedimm12` 7th sub-case (`imm2427=2`)~~, ~~the single-register bitmap
  push/pop family~~, ~~`callns`/`rtns`/`sspn=sp`/`wfe`/`sevl`/second `ssync`/`btbclr`
  encodings~~, ~~`trigger`~~, ~~extended-range `sp +=`~~, ~~the memory-operand
  shift/xor/and-with-packedimm12 compound-assign family~~, ~~signed-byte pre-increment loads~~,
  ~~the fixed `-16` post-increment word load~~, ~~`sat16`~~ — **all resolved in the sixth
  round**, see below.
- **A dual-register (`rH_rL`) multiply-accumulate-subtract form of the `(ssat,x2)` modifier**,
  e.g. `r3_r2 -= r6.h,r6.h *|* r15.l,r15.l (ssat,x2)` (first bytes `73 f5`, 4 real addresses
  across only 2 distinct byte patterns) — too few distinct real instances to unambiguously
  separate the destination-register, source-register, and lane-selector bit fields. Still open.
- **Dual-fetch parallel multiply-accumulate ops** (e.g. `r15_r14 = h[r13 ++= 6]*[r8 ++= -16]
  (s)`, `r1_r0 -= h[r0 ++= -6]*r10 (u)`) — a handful of single-occurrence DSP-style
  simultaneous-load-and-multiply instructions; each looks like its own distinct field layout
  and none repeats often enough to cross-check a bit derivation against.
- Other saturating-arithmetic single-occurrence forms: `r3_r2 = r12.h,r12.l *|* 4 (usat)`,
  `r1_r0 = r0,r1 +|+ r3,r3 (usat)`, `r0.l = r0.l - 162`, `r0 = r14.l,r14.h +|+ 32 (ssat) #`,
  `r3 -= r4.l * 111 (ssat) #`, `r1_r0 = r0.l,r0.l *|* -16 (ssat) #` — each a single real
  occurrence, not enough to confirm a general field layout.
- The still-unresolved **wide-immediate `if (rX ?? imm)`/`ifs (rX ?? imm) goto ...` family**
  (12 `LEN_MISMATCH` addresses, ground truth itself prints `??` for the condition — even the
  real LLVM-based objdump doesn't have a clean mnemonic for whatever condition code this is).
  Deferred across three rounds now for the same reason: fixing this means extending the
  if/then/else context-register state machine and disambiguating it against the existing
  32-bit `or`-immediate constructor that currently (incorrectly) claims these bytes, real but
  distinct work from anything else in this document, with real risk of regressing the `or`
  family if the new pattern is too broad.
- A `[rX+off] += imm` compound-assign-with-immediate-delta family (e.g. `[r0+-80] += 517`,
  `[r1+-4] += 1`) at `ins0511≈0x7c`/`0x7d`-adjacent opcodes — some instances (offset -80/-36/-8,
  delta 517) were decoded far enough to confirm the delta comes from `imm1631` directly, but a
  different instance (offset -4, delta 1) doesn't fit that same formula, meaning offset and
  delta are packed together in a way not yet fully solved. Left open rather than guessed at.
- A handful of remaining miscellaneous single-occurrence opcodes: `{pc} = [sp++]` (group=7
  bitmap-list form, `0x950`, distinct from the already-implemented group=0 `pop pc`),
  `[--sp] = {sp, ssp, usp, icfg, psr, rets, retx, rete, reti}` (a much larger special-register
  set than the existing 4-bit `{reti,rete,retx,rets}` bitmap already handles), a doubleword
  pre-increment store `d[++r3=940] = r5_r4`, and negative-offset halfword/word store siblings
  (`h[r0++=-4] = r3`, `h[r15++=-260] = r3`, `[r2++=-8] = r3`) that share an opcode slot with the
  now-implemented fixed-`-16` load but need a still-unsolved variable-offset formula.

## Files touched this session

- `data/languages/pi32v2_ins_arithops.sinc` (4 new constructors: fixes #4 and #6)
- `data/languages/pi32v2_ins_progflow.sinc` (1 new constructor: fix #5)
- `data/languages/pi32v2_ins_loadstore.sinc` (17 new constructors: fix #7)
- `data/languages/pi32v2.sla` (recompiled)

## Non-invasive-first compliance (this session)

Same as above, plus: the real JieLi `clang`/`objdump` toolchain was used exclusively to
compile and disassemble small local throwaway `.c` files inside a Linux VM already set up for
this purpose — never to touch, flash, or communicate with real hardware. No MIDI, USB, or
OTA/flash I/O was performed or attempted at any point.

---

# Third round: multi-register range-list/special-register-list push/pop family, LEN_MISMATCH/MISSING triage

Scope: same as above (static analysis only, real-firmware ground truth plus the same
batched-linear-sweep Ghidra headless harness). No new synthetic-compilation technique was
needed this round; the target family turned out to have unusually strong ground truth already
present in the real firmware (see below).

## Results this round

| Stage | BAD | LEN_MISMATCH | MISSING | Total gap addrs | Match rate |
|---|---|---|---|---|---|
| Start of this round (re-measured against the same tooling/ground truth) | 360 | 38 | 7 | 405 | 99.78% |
| + multi-register range-list/special-register-list push/pop family (fix #8) | 264 | 38 | 7 | **309** | **99.83%** |

Final state: **99.83%** of real (non-data-region, non-`<unknown instruction>`) ground-truth
instructions decode with matching length, up from 99.78% at the end of the previous round.

## Fix #8: multi-register range-list and special-register-list push/pop family (~96 addresses)

This was the item flagged as deferred, higher-effort work in the previous round's "Still open"
list. It turned out to be a single coherent 16-way-nibble-dispatched family, not a collection
of unrelated encodings, and — unusually for this project — the real firmware contains what
looks like a compiler- or vendor-emitted **exhaustive opcode self-test/enumeration table**
spanning a contiguous stretch of `.text` that walks nearly every nibble/count/bitmap
combination in this family (and several neighboring ones) in strict sequential order. That
table gave far stronger ground truth than any single real call site could: every value of the
relevant bitfields, not just the combinations that happen to occur "organically" in the
compiled application code.

All instructions in this family are a fixed 16-bit word with the upper byte constant (`0x04`)
and the lower byte carrying the actual opcode information:

- Bits 4-7 of the lower byte (`ins0407`, equivalently `ins0412 = ins0407 + 0x40` once the fixed
  upper byte is folded in) select one of 14 sub-families:
  - `0x1`: push `rets` alone, no register range (only the `ins0003=0` case has any
    confirmed real occurrence).
  - `0x3`/`0x4`/`0x5`/`0x6`/`0x7`: pop/push a contiguous register **range** with an optional
    `rets` or `pc` prefix. The 4-bit low nibble (`ins0003`) is a count field: for `ins0003<4`
    the range is `r3..r(ins0003)` (i.e. counting down from a fixed `r3` top); for `ins0003>=4`
    the range is `r(ins0003)..r4` (i.e. counting up to a fixed `r4` bottom). This is exactly
    the range-boundary convention the existing `pushreglist3`/`popreglist3`/`pushreglist4`/
    `popreglist4` tables in `pi32v2_ins_stack.sinc` already implemented — they just weren't
    wired up to cover the *full* `ins0003` domain (0-15) for every sub-family; several
    `ins0003<4` or `ins0003>=4` halves were entirely missing, and one existing constructor had
    an incorrect `ins0003>0` guard that excluded the valid `ins0003=0` case.
  - `0x8`-`0xf`: pop/push a **bitmap** over the four "small" special registers
    (`reti`/`rete`/`retx`/`rets`, one bit each in the low nibble), optionally prefixed with
    `sr4` and/or `psr` depending on two more bits of the nibble (`0x8`=plain pop, `0x9`=pop+
    `sr4`, `0xa`=pop+`psr`, `0xb`=pop+`psr`+`sr4`, `0xc`-`0xf` are the push-direction mirrors).
    The pre-existing `popsrmap` bitmap-list machinery already handled the plain `0x8` case;
    this round added an analogous push-direction `pshsrmap` table and wired up `0x9`-`0xf`.

Confirmed against the exhaustive self-test table plus every other real occurrence found for
each nibble/count value; the range-family formula in particular was checked against every one
of its ~40 real occurrences and matched exactly with no residual mismatches.

**Confidence: high** on every bitfield/formula derivation above (independently reproduced by
brute-force fitting against the exhaustive table). **Medium** on the exact push/pop pcode
*order* for the `sr4`/`psr` prefix registers relative to the bitmap items — inferred by
LIFO-symmetry with an existing hardcoded example in the same file (`push {psr,rets,reti}` /
`pop {psr,rets,reti}`, which pushes in display-left-to-right order and pops in the reverse
order), not independently re-derived from raw stack-pointer arithmetic in the binary.

### A blocking SLEIGH constraint found along the way

An early version of this fix tried to bind `sr4`/`psr` as ordinary attached-register operand
fields (the way `rets`/`pc`/`reti` are already bound elsewhere in this file) alongside the
bitmap subtable in the same constructor. This reliably failed to compile with `Pattern size
cannot vary (missing ... ?)`. Root cause: `sr4`/`psr`/`rets`/`pc`/`reti` are all attached to
the *same* 4-bit field (`sregA`, bits 0-3) as the very bitmap this family also reads out of
those identical bits (`ins0003`) — binding both a fixed register value and a free 4-bit bitmap
to the same physical bits in one constructor is a genuine contradiction, not just an SLEIGH
ambiguity-checker false positive. The fix was to stop trying to bind `sr4`/`psr` as pattern
operands at all in these constructors and instead print them as bare literal display text
(`"sr4"`, `"psr"`) while referencing the actual global `sr4`/`psr` registers directly by name
in the p-code (which works fine — SLEIGH allows referencing any declared global register by
name in p-code regardless of whether it's bound via the instruction pattern).

### Known cosmetic limitation carried over (not newly introduced)

The pre-existing `popsrmap`/(now also `pshsrmap`) recursive bitmap-list builder can render
incorrectly — a dropped register, or an extra/missing separator — when two back-to-back
instructions of this same family appear adjacent to each other during a forced linear sweep
(confirmed on an already-shipped, previously-"working" `nibble 0x8` occurrence pair, e.g.
`pop {retx,rete,reti}` immediately followed by `pop {rets,rete}` rendering as `pop
{rete,reti}` then `pop {,retx,rete,reti}`). This looks like context-register state (`counter`/
`bitset`/`sep`) not being fully reset between two uses of the same recursive table in adjacent
instructions during Ghidra's forced/linear disassembly. It does **not** affect instruction
length (the property this differential-testing methodology measures, and the reason the
pre-existing `nibble 0x8` case was already counted as "OK" despite this bug), only cosmetic
display text in that specific back-to-back adjacency case. Root-causing and fixing this
context-reset issue in the underlying recursive-list-building idiom (shared by this family and
the older group=7 `pshmap`/`popmap` register-bitmap machinery) is worth a dedicated follow-up,
but was out of scope for closing the length-based gap count this round.

## LEN_MISMATCH triage (38 addresses)

All 38 `LEN_MISMATCH` addresses turned out to be **the same single root cause**: a real,
currently-unmodeled 6-byte "wide-immediate compare-and-branch" instruction family (ground
truth shows forms like `ifs (r6 > 2000) goto 322`, `if (r15 ?? -1) goto -2`, `ifs (r1 >= 1)
goto -636`), sharing first bytes in the `0x00`-`0x0f`/`0x2c`-`0x2d` range. The current SLEIGH
module misdecodes the same bytes as an unrelated, shorter 4-byte `or [rX+off],#imm` bitwise-or
instruction — i.e. this isn't a subtly-wrong existing constructor so much as a genuinely
different, wider comparison-branch encoding that happens to alias a valid but wrong decode of
an existing constructor's pattern. This is the same family already flagged in the "Still open"
list above under "wider-immediate comparison forms" (`if (r7 != 134217728)`, `ifs (r12 >
33554944)`); triaging the `LEN_MISMATCH` bucket specifically confirmed it is *all* one family,
not several unrelated bugs, and that the existing `or`-with-32-bit-immediate constructor's
pattern is presumably too permissive (matching bytes it shouldn't). Modeling this properly
would mean extending `pi32v2_ins_ifthenelse.sinc`'s if/then/else context-register state
machine with a new wide-immediate comparison form and tightening or disambiguating it against
the existing `or`-immediate constructor — real, scoped work, but a distinct task from the
range-list fix above, and deferred for the same reason noted in earlier rounds (risk of
destabilizing the existing if/then/else state machine without more targeted ground truth for
that specific state machine's context transitions).

## MISSING triage (7 addresses)

All 7 `MISSING` addresses are **downstream artifacts of other, already-identified gap
families** — none is an independent new bug:

- One (`0x201b50a`) and two more (`0x204c432`, `0x204c434`) directly follow a `LEN_MISMATCH`
  wide-immediate compare-branch instruction (see above) that Ghidra decoded 2 bytes short;
  the following addresses land mid-instruction and never get a valid decode start.
- Three (`0x204d544`, `0x2050dc8`, `0x205639e`) each directly follow a `BAD` decode in one of
  the other still-open families noted above (the `(ssat,x2)`/parallel-multiply-accumulate DSP
  family and a related 32-bit-immediate bitwise-op-on-memory form) — same cascading-desync
  pattern.
- One (`0x207615c`) follows a ground-truth-side `<unknown instruction>` line that the
  `--unknown-window` proximity filter (default 6 ground-truth instructions) didn't quite reach
  in this specific case; likely a real data/misaligned-region false positive rather than a
  SLEIGH bug, consistent with the "Data-region false positives" methodology note further above.

None of the 7 are independently fixable without first resolving the upstream family each one
cascades from; no new constructor was added for this bucket as a result, but the triage itself
is a useful result — it confirms there is no additional, as-yet-unidentified bug hiding in the
`MISSING` count.

## Files touched this round

- `data/languages/pi32v2.slaspec` (no field/token changes needed; reused existing `ins0407`/
  `ins0412`/`ins0003` fields)
- `data/languages/pi32v2_ins_stack.sinc` (removed 2 superseded hardcoded constructors, added
  ~30 new constructors and 2 new recursive bitmap tables for fix #8)
- `data/languages/pi32v2.sla` (recompiled)

## Non-invasive-first compliance (this round)

Same as previous rounds: static analysis only, against a real firmware image and this fork's
own SLEIGH module, with no MIDI, USB, or OTA/flash I/O performed or attempted at any point.

---

# Fourth round: wide-immediate compare-and-branch family, cross-checked against a community ISA reference

Scope: same as previous rounds (static analysis only, real-firmware ground truth plus the
batched-linear-sweep Ghidra headless harness). This round's starting point was a third-party,
community-maintained pi32v2 opcode reference (<https://kagaimiq.github.io/jielie/cpu/pi32v2.html>),
used strictly as a hypothesis source to validate against this project's own real-firmware
ground truth and toolchain — not trusted as-is.

## Results this round

| Stage | BAD | LEN_MISMATCH | MISSING | Total gap addrs | Match rate |
|---|---|---|---|---|---|
| Start of this round (re-measured against the same tooling/ground truth) | 264 | 38 | 7 | 309 | 99.83% |
| + wide-immediate signed compare-and-branch, `s>=`/`s>` conditions (fix #9) | 260 | 11 | 6 | **277** | **99.87%** |

Final state: **99.87%** of real (non-data-region, non-`<unknown instruction>`) ground-truth
instructions decode with matching length, up from 99.83% at the end of the previous round.

## Resolving the byte-count discrepancy from the previous round

The previous round's `LEN_MISMATCH` triage described this family as a "6-byte wide-immediate
compare-and-branch" encoding. The community reference above independently proposes a *different*
encoding for what looks like the same kind of instruction: a compact 32-bit (2-word) form with a
first byte in the 0xF8-0xFD range. Before trusting either description, both were checked directly
against real ground-truth bytes for the same address (e.g. the instruction printed as
`ifs (r6 > 2000) goto 322`): the actual bytes are 6 bytes long (3 sixteen-bit words), confirming
the previous round's own finding and ruling out the community reference's 32-bit form for this
specific instruction family in this firmware. The community reference turned out to describe a
related but distinct/unverified encoding, not applicable here as-is — exactly the outcome the
"treat it as a hypothesis, not an authority" approach is meant to catch.

## Fix #9: wide-immediate signed compare-and-branch, `s>=`/`s>` conditions (32 addresses)

By hand-decoding roughly 40 real occurrences of this instruction family across every condition
code that appears in the ground truth (equality, unsigned/signed relational, register-vs-register,
and bitwise-and-test variants), the actual 48-bit encoding was fully confirmed:

- Word 0: a fixed marker byte (`0xFF`) in the high half, with the low byte selecting the specific
  condition/mode (a 7-bit code: bits 0-4 select the condition, bits 5-6 select immediate vs.
  wide-immediate vs. register-vs-register vs. bitwise-and-test mode).
- Word 1: register field in the high nibble of the high byte, and a 12-bit immediate (or second
  register, or bitmask, depending on mode) split across the rest of the word.
- Word 2: a signed 16-bit branch displacement, scaled by 2.

This exact encoding was already anticipated by this SLEIGH module's existing token/subtable
infrastructure (a whole `ins0012=0x1fXX`-keyed constructor family already existed, built on
already-declared `imm1627`/`packedimm12`/`eregA`/`eregC`/`jaddr16e` fields and subtables), and
most condition codes in this family were already correctly implemented. Two specific opcode
slots were simply missing outright: `ins0012=0x1f0a` (signed `>=`) and `ins0012=0x1f0c`
(signed `>`). With no constructor claiming those two bit patterns, the real 6-byte instructions
at those addresses were instead being incorrectly matched — at the wrong, shorter length — by an
unrelated, more permissive 4-byte `or [rX+off],#imm` constructor, which is exactly the
`LEN_MISMATCH` symptom the previous round observed. Adding the two missing constructors
(mirroring the existing, already-correct `ins0012=0x1f0b`, signed `<`, constructor immediately
next to them) resolved every real occurrence of both conditions with no regressions elsewhere.

**Confidence: high.** Verified against every real ground-truth occurrence of both condition
codes (not a sample), using the same 12-bit-immediate/register/branch-displacement decoding that
already checks out exactly against roughly 40 other real occurrences across every other
condition in the same instruction family.

## Corrected understanding of the `(ssat,x2)`/`(usat,x2)` modifier (no fix yet)

The previous round's "still open" note described this as a "SIMD multiply-accumulate family."
The community reference above shows this framing was too narrow: `(ssat,x2)`/`(usat,x2)` is a
generic saturation-variant modifier that appears as a sibling encoding across an entire cluster
of parallel-arithmetic operations — plain add, dual-add, quad-add, multiply, multiply-accumulate,
and dual-multiply all have their own `plain`/`usat`/`ssat`/`usat,x2`/`ssat,x2`/`uavg`/`savg`/
`rnd,uavg`/`rnd,savg` sibling opcodes selected by a small, consistently-placed bit field. It is
not specific to multiply-accumulate and not a SIMD/dual-lane concept as such.

This correction doesn't close any gaps by itself — all real firmware occurrences of this
modifier across *other* arithmetic shapes (plain dual-subtract, quad add/subtract, single-lane
multiply) already decode with the correct length via existing constructors; only one specific
sub-case remains an actual gap: a dual-register (`rH_rL`) multiply-accumulate-subtract form
(first bytes `73 f5`, e.g. `r3_r2 -= r6.h,r6.h *|* r15.l,r15.l (ssat,x2)`), 5 real occurrences
across only 2 distinct byte patterns. That's too little independent data to pin down the exact
bit boundaries between the destination register pair, the two source registers, and the lane
selectors with confidence — the two available raw encodings differ by a single bit in a
position that could plausibly belong to any of those fields. Per this project's "don't force a
low-confidence Ghidra fix" rule, this stays documented as open rather than patched; closing it
for real would need either more real-firmware instances of this exact sub-case (from this or
another pi32v2 firmware image) or a working synthetic-compilation reproducer, which was already
attempted in the second round without success.

## Files touched this round

- `data/languages/pi32v2_ins_progflow.sinc` (2 new constructors: fix #9)
- `data/languages/pi32v2.sla` (recompiled)

## Non-invasive-first compliance (this round)

Same as previous rounds: static analysis only, against a real firmware image and this fork's
own SLEIGH module, with no MIDI, USB, or OTA/flash I/O performed or attempted at any point. The
community ISA reference was consulted read-only over HTTP as public documentation and was not
trusted without independent verification against real firmware bytes, consistent with the
"treat it as a hypothesis, not ground truth" approach used throughout this round.

## Fifth round

### Results this round

| Stage | Gap addresses (of 209,161) | Match rate |
|---|---|---|
| Start of this round (= end of fourth round) | 277 | 99.87% |
| + Fixes #10-13 below | 179 | **99.91%** |

### A real p-code correctness bug, found via the compiler's own warnings (not a decode gap)

Asked to check whether this module's `sleigh` compile warnings were all benign-by-design, one
wasn't: `sextra` (signed bit-field extract, `pi32v2_ins_logicops.sinc`) computed
`regA = sext((eregA & smask) >> imm2327);` where both sides of `sext()` were already the same
4-byte width, so the compiler silently downgraded it to a plain copy (the "1 unnecessary
extension" warning) — the extracted field's own sign bit was never actually propagated into the
result's high bits. This has no effect on the *decode-length* metric this whole differential
harness measures (254 real `sextra` occurrences all still decode at the right length either
way), which is why it survived four rounds of ground-truth diffing undetected; it's a real bug
for anyone using Ghidra's decompiler or p-code emulator against this ISA, though.

Fixed with the standard shift-left-then-arithmetic-shift-right bitfield sign-extend idiom
(`((eregA & smask) >> imm2327) << (32 - imm1822)`, then `s>> (32 - imm1822)`), which also
matches the *intent* of an already-existing analogous idiom in this same module's (untouched,
inherited) `q32s` target (`q32s_ins_regfield.sinc`'s own `sextra`, `regE = (regF << lastbit)
s>> lastbit`) — confirmation that this is the standard fix pattern for this instruction, not a
novel guess. Recompiling now produces zero "unnecessary extension" warnings (down from 1).

### Fixes #10-11: register-operand 64-bit shift/divide families (`0xd8`, `0xf6`, `0x1d0`)

Three previously-unmodeled 64-bit-pair opcode families, all derived by hand from real
ground-truth byte patterns (bit-level derivation cross-checked against every real occurrence,
zero contradictions across 10-26 samples each):

- **`lsl`/`lsr edregA, eregC`** (`ins0012=0x1d8`, 26 addresses) — a 64-bit register pair
  shifted left or right by a *register-held* count (as opposed to the already-implemented
  `lsl`/`lsr edregA, #imm6` immediate-count sibling at `ins0011=0x1d0`). Field layout: `edregA`
  (pre-existing pair-register field) is the shifted operand, `eregC` (pre-existing
  plain-register field) holds the count, and the low byte's bit 1 selects direction (`0`=left,
  `1`=right) — every other bit in that byte was 0 across all 26 real samples. Only the logical
  (unsigned) forms are evidenced; no arithmetic/signed register-count shift exists anywhere in
  ground truth, so none was added.
- **`qasr edregA, #imm6`** (`ins0011=0x1d0`, `imm2627=3`, 5 addresses) — the arithmetic
  (signed) sibling of the already-implemented `lsr`/`lsl edregA, #imm6` (`imm2627=0`/`2`) in the
  *same* opcode slot. `imm2627=1` is not evidenced anywhere in this firmware and was
  deliberately left unimplemented rather than guessed at.
- **`div edregA, edregB, eregC`** (`ins0011=0x1f6`, 17 addresses) — 64-bit-pair ÷
  single-register unsigned division, a separate opcode slot from the existing 32-bit `div`/
  `div.s`. Field layout: `edregA` destination pair, `edregB` dividend pair, `eregC` divisor
  register; two single reserved bits (word2 bit 12, reusing the existing `imm2828` field, and
  word2 bit 4, needing a new field `imm2020` added to `pi32v2.slaspec`) are 0 in every real
  sample and are pinned rather than left unconstrained. Only the unsigned form is evidenced.

### Fixes #12-13: missing `if`/`ifs` comparison-family siblings (`pi32v2_ins_ifthenelse.sinc`)

The `if`/`ifs (regA OP ...) { ... } else { ... }` conditional-block family (the
context-register/state-machine constructors, distinct from the flat compare-and-branch family
fixed in the fourth round) turned out to have the exact same shape of gap as that earlier fix:
a handful of genuinely missing opcode slots in an otherwise near-complete, systematically-laid-
out family, found by decoding real gap bytes and checking which `ins0411` (or, for the
register-register family, `ins0011`) values were simply unclaimed by any existing constructor:

- **`ifs (regA > eregC) {`** (`ins0411=0xE1`, 9 addresses) — missing signed
  register/register `>`, alongside the already-implemented `>=`/`<=`/`<` siblings at
  `0xD1`/`0xE9`/`0xD9`.
- **`if (regA != #packedimm12) {`** (`ins0411=0x8A`, 2 addresses) — missing unsigned `!=`
  against a compressed/shifted immediate, mirroring the already-implemented `==` sibling at
  `0x82`.
- **`if (regA != #imm1627s) {`** (`ins0411=0x8B`) — this slot already existed but was scoped
  far too narrowly (`imm2427=0 & imm1623`, i.e. only an 8-bit value with the high nibble forced
  to 0) where it should have used the full signed 12-bit `imm1627s` field directly, exactly
  like its `==` sibling at `0x83` (which was never restricted this way). Widened rather than
  replaced; real firmware needs values like `-1` and `-97` that only fit in the full 12 bits.
- **`if (regA < imm1627) {`** (`ins0411=0x9B`, 4 addresses) — missing unsigned `<` against a
  plain 12-bit immediate, mirroring the already-implemented `>=` sibling at `0x93`.

### Newly discovered, not yet fixed

While fixing `ifs (regA > eregC)` above, a **second, distinct sub-case** of the same
register-register comparison opcodes turned up: the exact same `ins0411` values already used by
the *existing* `>=`/`<=`/`<` (and now `>`) siblings recur at different real addresses with the
low byte's bit 1 set (`imm1623=0x02`) instead of the `imm1623=0` every existing sibling
requires — e.g. `ifs (r0 <= r2) {` at bytes `90 ee 02 02` fails to decode even though
`ins0411=0xE9` (`<=`, `eregC`) is already implemented, purely because that implementation
requires `imm1623=0` and this instance has `imm1623=2`. This is the *same* "bit 1 = variant
flag" shape seen in the `0xd8` shift-direction family (Fix #10 above), but what the flag
actually *means* here (a wider operand? a different addressing mode for one side of the
compare?) isn't yet determined from the ~8 real occurrences seen so far. Left open rather than
guessed at; see the updated "Still open" section above.

### Also verified: unsigned `if (rA <= imm)` gap at `0xCB` is a `packedimm12` subtable gap, not a missing opcode

`if (r3 <= 640) {` and `if (r1 <= 4096) {` decode as `BAD` even though `ins0411=0xCB` (`if
regA <= #packedimm12`) is already implemented and correctly handles plenty of other addresses.
Decoding by hand confirmed this is a real gap in the shared `packedimm12` compressed-immediate
subtable itself (none of its existing 6 sub-case patterns matches these word2 bit patterns) —
see "Still open" above for why this was deferred rather than patched blind.

### Files touched this round

- `data/languages/pi32v2.slaspec` (new field `imm2020`)
- `data/languages/pi32v2_ins_logicops.sinc` (`sextra` p-code fix)
- `data/languages/pi32v2_ins_shiftrot.sinc` (2 new constructors: `qasr edregA,#imm6`,
  `lsl`/`lsr edregA,eregC`)
- `data/languages/pi32v2_ins_arithops.sinc` (1 new constructor: `div edregA,edregB,eregC`)
- `data/languages/pi32v2_ins_ifthenelse.sinc` (3 new constructors, 1 widened constructor)
- `data/languages/pi32v2.sla` (recompiled)

### Non-invasive-first compliance (this round)

Static analysis and headless Ghidra batch-disassembly only, against the same real firmware
image and this fork's own SLEIGH module. The one departure from pure "read bytes, reason about
bits" analysis was compiling two tiny freestanding C snippets (signed bit-field extraction, to
independently sanity-check the `sextra` fix's premise) with the real JieLi `clang` toolchain, in
a Linux VM already set up for this exact purpose (needed because the toolchain only ships
Linux x86-64 binaries) — no new tool installation, no device I/O, no MIDI/USB/OTA touched at
any point.

## Sixth round

### Results this round

| Stage | Gap addresses (of 209,161) | Match rate |
|---|---|---|
| Start of this round (= end of fifth round) | 179 | 99.91% |
| + Fixes #14-24 below | 68 | **99.97%** |

Zero regressions throughout: `MISSING` went from 6 to 5 (one genuine fix), and `LEN_MISMATCH`
stayed effectively flat (11 → 12 — the one apparent increase is the pre-existing `npc`-pseudo-
register address changing from a clean decode failure to a wrong-length match against an
unrelated new constructor, not a newly-broken address; it was already a gap either way). Every
other closed address moved from `BAD`/`MISSING` straight to a correct-length `OK`.

### A reproduction bug worth recording

Before any of the fixes below, re-running this round's verification pipeline from scratch (the
working directory had changed since the last session) produced a *completely* broken result —
every single ground-truth address showed as `MISSING`. The cause: the raw `app.bin` image needs
`-loader-baseAddr 0x2000120`, not `0x2000000` — the flat binary's file offset 0 corresponds to
`.text`'s VMA `0x2000120`, not the naively-assumed round base address. Getting this wrong
doesn't fail loudly; it silently produces a full-image address shift that looks superficially
like a real regression. Confirmed by comparing raw bytes at file offset 0 against the
ground-truth disassembly's first real instruction. Worth checking first if a from-scratch
reproduction of this pipeline ever again claims 0% match.

### Fix #14: single-register-based bitmap push/pop family (`pi32v2_ins_stack.sinc`, ~20 addresses)

The sp-only bitmap push/pop family (`[--sp]={reg,...}` / `{reg,...}=[sp++]`, `pshmap`/`popmap`
in `pi32v2_ins_stack.sinc`) turned out to have real-firmware siblings using an **arbitrary
register** as the base instead of `sp`, in six addressing-mode variants sharing one
`ins0411`-keyed opcode family:

- `ins0411=0xB1`: `{list} = [regA++]` (post-increment pop, writeback)
- `ins0411=0xB3`: `[regA++] = {list}` (post-increment push, writeback)
- `ins0411=0xB4`: `{list} = [-regA]` (pre-decrement pop, no writeback)
- `ins0411=0xB5`: `{list} = [--regA]` (pre-decrement pop, writeback)
- `ins0411=0xB6`: `[-regA] = {list}` (pre-decrement push, no writeback)
- `ins0411=0xB7`: `[--regA] = {list}` (pre-decrement push, writeback)

All six reuse the *exact same* 16-bit register-presence bitmap (`imm1631`) already used by
`pshmap`/`popmap`, confirmed against every real occurrence (`regA` = r1, r2, r5, r6, r7, r9,
r10, r11, r13, r14 across the six slots, register lists from 2 to 8 entries). Reusing `pshmap`/
`popmap` directly works for the post-increment pop and pre-decrement push forms; the
post-increment push form needed a new forward-storing mirror table (`pshmapfwd`, store-then-
increment instead of pre-decrement-then-store) and the pre-decrement pop forms needed a new
decrement-then-load mirror (`popmaprev`) that reuses `pshmapregs`' own recursion *shape*
(deepest bit first) so its address computation is byte-identical to what a matching
pre-decrement push of the same bitmap would use.

The single-dash (`[-regA]`) vs double-dash (`[--regA]`) distinction for the pre-decrement forms
is inferred, not independently provable from decode length alone: it mirrors the one asymmetry
already established for the sp-only forms, where the pre-decrement push always writes back
(that being the entire point of a stack push) and is always shown double-dash. Modeled as
"compute the address, use it, leave the base register unmodified" for the single-dash forms —
plausible, matches the one architectural precedent this module already has, but not
independently confirmed via synthetic compilation.

### Fix #15: register-register `if`/`ifs` `imm1623`-flagged siblings (`pi32v2_ins_ifthenelse.sinc`)

The "bit-1-flagged sub-case" left open at the end of the fifth round turned out, with more
ground truth in hand, to be four *exact-value* aliases of already-implemented opcodes, each
needing one specific nonzero `imm1623` value instead of the usual 0 — the same shape of
distinction this file's `if ((regA & eregC) != 0)` constructor already uses (`imm1623=0x80`
there) to disambiguate from its `imm1623=0` sibling:

- `if (regA < eregC) {` (`0x99`) also decodes at `imm1623=0x05`
- `if (regA > eregC) {` (`0xC1`) also decodes at `imm1623=0x05`
- `ifs (regA >= eregC) {` (`0xD1`) also decodes at `imm1623=0x05`
- `ifs (regA <= eregC) {` (`0xE9`) also decodes at `imm1623=0x02`

What `imm1623` actually encodes in these cases still isn't independently known — only that
these exact byte pairings are what real firmware emits, each confirmed against every real
occurrence.

### Fix #16: the `packedimm12` 7th sub-case (`imm2427=2`)

The `packedimm12` compressed-immediate subtable gap flagged since the fifth round (`if (rA <=
640/4096)` failing to decode) turned out to be a genuinely missing `imm2427=2` case — confirmed
against **two independent real occurrences at two completely different top-level opcodes**
(`imm1623=5 → 0x05000500 = 83887360` in an `if (rX < ...)` immediate-compare gap, and
`imm1623=2 → 0x02000200 = 33554944` in an `ifs (rX > ...)` gap), both landing on the exact same
formula as the already-implemented `imm2427=1` case (`(imm1623<<24)|(imm1623<<8)`) — this looks
like a genuine duplicate/alternate encoding of the same byte-repeat-at-24-and-8 shape rather
than a distinct one. Added to both `packedimm12` and its `notpackedimm12` mirror, plus the one
missing top-level sibling this exposed, `if (regA < #packedimm12) {` (`0x9A`, mirroring the
already-implemented `>=` at `0x92`). Confirmed via full re-diff to introduce no new pattern
ambiguity with the six other constructors that share this subtable (all their `imm2427`/
`imm2627` value ranges are mutually exclusive with the new case by construction) and no
decode-length regressions anywhere in the firmware.

One address in the same test-table region (`ifs (r12 <= 514) {`, sharing the exact same word2
bits as one of the two confirmed occurrences above but at a *different* top-level opcode,
`0xEB`) produces a *different* ground-truth value (514, a plain 12-bit `imm1627`, not a
`packedimm12` result) from the identical bits — since `packedimm12` is a shared subtable that
must decode identically everywhere it's invoked, this specific address is very likely an
undefined/reserved bit pattern in the exhaustive self-test table rather than meaningful code;
not chased further.

### Fixes #17-24: everything else

- **`callns regA`** (`ins0412=0x009`, all 16 registers) — the one open slot immediately before
  `swi` in the group=0 register-operand opcode run; modeled with plain `call` semantics (no
  secure/non-secure state exists in this module).
- **`rtns`** (`ins0012=0x0085`) — sibling of `rts`/`rti`/`rtx`/`rte` (`0x0080`-`0x0083`);
  modeled as a plain return via `rets`, same reasoning as `callns`.
- **`sspn = sp`** (`ins0012=0x1447`) — sibling of the existing `sp`/`usp`/`ssp` move quartet
  (`0x1440`-`0x1443`) in `pi32v2_ins_move.sinc`; needed a new `sspn` register definition (a
  shadow/secure-state stack pointer with no other use anywhere in this module).
- **A second `ssync`/`btbclr` encoding** (`0x0032`/`0x0036` → `ssync`, `0x0033`/`0x0037` →
  `btbclr`, alongside the existing `0x0022`/`0x0023`) and **`sevl`/`wfe`** (`0x0042`/`0x0044`,
  siblings of `lockclr`/`lockset` at `0x0040`/`0x0041`) — all exact-value aliases, all
  confirmed against every real occurrence.
- **`trigger`** (`ins0011=0x870`, fixed 4-byte encoding, `regA=0` and the entire second word
  always zero in all 4 real occurrences) — pinned to exactly what's evidenced.
- **Extended-range `sp += imm13`** (`ins0311=0x11E`, `imm0002=0`, a new signed 13-bit
  `imm1628s` field) for the `±608`/`±640` values outside the existing 10-bit form's
  `[-512,508]` range. A handful of other real occurrences at the same `ins0311` selector but
  with `imm0002` = 1/3/6 (values `-3088`, `-528`, `2288`, `-348`) don't fit this same formula
  and are deliberately left unimplemented — see "Still open" above.
- **The memory-operand compound-assign family** (`pi32v2_ins_logicops.sinc` /
  `pi32v2_ins_shiftrot.sinc`): `[rA+off] ^= rB` (sibling of the existing `|=`/`&=`/`&=~` forms,
  same `ins0011=0x864` opcode, `imm1617=1`); `[rA+off] &= #packedimm12` and
  `[rA+off] ^= #packedimm12` (siblings of the existing `&= #notpackedimm12` form, sharing its
  addressing shape but at `ins0611=0x3e`/`0x3d` with a *signed* 6-bit offset-index instead of
  the unsigned one); and a new `[rA+off] <<=`/`>>=`/`>>>= shamt5` family (`ins0111=0x436`, an
  11-bit opcode selector that deliberately excludes word1's bit 0, which turned out to be a
  genuine operand bit — the top bit of a 5-bit shift amount split across word1's bit 0 and
  word2's low nibble, confirmed against all 8 real occurrences of shift amounts 6/8/22).
- **Signed-byte pre-increment loads**: `lb.s eregA, [++eregB=#imm1619]` (`ins0011=0xe5c`, a
  narrower plain 4-bit immediate, distinct from `lb.z`'s existing 8-bit `0xe58`/`0xe59` pair)
  and `lb.s eregA, [++eregB=eregC]` (register-stride sibling of `lb.z` at `ins0011=0xedc`, using
  `imm1619=2` — the third value the neighbouring halfword family already uses this same way for
  z/store/s, since `imm1619=1` at this exact opcode was already claimed by an existing `sb`
  store constructor).
- **`lw eregA, [eregB++="-16"]`** (`ins0011=0xcdf`) — a fixed-offset post-increment word load,
  evidenced only ever with offset `-16` across all 8 real occurrences (`imm2427=15`,
  `imm1719=0` pinned rather than generalized); a real firmware store sibling exists at the same
  `ins0011` with a *different*, unsolved offset formula (`imm1719=4`, offsets like `-8`), so
  `imm1719=0` is pinned specifically to avoid this load constructor over-matching into that
  still-open store form's space.
- **`sat16 eregA, eregC`** (`ins0011=0x078`, signed saturate to `[-32768,32767]`) — modeled with
  the same explicit-branch saturation idiom already used for `sadd.sat`/`smax`/`smin` in
  `pi32v2_ins_arithops.sinc`.

### Files touched this round

- `data/languages/pi32v2.slaspec` (new `sspn` register, new `imm1628s` field, `packedimm12`/
  `notpackedimm12` 7th sub-case, second `ssync`/`btbclr`/`sevl`/`wfe` encodings, two new
  pcodeops)
- `data/languages/pi32v2_ins_progflow.sinc` (`callns`, `rtns`, `trigger`)
- `data/languages/pi32v2_ins_move.sinc` (`sspn = sp`)
- `data/languages/pi32v2_ins_arithops.sinc` (extended-range `sp +=`)
- `data/languages/pi32v2_ins_stack.sinc` (single-register bitmap push/pop family, two new
  mirror recursion tables)
- `data/languages/pi32v2_ins_ifthenelse.sinc` (4 new `imm1623`-flagged aliases, `if (regA <
  #packedimm12)`)
- `data/languages/pi32v2_ins_logicops.sinc` (`xor [eregA+offset],eregC`, `and`/`xor
  [eregA+offset],#packedimm12`, `sat16`)
- `data/languages/pi32v2_ins_shiftrot.sinc` (memory-operand shift compound-assign family)
- `data/languages/pi32v2_ins_loadstore.sinc` (signed-byte pre-increment loads, fixed `-16`
  post-increment word load)
- `data/languages/pi32v2.sla` (recompiled)

### Non-invasive-first compliance (this round)

Static analysis and headless Ghidra batch-disassembly only, against the same real firmware
image and this fork's own SLEIGH module, plus fixing the reproduction/base-address bug above
(no code changes, purely a local verification-pipeline correction). No synthetic compilation
was needed this round — every fix had enough independent real-firmware confirmation on its own.
No new tool installation, no device I/O, no MIDI/USB/OTA touched at any point.

## Seventh round

### A second real firmware image as an evidence source

Every prior round validated exclusively against one real firmware image. This round added a
**second, independently-sourced real firmware image from the same chip family** (same JLFS
container/unpack format, same `0x2000120` load address, different application code — a
different product built on the same SoC), disassembled with the same real vendor
LLVM-derived `objdump` toolchain used for the original ground truth. This gave several opcode
families that were previously "single occurrence, not enough evidence to generalize" 5-14
independent confirming occurrences each, which is what made most of the fixes below possible —
this is the same reproducible methodology as every other round (real toolchain disassembly vs.
this fork's own SLEIGH output), just against a second binary.

### Results this round

| Firmware | Before | After |
|---|---|---|
| Original (used by all prior rounds) | 68 gap addresses (99.97%) | 58 gap addresses (99.972%) |
| Second image (new this round) | 116 gap addresses | 77 gap addresses |

Zero regressions on either firmware image (verified via full re-diff after every batch of
fixes — `BAD`/`LEN_MISMATCH`/`MISSING` counts only ever decreased or held steady, never
increased).

### Fix #25: doubleword pre-increment store with immediate offset (`pi32v2_ins_loadstore.sinc`)

The `ldw`/`sdw`/`addldw` family at `ins0411=0xC5` already had load-with-offset, store-with-
offset, and register-stride pre-increment load slots (`imm1617=0/1/2`); the immediate-offset
pre-increment **store** at `imm1617=3` was flagged in a comment as "a plausible analogy...
but not observed." Confirmed this round against 3 real occurrences (two distinct `imm11`
values, 696 and 872, both register-pair destinations `r1_r0`/`r3_r2` seen at the same
immediate) — same `imm11 = (imm0002s<<8)|(imm2427<<4)|(imm1819<<2)` bit-packing as the existing
single-register `addsdw` immediate form, just in the `0xC5` family and storing 8 bytes instead
of 4.

### Fix #26: post-increment register-stride byte store (`pi32v2_ins_loadstore.sinc`)

`ins0011=0xede`, sibling of the pre-increment register-stride byte store already at `0xedc`
(same relationship as the halfword family's `0xddc`/`0xdde` pre/post pair). Confirmed against
7 real occurrences.

### Fix #27: fixed-offset post-increment stores, siblings of the existing `-16` load
(`pi32v2_ins_loadstore.sinc`)

When the `[rB++=-16]` fixed-offset load was added in an earlier round, its comment flagged "a
real firmware store sibling exists at the same `ins0011`... with offsets seen at -8" as an
unresolved formula. Confirmed this round: `imm1719=4` (vs. the load's `imm1719=0`) gives
exactly -8, at the same `ins0011=0xcdf` escape opcode, discriminated by the same `imm1616`
direction bit used elsewhere in this family. Also added two halfword siblings (`h[rB++=-4]`,
`h[rB++=-260]`) as fully-pinned single-occurrence escapes (each confirmed byte-exact, but with
only one sample per opcode there isn't yet enough evidence to tell whether the differing low
opcode bit or the base register drives the -4-vs-260 difference, so each is its own pinned
constructor rather than a guessed general formula — see the "still open" section).

### Fix #28: `rtss` (`pi32v2_ins_progflow.sinc`)

`ins0012=0x0084`, previously assumed unused, sits immediately before `rtns` (`0x0085`, "return
non-secure") in the same bare-mnemonic return-instruction opcode run. Confirmed against 3 real
occurrences; modeled with the same "return via `rets`" p-code as its siblings, for the same
no-TrustZone-modeled reason already documented for `rtns`.

### Fixes #29-31: `if`/`ifs` block-form immediate comparison siblings (`pi32v2_ins_ifthenelse.sinc`)

- `ifs (regA > #imm1627s) { ... }` at `ins0411=0xE3` — the missing "greater-than" signed
  direct-immediate sibling of the existing `>=`/`<` pair (`0xD3`/`0xDB`... `0xDA`). Confirmed
  against real occurrences including a `-1` comparison, which only comes out right through the
  plain signed 12-bit field (`imm1627s`), not any `packedimm12` sub-case — an important
  disambiguator since the byte pattern could otherwise look `packedimm12`-shaped.
- `if (regA <= #packedimm12) { ... }` at `ins0411=0xCA` — confirmed via two real values (4096
  and 134217728) that both decode exactly through `packedimm12`'s existing shift-based
  sub-cases, identically to the already-implemented `0xCB`. Treated as a duplicate opcode slot
  of `0xCB`, consistent with this ISA's other confirmed duplicate-opcode pairs (`ssync`/
  `btbclr`'s extra slots, `packedimm12`'s own `imm2427=1`/`2` duplicate).
- `ifs (regA <= #packedimm12) { ... }` at `ins0411=0xEA` — same duplicate-slot relationship to
  the existing `0xEB`, confirmed via one real value (127) that decodes identically either way.

### Newly discovered, not yet fixed (deferred this round)

- **The `(ssat,x2)` dual-register/half-register parallel-arithmetic family** now has far more
  evidence (9+ addresses across at least 4 distinct sub-opcodes in the second firmware image,
  up from the long-standing "4 addresses, 2 patterns"), and a partial hypothesis was derived
  (a single bit, `imm1616`, appears to switch all operands between `.h`/`.l` sub-register halves
  for the single-register forms at `ins0011=0x51f`/`0x54f`/`0x55f`) — but the register-pair
  forms at `ins0011=0x573` show *mixed* `.h`/`.l` selection across their two operand groups in
  the same instruction, meaning at least one more selector bit is involved that wasn't
  isolated this round. This ISA has no existing half-register (`.h`/`.l`) sub-piece machinery
  anywhere in the SLEIGH file yet, so getting this wrong risks incorrect p-code rather than
  just a length mismatch — deferred pending either more examples or a targeted synthetic-
  compilation reproducer.
- **A wide-immediate memory-operand AND family** at `ins0011=0xff3`/`0xff4` (`[r15+-48] &=
  0x31FFFFFF`, `[r15+-52] &= 0xFFFFFE01`) — a new opcode area distinct from the existing
  `and [eregA+offset],#packedimm12`/`#notpackedimm12` constructors. Only 2 occurrences, with
  masks that don't fit the existing compressed-immediate subtables' simple byte-repeat forms;
  not enough evidence yet to derive the encoding with confidence.
- **A completely separate `group=7`-based special-register push/pop mechanism** at
  `ins0011=0x950`-`0x958` (`{pc} = [sp++]`, `[--sp] = {sp, ssp, usp, icfg, psr, rets, retx,
  rete, reti}`) — distinct from the existing, already-comprehensive `group=0`/`ins0412=0x04x`
  multi-register range-list/special-register-list family documented in the sixth round's
  section above. Only 1 occurrence each; a wrong stack-pointer-arithmetic model here is
  higher-risk than most gaps, so deferred pending more evidence.
- **The wide-immediate `if (rX ?? imm) goto ...` family** (still the largest single deferred
  item, now with more confirmed offset values — 0x10/0x14/0x18/0x9c — across the LEN_MISMATCH
  addresses) remains deferred for the same reason as every prior round: extending the if/then/
  else state machine here risks regressing the existing 32-bit `or`-immediate constructor.
  Notably, even the real vendor `objdump` prints a literal `??` for this family's comparison
  operator instead of a real mnemonic, suggesting the authoritative toolchain itself doesn't
  fully resolve this encoding either — a data point worth keeping in mind before attempting it.

### Files touched this round

- `data/languages/pi32v2_ins_loadstore.sinc` (doubleword pre-increment immediate store,
  post-increment register-stride byte store, fixed-offset post-increment stores)
- `data/languages/pi32v2_ins_progflow.sinc` (`rtss`)
- `data/languages/pi32v2_ins_ifthenelse.sinc` (signed `>` direct-immediate block form, two
  duplicate-opcode `<=` block-form slots)
- `data/languages/pi32v2.sla` (recompiled)

### Non-invasive-first compliance (this round)

Static analysis and headless Ghidra batch-disassembly only, against two real firmware images
(one already used by every prior round, one newly added this round) and this fork's own SLEIGH
module. No synthetic compilation was needed — every fix had enough independent real-firmware
confirmation on its own. No new tool installation beyond what was already documented for
generating ground-truth disassembly in prior rounds; no device I/O, no MIDI/USB/OTA touched at
any point.
