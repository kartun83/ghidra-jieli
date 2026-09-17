# ghidra-jieli (pi32v2-focused fork)

Ghidra processor module for JieLi's custom CPU architectures. Originally implemented by
[Kagaimiq](https://github.com/kagaimiq/jielie/) and substantially improved by
[Quarkslab](https://github.com/quarkslab/ghidra-jieli). This fork narrows scope further:
**it exists specifically to make `pi32v2` decode correctly against real hardware firmware**,
verified by differential testing against ground-truth disassembly from JieLi's own LLVM/clang
toolchain — not just made to "look plausible."

Everything else in the module (`pi32`, `q32s`, `dv10`/`dv12`, `f59`/`f95`) is carried over
unmodified from upstream Quarkslab and has received **no additional work, testing, or
verification here**. If you need those targets, go to
[quarkslab/ghidra-jieli](https://github.com/quarkslab/ghidra-jieli) directly — this fork has
nothing to offer you there.

## Why this fork exists

This fork's `pi32v2` support was validated **address-by-address against 209,161 real
instructions**, decoded independently by JieLi's own `clang`/`objdump` toolchain running
against a real shipped firmware binary. A differential-testing harness
(`tools/gap-analysis/`) walks both disassemblies in lockstep, flags every address where they
disagree (wrong length, undecoded, or missing), and ranks the disagreements by how many real
addresses share the same byte encoding — so a single SLEIGH fix can resolve thousands of
addresses at once instead of chasing one-off mismatches.

### Results

| Stage | Gap addresses (of 209,161) | Match rate |
|---|---|---|
| Naive per-address test harness (harness bug, not a real baseline) | 8,966 | 95.7% |
| Same SLEIGH module, correct batched/linear-sweep harness | 1,358 | 99.35% |
| + this fork's 3 targeted encoding fixes | 768 | **99.63%** |

Three previously-undecoded `pi32v2` encoding families were identified and added, each verified
against every real occurrence in the ground truth (not a sample):

- **Register-indexed post-increment load/store** (`[rB ++= rC]`, word/halfword/byte) — the
  single largest gap, ~3,000+ addresses, a very common addressing mode in compiler-generated
  loop code that pi32v2 was missing despite pi32 (v1) already having it.
- **Extended-offset (128–252) `sp`-relative word load/store** — ~975 addresses, needed for
  any function with a stack frame larger than 124 bytes.
- **Signed halfword `sp`-relative load (`lh.s`)** — ~136 addresses, the one missing slot in an
  otherwise-complete `sp`-relative family.

Full derivation, confidence levels, and the remaining (lower-impact, harder) open gaps are
documented in [`tools/gap-analysis/PI32V2_SLEIGH_GAPS.md`](tools/gap-analysis/PI32V2_SLEIGH_GAPS.md).

### Methodology note worth knowing if you extend this

A naive "force-disassemble one address in isolation" test harness produces large numbers of
**false-positive** gaps for pi32v2, because its delay-slot/parallel-issue encodings need to
read past the current instruction to resolve correctly — restricting the address set breaks
that lookahead. The harness in `tools/gap-analysis/DumpDisasm.java` instead seeds a whole
memory block and disassembles it in one batched call, matching how `objdump`'s own linear
sweep works. This alone eliminated most apparent gaps before any real SLEIGH fix was made —
worth knowing before trusting any other differential-testing setup against this ISA.

## Reproducing / extending this work

See [`tools/gap-analysis/PI32V2_SLEIGH_GAPS.md`](tools/gap-analysis/PI32V2_SLEIGH_GAPS.md)'s
"Reproducing" section for the exact commands (rebuild SLEIGH → reinstall into Ghidra → headless
dump → diff against your own ground-truth disassembly). The diff tool
(`tools/gap-analysis/pi32v2_sleigh_diff.py`) takes explicit `--ground-truth`/`--ghidra-dump`
paths, so it works against any target firmware, not just the one this fork was built against.

## Status of each target (inherited from upstream, pi32v2 line reflects this fork's work)

- dv10 *(this is Blackfin, not implemented)*
- dv12 *(this is Blackfin, not implemented)*
- pi32 *(not complete, but somewhat usable — untouched by this fork)*
- **pi32v2** *(99.63% instruction-match rate against real firmware ground truth — see above;
  a handful of lower-impact encoding families still open, see the gap-analysis doc)*
- q32s *(very early stage — untouched by this fork)*
- f59 *(not implemented yet)*
- f95 *(not implemented yet)*

## Upstream TODO (unaddressed by this fork, kept for reference)

- pi32
  - Stack-related instructions (currently only `push {rets}` and `pop {pc}` is handled)
  - Remaining missing instructions
  - rep loops and if-else blocks?
  - Maybe refactor the mnemonics? (like the ones used on q32s and pi32v2? or do it the other way around?)
  - Change flags on instructions that change them (e.g. add, sub, rotc, etc.)
- pi32v2
  - Remaining missing instructions (`ifeq`/self-loop trap idiom, `smax`/`umax`/`ssat` parallel-arith
    family, a narrower `[rB++=imm]` variant, some push/pop-list variants — see the gap-analysis doc)
  - Mnemonics like in q32s or pi32?
- q32s
  - Do the rest:
    - Group7 instructions of course
    - Flags and stacks too
  - Make decisions about a new mnemonic standard (or use pi32's?)
  - (at least it's used on BD19 and BD29 — AC632N and AC630N resp.)
  - (It also seems to be simpler than pi32 or pi32v2!)
- dv10/dv12 (blackfin)
  - Maybe implement it too? Or leave it as a separate project?
