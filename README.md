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
| + first round's 3 targeted encoding fixes | 768 | 99.63% |
| + second round's saturating-arithmetic/branch/load-store fixes | 405 | 99.78% |
| + third round's multi-register range-list/special-register-list push/pop family | 309 | 99.83% |
| + fourth round's wide-immediate signed compare-and-branch fix | 277 | 99.87% |
| + fifth round's register-operand shift/divide and `if`/`ifs` sibling fixes | 179 | 99.91% |
| + sixth round's single-register bitmap push/pop, `packedimm12` 7th mode, and misc fixes | 68 | 99.97% |
| + seventh round's fixes, cross-validated against a second real firmware image | 58 | **99.972%** |
| + eighth round's fixes, found via a third real firmware image (147→111 gaps on that image; no change on this baseline) | 58 | 99.972% |

Across all four rounds, previously-undecoded `pi32v2` encoding families were identified and
added, each verified against every real occurrence in the ground truth (not a sample) and,
where real occurrences were too sparse to pin an encoding confidently, cross-checked against
clean output from the real JieLi `clang`/`objdump` toolchain compiling small targeted C
snippets. The fourth round additionally cross-checked a community-maintained pi32v2 opcode
reference (<https://kagaimiq.github.io/jielie/cpu/pi32v2.html>) as a hypothesis source, not an
authority — one of its two candidate encodings didn't match this firmware's real bytes and was
discarded after verification, while the other correctly pointed at two missing opcode slots in
an instruction family this module had already mostly implemented:

- **Register-indexed post-increment load/store** (`[rB ++= rC]`, word/halfword/byte) — the
  single largest gap, ~3,000+ addresses, a very common addressing mode in compiler-generated
  loop code that pi32v2 was missing despite pi32 (v1) already having it.
- **Extended-offset (128–252) `sp`-relative word load/store** — ~975 addresses, needed for
  any function with a stack frame larger than 124 bytes.
- **Signed halfword `sp`-relative load (`lh.s`)** — ~136 addresses, the one missing slot in an
  otherwise-complete `sp`-relative family.
- **`smax`/`umax` parallel-arithmetic ops** — confirmed by compiling a saturating-max/min C
  idiom with the real toolchain; `smin`/`umin` were already present, `smax`/`umax` were the
  missing sibling opcode.
- **A test-and-set spinlock retry branch (`ifeq`)** — previously suspected to be a trap/padding
  idiom; real-firmware context (always immediately following a `testset` instruction, always
  looping back exactly onto it) showed it's a genuine conditional branch, not padding.
- **A large family of byte/halfword pre/post-increment and negative-offset load/store
  addressing modes** (`b[rB++=imm]`, `b[++rB=imm]`, `h[++rB=imm]`, `h[++rB=rC]`, register-pair
  `d[++rB=rC]`, and their negative-immediate/store-direction siblings) — the biggest single
  bucket of remaining gaps, resolved by extending the existing byte-family encoding pattern to
  its unimplemented sibling opcodes and to the analogous halfword/doubleword opcodes.
- **A third round then added the multi-register "range-list" and "special-register-list"
  `[--sp]={...}` / `{...}=[sp++]` push/pop family** (`[--sp]={r10-r4}`, `{rets,r3-r1}=[sp++]`,
  `[--sp]={psr,sr4,rets,rete,reti}`, and every other combination in that opcode nibble) —
  ~100 addresses, closed by extending an existing-but-partial bitmap/range-list constructor
  scheme to its full, previously only partially-covered domain. This was the multi-register
  push/pop syntax noted as an open, higher-effort item in earlier rounds; see the gap-analysis
  doc for the full bitfield derivation and a couple of known cosmetic-only display quirks that
  remain in that constructor family.
- **A fourth round closed the wide-immediate signed compare-and-branch family**
  (`ifs (rX >= imm) goto ...` / `ifs (rX > imm) goto ...`) — 32 addresses, fixed by adding two
  opcode slots (signed `>=` and `>`) that were simply missing from an otherwise-complete,
  already-implemented 48-bit compare-and-branch instruction family. Real firmware bytes at
  those addresses were previously being mismatched against an unrelated, shorter 4-byte
  bitwise-or instruction.
- **A fifth round closed 98 more addresses across two areas**: 64-bit-pair register-operand
  shift/divide ops (`lsl`/`lsr`/`qasr edregA, eregC`, `div edregA, edregB, eregC` — 48
  addresses) and four missing/too-narrowly-scoped siblings in the `if`/`ifs` conditional-block
  family (`ifs (rA > rB)`, unsigned `if (rA != #packedimm12)`, a too-narrow `if (rA !=
  #imm1627s)` widened to its full 12-bit range, and unsigned `if (rA < imm)` — 46 addresses),
  each confirmed against every real ground-truth occurrence. This round also found and fixed a
  real (non-decode-affecting) p-code correctness bug flagged by the SLEIGH compiler's own
  "unnecessary extension" warning: `sextra` (signed bit-field extract) was silently failing to
  propagate the extracted field's sign bit.
- **A sixth round closed 111 more addresses**, the largest since the initial baseline: a
  single-register-based bitmap push/pop family (`{list} = [regA++]` and five sibling
  addressing modes, extending the existing sp-only push/pop machinery to an arbitrary base
  register), four exact-value `if`/`ifs` register-register comparison aliases, a previously
  missing 7th mode of the shared `packedimm12` compressed-immediate subtable (confirmed against
  two independent real occurrences at different opcodes), a memory-operand compound-assign
  family (`[rX+off] ^=`/`&=`/`<<=`/`>>=`/`>>>=`), signed-byte pre-increment loads, a fixed-
  offset post-increment word load, and a handful of single/double-byte opcodes (`callns`,
  `rtns`, `sspn = sp`, `sevl`/`wfe`, a second `ssync`/`btbclr` encoding, `trigger`, `sat16`, and
  an extended-range `sp +=` form). This round also caught and fixed a reproduction bug in the
  verification pipeline itself (a wrong raw-binary load base address that silently produced a
  0%-match false alarm) — worth knowing before trusting a from-scratch run of this pipeline
  that claims everything is broken.
- **A seventh round validated against a second, independently-sourced real firmware image from
  the same chip family** (same container/load-address format, different application code),
  disassembled with the same real vendor toolchain used for the original ground truth. This
  turned several previously single-occurrence, "not enough evidence" gaps into 3-14x confirmed
  patterns, closing 10 addresses on the original firmware (58 remaining) and 39 on the new one
  (116 → 77), across a doubleword pre-increment immediate store, a post-increment register-
  stride byte store, two fixed-offset post-increment stores resolving formulas flagged as
  unsolved in earlier rounds, a missing `rtss` return opcode, and three `if`/`ifs` block-form
  immediate-comparison siblings (one new signed direct-immediate form, two confirmed duplicate-
  opcode slots of already-implemented comparisons). Zero regressions on either firmware image.
- **An eighth round added a third real firmware image from the same chip family**, closing 36
  addresses on that image (147 → 111; no change on the original baseline, since these opcodes
  simply don't occur there), across a missing multiply-subtract-accumulate opcode (`mulsub.s`/
  `.z`, sibling of the existing `muladd.s`/`.z`, confirmed via a 33-times-repeated unrolled
  multiply-accumulate loop), a third confirmed value of an apparently-inert field on an existing
  `if` comparison opcode, and one more duplicate-opcode slot in the `if`/`packedimm12` family.
  A fourth candidate firmware image was found to use a different, unsupported container
  sub-format and was left for a future round. Zero regressions on any of the three images.
- **A ninth round switched from firmware archaeology to synthetic ground truth**, compiling
  real probes with the vendor's own pi32v2 `clang` and cross-checking the output against this
  grammar. This produced solid negative evidence that ordinary compiled C never emits a direct
  wide-immediate compare-and-branch opcode (it always materializes the constant into a register
  first), and independent confirmation that the single-special-register interrupt push/pop
  (`[--sp] = {reti}` / `{reti} = [sp++]`) already decodes correctly. Five more real firmware
  images were also checked: two from the same chip family surfaced a new class of apparent gap
  that a controlled, content-free test (a large synthetic run of `nop` instructions reproduces the
  exact same failure) root-caused to a scale-dependent artifact in Ghidra's own disassembler/
  context runtime — not a grammar defect, and nothing to fix here — and two images from a
  different, related chip showed a gap rate
  50-100x the established baseline across unrelated instruction families — evidence of a
  meaningfully different encoding revision, not a few missing constructors, so neither was used
  as a fix source. No grammar changes this round; a ground-truth tooling bug (address-column
  parsing for a wider memory map) was found and fixed instead.
- **A tenth round diagnosed and partially fixed a Ghidra-analyzer bug, not a grammar gap**: a
  full-binary decompile of a real firmware image showed `tbb`/`tbh` (table-branch) instructions —
  correctly implemented in the grammar — confusing Ghidra's generic switch-table analyzer, which
  has no way to know a table's real length for a custom ISA and reads well past its end, pulling
  unrelated downstream code into artificially bloated functions (one case: a real ~150-byte
  function reported as 15,978 bytes). A new script, `tools/gap-analysis/FixTbbTbhTables.java`,
  locates each instance's compiler-emitted bounds check, computes the real table, and rebuilds the
  affected function; verified to correctly fix 60 of 110 instances on that image with zero
  regressions. A controlled before/after test also disproved part of the ninth round's own
  large-image findings: the fix left the decompiler's total `pcode error` warning count completely
  unchanged, so the `tbb`/`tbh` bug — despite being real and fixed — is *not* the main driver of
  those warnings on large images. Their actual cause remains open.

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
- **pi32v2** *(99.972% instruction-match rate against real firmware ground truth — see above;
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
  - Remaining missing instructions (a dual-register/half-register `(ssat,x2)` parallel-
    arithmetic family now with a partial bit-level hypothesis but at least one unresolved
    selector bit, a wide-immediate memory-operand AND family, a separate `group=7`-based
    special-register push/pop mechanism distinct from the existing range-list family, several
    single-occurrence dual-fetch parallel multiply-accumulate and saturating-arithmetic forms, a
    `[rX+off] += imm` compound-assign-with-immediate-delta family whose offset/delta packing
    isn't fully solved, and a few other single-occurrence opcodes — see the gap-analysis doc)
  - The wide-immediate `if (rX ?? imm)` conditional-branch family (12 addresses) — deferred
    across several rounds since fixing it means extending the if/then/else state machine and
    disambiguating against the existing 32-bit `or`-immediate constructor, with real risk of
    regressing that family if the new pattern is too broad
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
