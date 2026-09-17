// Post-analysis fixup for pi32v2's "tbb"/"tbh" (table branch byte/halfword)
// instructions, which Ghidra's generic switch/jump-table analysis cannot
// bound correctly on its own.
//
// BACKGROUND: `tbb regA` / `tbh regA` read a 1-byte (tbb) or 2-byte (tbh)
// offset from `inst_next + regA`, double it, add it to `inst_next`, and jump
// there -- the same construct as ARM Thumb's TBB/TBH. Nothing in the
// instruction encoding says how many entries the table has; compilers always
// emit a bounds check (e.g. `jbe idx,#N,<table-start>`) immediately before
// the scale+branch sequence, and the table is exactly N+1 (inclusive bound)
// or N (exclusive bound) entries long. Ghidra's generic SwitchAnalyzer has no
// architecture-specific knowledge of this pattern for a custom SLEIGH module
// (its ARM support gets this via a dedicated Java analyzer that this project
// has no equivalent of), so it guesses a table length, over-reads past the
// real end of the table into whatever real code follows, and computes
// garbage jump targets from misinterpreted instruction bytes. This produces
// exactly the symptoms documented in the tenth round of
// PI32V2_SLEIGH_GAPS.md: scattered "pcode error: unable to resolve
// constructor" targets, "instruction overlaps instruction" warnings, and a
// handful of functions ballooning to tens of kilobytes because unrelated
// downstream code gets pulled into them as bogus flow targets.
//
// This script finds every tbb/tbh instruction, locates its bounding compare
// by walking a short window of preceding instructions, computes the real
// table length from it, re-types the table as data of the correct size, adds
// an explicit COMPUTED_JUMP reference from the tbb/tbh instruction to each
// real case target (disassembling it if needed), and writes a jump-table
// override (the same mechanism the GUI's "Override Jump Table" action uses)
// so the decompiler's own independent switch-recovery pass uses our resolved
// table instead of re-deriving one. Instructions whose bound can't be
// confidently located are left untouched and logged rather than guessed at,
// per this project's evidence discipline -- a wrong bound is worse than no
// fix.
//
// VERIFIED RESULT (see the tenth round of PI32V2_SLEIGH_GAPS.md for the full
// writeup): on a real SMK-37 Elite v016 firmware decompile, this correctly
// resolves 60 of 110 tbb/tbh instances and demonstrably fixes real function-
// boundary corruption -- one function that had absorbed ~16KB of unrelated
// downstream code as bogus flow targets was correctly reduced back to its
// real ~150-byte body once fixed. That part is a genuine, confirmed win.
// HOWEVER, a controlled A/B test (identical firmware, otherwise-identical
// pipeline, fix applied vs not) showed the decompiler's own reported
// "pcode error" warning count is completely unaffected by this fix -- byte-
// for-byte identical before and after, across both the initial auto-analysis
// phase and the explicit decompile pass. This disproves the original
// hypothesis that tbb/tbh table over-reads were the source of those specific
// warnings; whatever actually causes them remains unidentified and is a
// separate, still-open problem. Use this script for what it's proven to fix
// (function-boundary corruction from unbounded tbb/tbh tables), not as a fix
// for pcode-error counts in general.
//
// Usage (as a -postScript, after normal auto-analysis, before decompiling):
//   -postScript FixTbbTbhTables.java <report-output-path>

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.pcode.JumpTable;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class FixTbbTbhTables extends GhidraScript {

    // Two ways a bounds check can reach the scale+tbb/tbh block:
    //
    //  (a) "branch INTO the block": the compare's TAKEN branch targets the
    //      block directly (in-range falls into the table, out-of-range falls
    //      through to a default handler elsewhere). Here the *taken*
    //      condition is the in-range one: jbe/jle (<=) -> entries = imm+1,
    //      jb/jl (<) -> entries = imm.
    //
    //  (b) "fallthrough INTO the block": the compare is the block's ordinary
    //      linear predecessor and its taken branch goes elsewhere (the
    //      default handler); reaching the block means the condition was
    //      NOT taken. Here the *fallthrough* condition is the in-range one:
    //      ja/jg (branches away if >imm) -> entries = imm+1,
    //      jae/jge (branches away if >=imm) -> entries = imm.
    private static final Set<String> TAKEN_INCLUSIVE = new HashSet<>(Arrays.asList("jbe", "jle"));
    private static final Set<String> TAKEN_EXCLUSIVE = new HashSet<>(Arrays.asList("jb", "jl"));
    private static final Set<String> FALLTHROUGH_INCLUSIVE = new HashSet<>(Arrays.asList("ja", "jg"));
    private static final Set<String> FALLTHROUGH_EXCLUSIVE = new HashSet<>(Arrays.asList("jae", "jge"));

    // Sanity cap: reject anything that doesn't look like a real bounded
    // switch, rather than guessing.
    private static final int MAX_TABLE_ENTRIES = 64;

    private PrintWriter report;

    @Override
    protected void run() throws Exception {
        String outPath = getScriptArgs().length > 0 ? getScriptArgs()[0]
                : "/tmp/fix_tbb_tbh_report.txt";
        report = new PrintWriter(new FileWriter(outPath));

        Listing listing = currentProgram.getListing();
        List<Instruction> tableBranches = new ArrayList<>();
        InstructionIterator it = listing.getInstructions(true);
        while (it.hasNext()) {
            Instruction insn = it.next();
            String mn = insn.getMnemonicString();
            if (mn.equals("tbb") || mn.equals("tbh")) {
                tableBranches.add(insn);
            }
        }
        report.println("Found " + tableBranches.size() + " tbb/tbh instructions total");

        int fixed = 0, skipped = 0;
        Set<Address> touchedFunctionEntries = new LinkedHashSet<>();
        for (Instruction tb : tableBranches) {
            try {
                if (fixOne(tb)) {
                    fixed++;
                    Function fn = listing.getFunctionContaining(tb.getAddress());
                    if (fn != null) {
                        touchedFunctionEntries.add(fn.getEntryPoint());
                    }
                }
                else {
                    skipped++;
                }
            }
            catch (Exception e) {
                report.println("  " + tb.getAddress() + ": EXCEPTION " + e);
                skipped++;
            }
            monitor.checkCancelled();
        }

        report.println("TOTAL " + tableBranches.size() + "  FIXED " + fixed + "  SKIPPED " + skipped);

        // A function's body (the set of addresses it covers) was already
        // computed and cached by the auto-analysis that ran before this
        // script, using the bogus over-read table edges. Fixing those edges
        // doesn't retroactively shrink an already-built function -- rebuild
        // any function that contained a fixed tbb/tbh from scratch so its
        // body gets recomputed from the now-correct flow graph.
        for (Address entry : touchedFunctionEntries) {
            Function fn = listing.getFunctionAt(entry);
            String name = fn != null ? fn.getName() : "?";
            boolean hadFunction = fn != null;
            if (hadFunction) {
                listing.removeFunction(entry);
            }
            Function recreated = createFunction(entry, name);
            String ranges = "?";
            if (recreated != null) {
                StringBuilder sb = new StringBuilder();
                int n = 0;
                for (ghidra.program.model.address.AddressRange r : recreated.getBody().getAddressRanges()) {
                    if (n++ < 5) {
                        sb.append(r).append("; ");
                    }
                }
                ranges = "numRanges=" + recreated.getBody().getNumAddressRanges() + " first5=[" + sb + "]";
            }
            report.println("Rebuilt function " + name + " @ " + entry
                    + " (removed=" + hadFunction + ", recreated=" + (recreated != null) + ") " + ranges);
        }
        report.close();

        // Deliberately NOT calling analyzeAll() here: Ghidra's generic
        // SwitchAnalyzer runs as part of it, re-guesses the same wrong
        // tbb/tbh table lengths from scratch, and re-adds the exact bogus
        // computed-jump references this script just removed -- confirmed by
        // testing (it silently re-introduced the full original error count).
        // removeFunction()+createFunction() above already recompute each
        // affected function's body directly from the now-correct flow graph,
        // which is all that's needed.
    }

    private boolean fixOne(Instruction tb) throws Exception {
        Address tbAddr = tb.getAddress();
        boolean isHalfword = tb.getMnemonicString().equals("tbh");
        int entrySize = isHalfword ? 2 : 1;

        Register idxReg = tb.getRegister(0);
        if (idxReg == null) {
            report.println(tbAddr + ": no register operand on " + tb.getMnemonicString() + ", skip");
            return false;
        }

        // The scale+branch block's real entry point: if a "lsl dst,src,#1"
        // immediately precedes the tbb/tbh (tbh indexes are pre-scaled by 2),
        // the block starts there and the bounded register is its source;
        // otherwise the block is just the tbb/tbh instruction itself.
        Address blockStart = tbAddr;
        String boundedReg = idxReg.getName();
        Instruction maybeScale = currentProgram.getListing().getInstructionBefore(tbAddr);
        if (maybeScale != null && maybeScale.getMnemonicString().equals("lsl")) {
            Register dst = maybeScale.getRegister(0);
            Register src = maybeScale.getRegister(1);
            if (dst != null && dst.getName().equals(boundedReg) && src != null) {
                blockStart = maybeScale.getAddress();
                boundedReg = src.getName();
            }
        }

        // The compiler-emitted bounds check reaches this block either by
        // falling straight through into it, or (as is common when the
        // default/out-of-range case is the fallthrough path instead) via an
        // explicit forward branch. Check both kinds of predecessor rather
        // than assuming linear address order reflects control flow.
        BoundResult br = computeBoundedEntries(blockStart, boundedReg);
        if (br == null) {
            report.println(tbAddr + ": no bounding compare found among predecessors of "
                    + blockStart + ", skip (leave for manual review)");
            return false;
        }

        long entries = br.entries;
        if (entries <= 0 || entries > MAX_TABLE_ENTRIES) {
            report.println(tbAddr + ": computed " + entries + " entries from "
                    + br.cmpInsn.getAddress() + " (" + br.cmpInsn.getMnemonicString()
                    + "), out of sane range, skip");
            return false;
        }

        Address tableStart = tbAddr.add(tb.getLength());
        Address tableEnd = tableStart.add(entries * entrySize);
        Memory mem = currentProgram.getMemory();

        // Read the real table entries BEFORE touching the listing.
        long[] targets = new long[(int) entries];
        for (int i = 0; i < entries; i++) {
            Address entryAddr = tableStart.add((long) i * entrySize);
            long raw = isHalfword ? (mem.getShort(entryAddr) & 0xFFFFL) : (mem.getByte(entryAddr) & 0xFFL);
            targets[i] = tableStart.getOffset() + (raw << 1);
        }

        // Clear whatever Ghidra previously guessed across the table region
        // (wrong-length data, or real code it wrongly decoded from
        // misread table bytes) and re-type it as a proper fixed-size array.
        clearListing(tableStart, tableEnd.subtract(1));
        if (isHalfword) {
            currentProgram.getListing().createData(tableStart, new ArrayDataType(WordDataType.dataType, (int) entries, 2));
        }
        else {
            currentProgram.getListing().createData(tableStart, new ArrayDataType(ByteDataType.dataType, (int) entries, 1));
        }

        // Ghidra's own auto-analysis already ran (and mis-guessed the table
        // length) before this script -- it will have left behind computed-
        // jump references to whatever garbage targets it read past the real
        // table. Drop all of those before adding the correct ones, or the
        // decompiler keeps chasing both sets.
        currentProgram.getReferenceManager().removeAllReferencesFrom(tbAddr);

        int okTargets = 0;
        List<Address> resolvedTargets = new ArrayList<>();
        for (long t : targets) {
            Address targetAddr = tableStart.getNewAddress(t);
            try {
                if (currentProgram.getListing().getInstructionAt(targetAddr) == null) {
                    disassemble(targetAddr);
                }
                currentProgram.getReferenceManager().addMemoryReference(
                        tbAddr, targetAddr, RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0);
                resolvedTargets.add(targetAddr);
                okTargets++;
            }
            catch (Exception e) {
                report.println(tbAddr + ":   target 0x" + Long.toHexString(t) + " failed to disassemble: " + e);
            }
        }

        // Plain References are not enough: the decompiler runs its OWN
        // independent jump-table recovery pass over the p-code and, for a
        // load-then-branch construct like tbb/tbh, re-derives a table length
        // from scratch rather than trusting pre-existing references -- so it
        // reproduces the exact same over-read unless the table is written as
        // an explicit override (the same mechanism the GUI's "Override Jump
        // Table" action uses), which the decompiler checks first.
        Function containing = currentProgram.getListing().getFunctionContaining(tbAddr);
        if (containing != null && !resolvedTargets.isEmpty()) {
            try {
                JumpTable jt = new JumpTable(tbAddr, new ArrayList<>(resolvedTargets), true, 16);
                jt.writeOverride(containing);
            }
            catch (Exception e) {
                report.println(tbAddr + ":   failed to write jump-table override: " + e);
            }
        }

        report.println(tbAddr + ": FIXED, bound=" + br.cmpInsn.getAddress() + " ("
                + br.cmpInsn.getMnemonicString() + ", " + (br.inclusive ? "inclusive" : "exclusive")
                + "), " + entries + " entries, " + okTargets + "/" + entries + " targets resolved, table ["
                + tableStart + "," + tableEnd + ")");
        return true;
    }

    private static class BoundResult {
        Instruction cmpInsn;
        long entries;
        boolean inclusive;
    }

    // Looks for the compiler-emitted bounds check that guards entry into the
    // scale+tbb/tbh block, in either of the two shapes described above.
    private BoundResult computeBoundedEntries(Address blockStart, String boundedReg) {
        Listing listing = currentProgram.getListing();

        // Shape (b): ordinary linear predecessor, taken branch goes
        // elsewhere (the default handler) -- reaching blockStart means the
        // compare's condition was NOT taken.
        Instruction pred = listing.getInstructionBefore(blockStart);
        if (pred != null && matchesReg(pred, boundedReg)) {
            boolean targetsBlock = false;
            for (Address f : pred.getFlows()) {
                if (f.equals(blockStart)) {
                    targetsBlock = true;
                    break;
                }
            }
            if (!targetsBlock) {
                BoundResult r = classify(pred, FALLTHROUGH_INCLUSIVE, FALLTHROUGH_EXCLUSIVE);
                if (r != null) {
                    return r;
                }
            }
        }

        // Shape (a): some instruction elsewhere branches directly into
        // blockStart when the index is in range.
        for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(blockStart)) {
            Instruction src = listing.getInstructionAt(ref.getFromAddress());
            if (src != null && matchesReg(src, boundedReg)) {
                BoundResult r = classify(src, TAKEN_INCLUSIVE, TAKEN_EXCLUSIVE);
                if (r != null) {
                    return r;
                }
            }
        }
        return null;
    }

    private boolean matchesReg(Instruction insn, String regName) {
        Register r = insn.getRegister(0);
        return r != null && r.getName().equals(regName);
    }

    private BoundResult classify(Instruction insn, Set<String> inclusiveSet, Set<String> exclusiveSet) {
        String mn = insn.getMnemonicString();
        boolean inclusive;
        if (inclusiveSet.contains(mn)) {
            inclusive = true;
        }
        else if (exclusiveSet.contains(mn)) {
            inclusive = false;
        }
        else {
            return null;
        }
        Scalar bound = null;
        for (int op = 0; op < insn.getNumOperands(); op++) {
            for (Object o : insn.getOpObjects(op)) {
                if (o instanceof Scalar) {
                    bound = (Scalar) o;
                }
            }
        }
        if (bound == null) {
            return null;
        }
        BoundResult r = new BoundResult();
        r.cmpInsn = insn;
        r.inclusive = inclusive;
        r.entries = inclusive ? bound.getUnsignedValue() + 1 : bound.getUnsignedValue();
        return r;
    }
}
