// Headless -postScript: decompiles every function auto-analysis found to a
// single ordered pseudo-C text dump, with a clear per-function
// "// FUNCTION <name> @ 0x<addr> (size=N bytes)" banner, and separately
// dumps a plain linear disassembly listing alongside it -- since the
// decompiler silently drops/simplifies real detail (e.g. delay-slot
// pairing, exact instruction-level control flow) that the raw disassembly
// still shows.
//
// This is the last stage of the full-decompile export pipeline used to
// produce a Kimi-ready decompile handoff for a whole firmware image; see
// MarkEntry.java (first stage, in this directory) and
// keysmith's research/decompile/REEXPORT_NOTES_20260917.md for the full
// recipe and worked example (MarkEntry -> auto-analysis -> FixTbbTbhTables
// -> DecompileAll). Run FixTbbTbhTables.java as a -postScript *before* this
// one -- it fixes function-boundary corruption from unbounded tbb/tbh jump
// tables that otherwise makes some of this script's output badly wrong
// (functions absorbing tens of KB of unrelated downstream code).
//
// Usage (as a -postScript, after auto-analysis and after FixTbbTbhTables):
//   -postScript DecompileAll.java <decompiled-C-out-path> <disasm-out-path>
// Defaults to /tmp/decompiled_all.c and /tmp/disasm_all.txt if omitted.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.BufferedWriter;
import java.io.FileWriter;

public class DecompileAll extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String cOutPath = getScriptArgs().length > 0 ? getScriptArgs()[0] : "/tmp/decompiled_all.c";
        String asmOutPath = getScriptArgs().length > 1 ? getScriptArgs()[1] : "/tmp/disasm_all.txt";

        DecompInterface decomp = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decomp.setOptions(options);
        decomp.openProgram(currentProgram);

        int total = 0;
        int ok = 0;
        int failed = 0;

        try (BufferedWriter w = new BufferedWriter(new FileWriter(cOutPath))) {
            FunctionIterator fiter = currentProgram.getListing().getFunctions(true);
            while (fiter.hasNext() && !monitor.isCancelled()) {
                Function f = fiter.next();
                total++;
                w.write("// ==========================================================\n");
                w.write(String.format("// FUNCTION %s @ 0x%s  (size=%d bytes)\n",
                        f.getName(), f.getEntryPoint(), (int) f.getBody().getNumAddresses()));
                w.write("// ==========================================================\n");
                DecompileResults res = decomp.decompileFunction(f, 60, new ConsoleTaskMonitor());
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    w.write(res.getDecompiledFunction().getC());
                    ok++;
                } else {
                    String err = res != null ? res.getErrorMessage() : "null result";
                    w.write("// DECOMPILE FAILED: " + err.replace("\n", " ") + "\n");
                    failed++;
                }
                w.write("\n\n");
                if (total % 200 == 0) {
                    println("Decompiled " + total + " functions so far (" + ok + " ok, " + failed + " failed)...");
                }
            }
        }
        decomp.dispose();

        try (BufferedWriter w = new BufferedWriter(new FileWriter(asmOutPath))) {
            InstructionIterator iiter = currentProgram.getListing().getInstructions(true);
            while (iiter.hasNext() && !monitor.isCancelled()) {
                Instruction instr = iiter.next();
                w.write(String.format("%s\t%s%n", instr.getAddress(), instr.toString()));
            }
        }

        println("TOTAL FUNCTIONS: " + total + "  OK: " + ok + "  FAILED: " + failed);
        println("Wrote decompiled C to " + cOutPath);
        println("Wrote disassembly to " + asmOutPath);
    }
}
