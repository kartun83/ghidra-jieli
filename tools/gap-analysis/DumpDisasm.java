// Dump a linear disassembly listing of the .text/code memory to a file
// for diffing against the LLVM ground-truth objdump listing.
// Format per line: <hexaddr>\t<lengthOrErr>\t<mnemonic+operands or ERROR message>

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.disassemble.Disassembler;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.BufferedWriter;
import java.io.FileWriter;

// Full linear-sweep forced disassembly over the whole executable block.
//
// IMPORTANT METHODOLOGY NOTE: an earlier version of this script forced
// disassembly one address at a time with an AddressSet restricted to that
// single address. That approach produced large numbers of false-positive
// "BAD" results for pi32v2's delay-slot / parallel-issue constructs (the
// SLEIGH pcode builder needs to read bytes *past* the current instruction to
// resolve a following delay-slot instruction; restricting the address set to
// a single address made that lookahead fail with
// "Program does not contain referenced instruction" pcode errors, which are
// an artifact of the restricted range, not a real decode gap).
//
// This version seeds every address in the block as a candidate instruction
// start but disassembles them all in a single batched call with the full
// memory available (no restrictSet truncation), letting Ghidra's normal
// address-ordered seed processing (skipping addresses already consumed by an
// earlier instruction) do a proper linear sweep, exactly like objdump's own
// linear disassembly -- and with delay slots resolved correctly.
public class DumpDisasm extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String outPath = getScriptArgs().length > 0 ? getScriptArgs()[0]
                : "/tmp/ghidra_disasm_dump.txt";

        Disassembler disassembler = Disassembler.getDisassembler(currentProgram, new ConsoleTaskMonitor(), null);

        try (BufferedWriter w = new BufferedWriter(new FileWriter(outPath))) {
            for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
                if (!block.isInitialized()) {
                    continue;
                }
                Address start = block.getStart();
                Address end = block.getEnd();
                AddressSetView blockSet = new AddressSet(start, end);

                // Seed every address in the block; Ghidra will skip seeds that
                // fall inside an instruction already disassembled from an
                // earlier (lower-address) seed, giving a linear sweep.
                println("Disassembling block " + block.getName() + " " + start + "-" + end);
                disassembler.disassemble(blockSet, blockSet, false);

                Address addr = start;
                while (addr != null && addr.compareTo(end) <= 0) {
                    Instruction instr = currentProgram.getListing().getInstructionAt(addr);
                    if (instr != null) {
                        int len = instr.getLength();
                        String text = instr.toString();
                        w.write(String.format("%08x\t%d\tOK\t%s%n", addr.getOffset(), len, text.replace("\t", " ")));
                        addr = addr.add(len);
                        continue;
                    }
                    w.write(String.format("%08x\t%d\tBAD\t%s%n", addr.getOffset(), 1, "bad-instruction"));
                    addr = addr.add(1);
                }
            }
        }
        println("Wrote disasm dump to " + outPath);
    }
}
