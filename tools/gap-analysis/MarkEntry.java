// Tiny headless -preScript: labels and disassembles a program's real entry
// point before auto-analysis runs, and creates a function there named
// "entry" so downstream scripts (DecompileAll.java, the normal Function
// Manager) have a real starting point instead of relying on auto-analysis's
// own (often wrong, for a raw BinaryLoader image with no header) entry-point
// guessing.
//
// Used as the first stage of the full-decompile export pipeline for a raw
// pi32v2 app.bin image -- see DecompileAll.java in this directory and
// keysmith's research/decompile/REEXPORT_NOTES_20260917.md for the full
// three-script headless recipe (MarkEntry -> auto-analysis ->
// FixTbbTbhTables -> DecompileAll).
//
// Usage (as a -preScript, before normal auto-analysis):
//   -preScript MarkEntry.java <entry-address-hex-no-0x-prefix>
// Defaults to 2000120 (this project's baseline chip-variant-A load address)
// if no argument is given.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;

public class MarkEntry extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String entryHex = getScriptArgs().length > 0 ? getScriptArgs()[0] : "2000120";
        Address entry = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseLong(entryHex, 16));
        currentProgram.getSymbolTable().createLabel(entry, "entry", SourceType.USER_DEFINED);
        disassemble(entry);
        createFunction(entry, "entry");
        println("Marked entry function at " + entry);
    }
}
