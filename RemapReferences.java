// Remaps references from one address range to another.
// Useful when Ghidra doesn't know the actual value of a segment register and creates references in
// the wrong segment.
//
// @category 0Saverio/DosMalware

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;
import java.util.ArrayList;
import java.util.List;

public class RemapReferences extends GhidraScript {

  @Override
  protected void run() throws Exception {
    String[] args = getScriptArgs();
    String fromStart = args.length > 0 ? args[0] : "0000:8000";
    String fromEnd = args.length > 1 ? args[1] : "0000:81ff";
    String toAddress = args.length > 2 ? args[2] : "07c0:8000";
    boolean commit = true;

    Address startAddr = toAddr(fromStart);
    Address endAddr = toAddr(fromEnd);
    Address targetBase = toAddr(toAddress);
    ReferenceManager refManager = currentProgram.getReferenceManager();

    int txId = currentProgram.startTransaction("Remap references");
    boolean success = false;

    try {
      Address addr = startAddr;
      while (addr.compareTo(endAddr) <= 0) {
        List<Reference> refs = new ArrayList<>();
        refManager.getReferencesTo(addr).forEachRemaining(refs::add);
        if (!refs.isEmpty()) {
          Address targetAddr = targetBase.add(addr.getOffset() - startAddr.getOffset());
          for (Reference ref : refs) {
            Address from = ref.getFromAddress();
            RefType type = ref.getReferenceType();
            int op = ref.getOperandIndex();
            refManager.delete(ref);
            refManager.addMemoryReference(from, targetAddr, type, SourceType.USER_DEFINED, op);
          }
          printf("Remapped %s -> %s (%d ref%s)\n", addr, targetAddr, refs.size(), refs.size() == 1 ? "" : "s");
        }
        addr = addr.add(1);
      }
      success = commit;
    } finally {
      currentProgram.endTransaction(txId, success);
    }
  }
}
