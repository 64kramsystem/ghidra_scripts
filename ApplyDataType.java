// Applies a named data type at a given address. Params via environment vars or defaults.
//
// @category 0Saverio/DosMalware

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Listing;

public class ApplyDataType extends GhidraScript {

  @Override
  protected void run() throws Exception {
    String name = (String) state.getEnvironmentVar("APPLY_DT_NAME");
    if (name == null)
      name = "BPB";
    String startAddrStr = (String) state.getEnvironmentVar("APPLY_DT_ADDR");
    if (startAddrStr == null)
      startAddrStr = "0f80:0402";

    Address startAddr = toAddr(startAddrStr);
    Listing listing = currentProgram.getListing();

    int txId = currentProgram.startTransaction("Apply data type");
    boolean success = false;

    try {
      DataType dt = currentProgram.getDataTypeManager().getDataType("/" + name);
      if (dt == null) {
        throw new RuntimeException("Data type not found: " + name);
      }

      listing.clearCodeUnits(startAddr, startAddr.add(dt.getLength() - 1), false);
      listing.createData(startAddr, dt);

      printf("Applied %s structure at %s\n", name, startAddr);
      success = true;
    } finally {
      currentProgram.endTransaction(txId, success);
    }
  }
}
