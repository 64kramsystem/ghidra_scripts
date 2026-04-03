// Creates a label at a hardcoded address.
//
// @category 0Saverio/DosMalware

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;

public class SetLabelAtArbitraryAddress extends GhidraScript {

  static final String ADDRESS = "0000:011f";
  static final String LABEL = "INT21_ORIGINAL_VECTOR_OFS";

  @Override
  protected void run() throws Exception {
    Address address = toAddr(ADDRESS);
    currentProgram.getSymbolTable().createLabel(
        address, LABEL, currentProgram.getGlobalNamespace(), SourceType.USER_DEFINED);
    printf("OK: labeled %s\n", address);
  }
}
