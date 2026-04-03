// Creates a BPB struct data type and applies it.
//
// @category 0Saverio/DosMalware

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class CreateDataType extends GhidraScript {

  static final String NAME = "BPB";
  static final String START_ADDR = "07c0:0003";

  @Override
  protected void run() throws Exception {
    int txId = currentProgram.startTransaction("Create and apply data type");
    boolean success = false;

    try {
      StructureDataType struct = new StructureDataType(NAME, 0);
      struct.add(new ArrayDataType(CharDataType.dataType, 8, 1), "oem_name", "OEM identifier");
      struct.add(WordDataType.dataType, "bytes_per_sector", "");
      struct.add(ByteDataType.dataType, "sectors_per_cluster", "");
      struct.add(WordDataType.dataType, "reserved_sectors", "");
      struct.add(ByteDataType.dataType, "fat_count", "");
      struct.add(WordDataType.dataType, "root_entries", "");
      struct.add(WordDataType.dataType, "total_sectors", "");
      struct.add(ByteDataType.dataType, "media_descriptor", "");
      struct.add(WordDataType.dataType, "sectors_per_fat", "");
      struct.add(WordDataType.dataType, "sectors_per_track", "");
      struct.add(WordDataType.dataType, "heads", "");
      struct.add(WordDataType.dataType, "hidden_sectors", "");

      currentProgram.getDataTypeManager().addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER);
      println("Created data type");

      state.addEnvironmentVar("APPLY_DT_NAME", NAME);
      state.addEnvironmentVar("APPLY_DT_ADDR", toAddr(START_ADDR).toString());
      runScript("ApplyDataType.java");

      success = true;
    } finally {
      currentProgram.endTransaction(txId, success);
    }
  }
}
