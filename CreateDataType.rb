#@category 0Saverio/DosMalware

java_import 'ghidra.program.model.data.StructureDataType'
java_import 'ghidra.program.model.data.ByteDataType'
java_import 'ghidra.program.model.data.WordDataType'
java_import 'ghidra.program.model.data.ArrayDataType'
java_import 'ghidra.program.model.data.CharDataType'
java_import 'ghidra.program.model.data.DataTypeConflictHandler'

NAME = "BPB"
FIELDS = [
  [ArrayDataType.new(CharDataType::dataType, 8, 1), "oem_name",           "OEM identifier"],
  [WordDataType::dataType,                          "bytes_per_sector",    ""],
  [ByteDataType::dataType,                          "sectors_per_cluster", ""],
  [WordDataType::dataType,                          "reserved_sectors",    ""],
  [ByteDataType::dataType,                          "fat_count",           ""],
  [WordDataType::dataType,                          "root_entries",        ""],
  [WordDataType::dataType,                          "total_sectors",       ""],
  [ByteDataType::dataType,                          "media_descriptor",    ""],
  [WordDataType::dataType,                          "sectors_per_fat",     ""],
  [WordDataType::dataType,                          "sectors_per_track",   ""],
  [WordDataType::dataType,                          "heads",               ""],
  [WordDataType::dataType,                          "hidden_sectors",      ""],
]
START_ADDR = toAddr("07c0:0003")

tx_id = currentProgram.startTransaction("Create and apply data type")
success = false

begin
  dtm    = currentProgram.dataTypeManager
  struct = StructureDataType.new(NAME, 0)

  FIELDS.each do |field_data|
    struct.add(*field_data)
  end

  # Register the type
  dtm.addDataType(struct, DataTypeConflictHandler::DEFAULT_HANDLER)

  puts "Created data type"

  $current_api.state.addEnvironmentVar("APPLY_DT_NAME", NAME)
  $current_api.state.addEnvironmentVar("APPLY_DT_ADDR", START_ADDR.toString)
  $script.runScript("ApplyDataType.rb")

  success = true
ensure
  currentProgram.endTransaction(tx_id, success)
end
