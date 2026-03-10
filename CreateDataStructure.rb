#@category Malware/DOS

java_import 'ghidra.program.model.data.StructureDataType'
java_import 'ghidra.program.model.data.ByteDataType'
java_import 'ghidra.program.model.data.WordDataType'
java_import 'ghidra.program.model.data.ArrayDataType'
java_import 'ghidra.program.model.data.CharDataType'
java_import 'ghidra.program.model.data.DataTypeConflictHandler'

tx_id = currentProgram.startTransaction("Create BPB structure")
success = false

begin
  dtm    = currentProgram.dataTypeManager
  struct = StructureDataType.new("BPB", 0)

  struct.add(ArrayDataType.new(CharDataType::dataType, 8, 1), "oem_name",           "OEM identifier")
  struct.add(WordDataType::dataType,                          "bytes_per_sector",    "")
  struct.add(ByteDataType::dataType,                          "sectors_per_cluster", "")
  struct.add(WordDataType::dataType,                          "reserved_sectors",    "")
  struct.add(ByteDataType::dataType,                          "fat_count",           "")
  struct.add(WordDataType::dataType,                          "root_entries",        "")
  struct.add(WordDataType::dataType,                          "total_sectors",       "")
  struct.add(ByteDataType::dataType,                          "media_descriptor",    "")
  struct.add(WordDataType::dataType,                          "sectors_per_fat",     "")
  struct.add(WordDataType::dataType,                          "sectors_per_track",   "")
  struct.add(WordDataType::dataType,                          "heads",               "")
  struct.add(WordDataType::dataType,                          "hidden_sectors",      "")

  # Register the type
  dt = dtm.addDataType(struct, nil)

  # Clean existing associations, and associate
  START_ADDR = toAddr("07c0:0003")
  currentProgram.listing.clearCodeUnits(START_ADDR, START_ADDR.add(struct.length - 1), false)
  currentProgram.listing.createData(START_ADDR, dt)

  puts "Created data structure"

  success = true
ensure
  currentProgram.endTransaction(tx_id, success)
end
