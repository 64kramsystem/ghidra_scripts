#@category Malware/DOS

# PARAMS ###########################################################################################

name       = $current_api.state.getEnvironmentVar("APPLY_DT_NAME") || "BPB"
start_addr = $current_api.state.getEnvironmentVar("APPLY_DT_ADDR") || "0f80:0402"

####################################################################################################

start_addr = toAddr(start_addr)

tx_id = currentProgram.startTransaction("Apply data type")
success = false

begin
  dtm = currentProgram.dataTypeManager
  dt  = dtm.getDataType("/#{name}") || raise("Data type not found")

  currentProgram.listing.clearCodeUnits(start_addr, start_addr.add(dt.length - 1), false)
  currentProgram.listing.createData(start_addr, dt)

  puts "Applied #{name} structure at #{start_addr}"

  success = true
ensure
  currentProgram.endTransaction(tx_id, success)
end
