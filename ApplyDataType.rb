#@category Malware/DOS

args = begin; getScriptArgs; rescue NameError; []; end

# PARAMS ###########################################################################################

name       = args[0] || "BPB"
start_addr = args[1] || "0f80:0402"

####################################################################################################

start_addr = toAddr(start_addr)

tx_id = currentProgram.startTransaction("Apply data type")
success = false

begin
  dtm = currentProgram.dataTypeManager
  dt  = dtm.getDataType("/#{name}") || raise("Data type not found")

  currentProgram.listing.clearCodeUnits(start_addr, start_addr.add(dt.length - 1), false)
  currentProgram.listing.createData(start_addr, dt)

  puts "Applied BPB structure at #{start_addr}"

  success = true
ensure
  currentProgram.endTransaction(tx_id, success)
end
