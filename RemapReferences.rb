#@category Malware/DOS

# Useful when Ghidra doesn't know the actual value of a segment register and creates references in
# the wrong segment.

args = begin; getScriptArgs; rescue NameError; []; end

# PARAMS ###########################################################################################

from_address_start = args[0] || "0000:8000"
from_address_end   = args[1] || "0000:81ff"
to_address         = args[2] || "07c0:8000"
commit             = true

####################################################################################################

java_import 'ghidra.program.model.symbol.SourceType'

tx_id = currentProgram.start_transaction("Remap references")
success = false

begin
  ref_manager = currentProgram.reference_manager
  start_addr  = toAddr(from_address_start)
  end_addr    = toAddr(from_address_end)
  to_addr     = toAddr(to_address)

  addr = start_addr
  while addr <= end_addr
    refs = ref_manager.get_references_to(addr).to_a   # snapshot to avoid iterator mutation
    unless refs.empty?
      target_addr = to_addr.add(addr.offset - start_addr.offset)
      refs.each do |ref|
        from = ref.from_address
        type = ref.reference_type
        op   = ref.operand_index
        ref_manager.delete(ref)
        ref_manager.add_memory_reference(from, target_addr, type, SourceType::USER_DEFINED, op)
      end
      puts "Remapped #{addr} -> #{target_addr} (#{refs.size} ref#{refs.size == 1 ? '' : 's'})"
    end
    addr = addr.add(1)
  end

  success = commit
ensure
  currentProgram.end_transaction(tx_id, success)
end
