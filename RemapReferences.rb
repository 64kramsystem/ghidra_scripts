#@category Malware/DOS

# PARAMS ###########################################################################################

from_segment   = getScriptArgs[0] || "0000"
to_segment     = getScriptArgs[1] || "07c0"
start_offset   = getScriptArgs[2] || "8000"
end_offset     = getScriptArgs[3] || "81ff"

####################################################################################################

tx_id = currentProgram.start_transaction("Remap #{from_segment}:#{start_offset}-#{end_offset} references to #{to_segment}")
success = false

begin
  ref_manager = currentProgram.reference_manager
  start_addr  = toAddr("#{from_segment}:#{start_offset}")
  end_addr    = toAddr("#{from_segment}:#{end_offset}")

  addr = start_addr
  while addr <= end_addr
    refs = ref_manager.get_references_to(addr).to_a   # snapshot to avoid iterator mutation
    unless refs.empty?
      # Compute the equivalent address in the virus segment (07c0)
      target_addr = toAddr("#{to_segment}:#{"%04x" % addr.segment_offset}")
      refs.each do |ref|
        # Add new reference pointing to the correct segment
        ref_manager.add_memory_reference(
          ref.from_address,
          target_addr,
          ref.reference_type,   # preserve original ref type (read/write/data)
          SourceType::USER_DEFINED,
          ref.operand_index     # preserve which operand the ref belongs to
        )
        ref_manager.delete(ref)
      end
      puts "Remapped #{addr} -> #{target_addr} (#{refs.size} ref#{refs.size == 1 ? '' : 's'})"
    end
    addr = addr.next   # advance one byte at a time
  end

  success = true
ensure
  # Rollback on exception
  currentProgram.end_transaction(tx_id, success)
end
