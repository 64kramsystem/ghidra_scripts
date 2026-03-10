#@category Malware/DOS

NEW_SEGMENT = "07c0"

tx_id = currentProgram.start_transaction("Remap 0000:8xxx references")
success = false

begin
  ref_manager = currentProgram.reference_manager
  start_addr  = toAddr("0000:8000")
  end_addr    = toAddr("0000:81ff")

  addr = start_addr
  while addr <= end_addr
    refs = ref_manager.get_references_to(addr).to_a   # snapshot to avoid iterator mutation
    unless refs.empty?
      # Compute the equivalent address in the virus segment (07c0)
      target_addr = toAddr("#{NEW_SEGMENT}:#{"%04x" % addr.segment_offset}")
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
