#@category Malware/DOS

java_import 'ghidra.program.model.symbol.SourceType'

symbol_table = currentProgram.getSymbolTable
namespace    = currentProgram.getGlobalNamespace

address = toAddr("07c0:012A")

symbol_table.createLabel(address, "INT13_ORIGINAL_VECTOR_OFS", namespace, SourceType::USER_DEFINED)

puts "OK: labeled #{address}"
