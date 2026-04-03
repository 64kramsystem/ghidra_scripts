#@category 0Saverio/DosMalware

java_import 'ghidra.program.model.symbol.SourceType'

ADDRESS = "0000:011f"
LABEL = "INT21_ORIGINAL_VECTOR_OFS"

symbol_table = currentProgram.getSymbolTable
namespace    = currentProgram.getGlobalNamespace

address = toAddr(ADDRESS)

symbol_table.createLabel(address, LABEL, namespace, SourceType::USER_DEFINED)

puts "OK: labeled #{address}"
