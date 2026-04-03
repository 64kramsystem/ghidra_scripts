#@category 0Saverio/DosMalware

java_import 'ghidra.app.util.exporter.AsciiExporter'
java_import 'ghidra.app.util.exporter.XmlExporter'
java_import 'ghidra.app.util.Option'
java_import 'ghidra.util.task.TaskMonitor'
java_import 'java.io.File'

project_dir = currentProgram.getDomainFile.getProjectLocator.getLocation

# Export ASM listing

asm_path = "#{project_dir}#{currentProgram.getName}.asm"

asm_exporter = AsciiExporter.new
asm_exporter.get_options { currentProgram }
asm_exporter.set_options([
  Option.new('Field Widths', ' Address ',     java.lang.Integer.new(25)),
  Option.new('Field Widths', ' Operand ',     java.lang.Integer.new(60)),
  Option.new('Field Widths', ' End of Line ', java.lang.Integer.new(80)),
])
asm_exporter.export(File.new(asm_path), currentProgram, nil, TaskMonitor::DUMMY)

processed_asm = IO
  .read(asm_path)
  .gsub(/\s+$/, '')

IO.write(asm_path, processed_asm)

puts "Listing exported to: #{asm_path}"

# Export XML and scrub it

xml_path = "#{project_dir}#{currentProgram.getName}.xml"

XmlExporter.new.export(File.new(xml_path), currentProgram, nil, TaskMonitor::DUMMY)

# Watch out the `\S` - `.` would eat the closing tag.
processed_xml = IO
  .read(xml_path)
  .gsub(%r{#{Dir.home}\S*/}, '/path/to/')
  .gsub(Etc.getlogin, 'myuser')
  .gsub(/TIMESTAMP=".+?\K\d\d:\d\d:\d\d/, '00:00:00')

IO.write(xml_path, processed_xml)

puts "XML exported to: #{xml_path}"
