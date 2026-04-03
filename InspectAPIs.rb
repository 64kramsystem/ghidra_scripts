#@category 0Saverio/DosMalware

# Prints the Ruby APIs available in a RubyDragon Ghidra script, for reference.
# Run headlessly and feed the output to an LLM before writing scripts.

def section(title)
  puts "\n#{'=' * 60}"
  puts "# #{title}"
  puts '=' * 60
end

section "$current_api (RubyScript instance)"
puts "  java_class: #{$current_api.java_class}"

section "$current_api methods (ruby names)"
puts $current_api.methods.sort.map { |m| "  #{m}" }.join("\n")

section "currentProgram (#{currentProgram.java_class})"
puts currentProgram.methods.sort.map { |m| "  #{m}" }.join("\n")

section "currentProgram.getDomainFile (#{currentProgram.getDomainFile.java_class})"
puts currentProgram.getDomainFile.methods.sort.map { |m| "  #{m}" }.join("\n")

section "currentProgram.getDomainFile.getProjectLocator (#{currentProgram.getDomainFile.getProjectLocator.java_class})"
puts currentProgram.getDomainFile.getProjectLocator.methods.sort.map { |m| "  #{m}" }.join("\n")

section "Sample values"
dom  = currentProgram.getDomainFile
loc  = dom.getProjectLocator
puts "  currentProgram.getName              => #{currentProgram.getName}"
puts "  currentProgram.getExecutablePath    => #{currentProgram.getExecutablePath}"
puts "  getDomainFile.getName               => #{dom.getName}"
puts "  getDomainFile.getPathname           => #{dom.getPathname}"
puts "  getProjectLocator.getLocation       => #{loc.getLocation}"
puts "  getProjectLocator.getName           => #{loc.getName}"
puts "  getProjectLocator.getProjectDir     => #{loc.getProjectDir}"
