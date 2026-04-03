// Exports ASM listing and XML, then scrubs personal info from both.
//
// @category 0Saverio/General

import ghidra.app.script.GhidraScript;
import ghidra.app.util.exporter.AsciiExporter;
import ghidra.app.util.exporter.XmlExporter;
import ghidra.app.util.Option;
import java.io.File;
import java.nio.file.*;
import java.util.List;
import java.util.regex.Pattern;

public class ScrubAndExportProject extends GhidraScript {

  @Override
  protected void run() throws Exception {
    String projectDir = currentProgram.getDomainFile()
        .getProjectLocator().getLocation().toString();
    if (!projectDir.endsWith(File.separator)) {
      projectDir += File.separator;
    }
    String progName = currentProgram.getName();

    // Export ASM listing

    String asmPath = projectDir + progName + ".asm";

    AsciiExporter asmExporter = new AsciiExporter();
    List<Option> opts = asmExporter.getOptions(() -> currentProgram);
    for (Option opt : opts) {
      String name = opt.getName().trim();
      if (name.equals("Address"))
        opt.setValue(Integer.valueOf(25));
      else if (name.equals("Operand"))
        opt.setValue(Integer.valueOf(60));
      else if (name.equals("End of Line"))
        opt.setValue(Integer.valueOf(80));
    }
    asmExporter.setOptions(opts);
    asmExporter.export(new File(asmPath), currentProgram, null, monitor);

    String asmContent = Files.readString(Path.of(asmPath));
    asmContent = asmContent.replaceAll("(?m)\\s+$", "");
    Files.writeString(Path.of(asmPath), asmContent);

    printf("Listing exported to: %s\n", asmPath);

    // Export XML and scrub it

    String xmlPath = projectDir + progName + ".xml";

    new XmlExporter().export(new File(xmlPath), currentProgram, null, monitor);

    String homeDir = System.getProperty("user.home");
    String username = System.getProperty("user.name");
    String xmlContent = Files.readString(Path.of(xmlPath));
    xmlContent = xmlContent.replaceAll(Pattern.quote(homeDir) + "\\S*/", "/path/to/");
    xmlContent = xmlContent.replace(username, "myuser");
    xmlContent = xmlContent.replaceAll("(TIMESTAMP=\"[^\"]*?)\\d\\d:\\d\\d:\\d\\d", "$100:00:00");
    Files.writeString(Path.of(xmlPath), xmlContent);

    printf("XML exported to: %s\n", xmlPath);
  }
}
