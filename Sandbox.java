// @category 0Saverio/DosMalware

import ghidra.app.script.GhidraScript;

public class Sandbox extends GhidraScript {

  @Override
  protected void run() throws Exception {
    for (int i = 0; i < 10; i++) {
      println(String.valueOf(i));
    }
  }
}
