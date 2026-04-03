// Annotates The Neverending Story sentence data:
// - Creates string data types for ASCII text runs (excluding opcodes >= $80 and terminator '@')
// - Adds SENTENCE_XX labels at each sentence start
// - Adds xrefs from the pointer table to each sentence
//
// Transaction rolls back by default (test mode). Set `commit = true` to apply.
//
// @category 0Saverio/C64

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;

public class AnnotateNESentences extends GhidraScript {

  static final long TABLE_START = 0x1CB0;
  static final int NUM_ENTRIES = 68;
  static final int TERMINATOR = 0x40; // '@'

  static final boolean commit = true;

  static final String[] LABELS = {
      "SENT_DONT_UNDERSTAND_WORD", // 00
      "SENT_NO_VERB", // 01
      "SENT_CANT_GO", // 02
      "SENT_CANT_DO", // 03
      "SENT_OPCODE_04", // 04
      "SENT_OPCODE_05", // 05
      "SENT_LYING_GROUND", // 06
      "SENT_HERE", // 07
      "SENT_DONT_SEE_IT", // 08
      "SENT_ALREADY_CARRYING", // 09
      "SENT_NOT_CARRYING", // 10
      "SENT_FULL_LOAD", // 11
      "SENT_TAKEN", // 12
      "SENT_DROPPED", // 13
      "SENT_CARRYING_FOLLOWING", // 14
      "SENT_OPCODE_15", // 15
      "SENT_OPCODE_16", // 16
      "SENT_ERROR_RETRY", // 17
      "SENT_ERROR", // 18
      "SENT_WAIT", // 19
      "SENT_WITH_YOU_1", // 20
      "SENT_WITH_YOU_2", // 21
      "SENT_HES_NOT", // 22
      "SENT_HES_NOT_WITH", // 23
      "SENT_FOOD_RESTORES", // 24
      "SENT_NO_NOUN", // 25
      "SENT_GO_ALONE", // 26
      "SENT_VERY_WEAK", // 27
      "SENT_TOO_WEAK_CONSUMED", // 28
      "SENT_PAUSED", // 29
      "SENT_THEYRE_NOT", // 30
      "SENT_OK", // 31
      "SENT_HOW", // 32
      "SENT_NOT_EFFECTIVE", // 33
      "SENT_HAPPENS", // 34
      "SENT_APPEARS", // 35
      "SENT_NOTHING_TO_CLIMB", // 36
      "SENT_DONT_UNDERSTAND", // 37
      "SENT_CANT_FLY", // 38
      "SENT_NOTHING_TO_RIDE", // 39
      "SENT_SMASH_FIRST", // 40
      "SENT_FRAGMENT_SHARP", // 41
      "SENT_BOX_SHATTERS", // 42
      "SENT_TOO_TOUGH", // 43
      "SENT_FLIES_ACROSS", // 44
      "SENT_CUT_YOURSELF", // 45
      "SENT_RESTORE_GAME", // 46
      "SENT_HIT_SPACE_LOAD", // 47
      "SENT_PART_ONE", // 48
      "SENT_PART_TWO", // 49
      "SENT_PART_THREE", // 50
      "SENT_OLD_GAME", // 51
      "SENT_ARE_SURE", // 52
      "SENT_GAME_OVER", // 53
      "SENT_APPLE_DESTROYS_POISON", // 54
      "SENT_HUH", // 55
      "SENT_NOT_A_CHANCE", // 56
      "SENT_NOTHING_TO_CUT", // 57
      "SENT_PAPER_ADVERT", // 58
      "SENT_BOOK_HISTORY", // 59
      "SENT_ALREADY_OPEN", // 60
      "SENT_ALREADY_CLOSED", // 61
      "SENT_TIN_WHITE_POWDER", // 62
      "SENT_TOO_DARK", // 63
      "SENT_POISON_WEAKENING", // 64
      "SENT_GRABS_STRANGLES", // 65
      "SENT_WILL_HELP_BEARER", // 66
      "SENT_ENTER_FILENAME", // 67
  };

  @Override
  protected void run() throws Exception {
    Memory memory = currentProgram.getMemory();
    Listing listing = currentProgram.getListing();
    SymbolTable symbolTable = currentProgram.getSymbolTable();
    ReferenceManager refManager = currentProgram.getReferenceManager();

    int txId = currentProgram.startTransaction("Annotate NE Sentences");
    boolean success = false;

    try {
      for (int i = 0; i < NUM_ENTRIES; i++) {
        Address ptrAddr = toAddr(TABLE_START + i * 2);
        int lo = memory.getByte(ptrAddr) & 0xFF;
        int hi = memory.getByte(ptrAddr.add(1)) & 0xFF;
        long sentOffset = lo | (hi << 8);
        Address sentAddr = toAddr(sentOffset);

        printf("=== Entry %02d: table=$%04X -> sentence=$%04X ===\n", i, TABLE_START + i * 2, sentOffset);

        // Label
        String label = LABELS[i];
        symbolTable.createLabel(sentAddr, label, SourceType.USER_DEFINED);
        printf("  Label: %s at $%04X\n", label, sentOffset);

        // Xref
        refManager.addMemoryReference(ptrAddr, sentAddr, RefType.DATA, SourceType.USER_DEFINED, 0);
        printf("  Xref: $%04X -> $%04X\n", TABLE_START + i * 2, sentOffset);

        // Walk sentence bytes, create strings for ASCII runs
        Address pos = sentAddr;
        Address asciiStart = null;
        StringBuilder decoded = new StringBuilder();
        int stringCount = 0;

        while (true) {
          int b = memory.getByte(pos) & 0xFF;

          if (b == TERMINATOR) {
            if (asciiStart != null) {
              int length = (int) (pos.getOffset() - asciiStart.getOffset());
              listing.clearCodeUnits(asciiStart, asciiStart.add(length - 1), false);
              createAsciiString(asciiStart, length);
              stringCount++;
              printf("  String #%d at $%04X, len=%d\n", stringCount, asciiStart.getOffset(), length);
              asciiStart = null;
            }
            decoded.append(" [@]");
            printf("  Terminator '@' at $%04X\n", pos.getOffset());
            break;

          } else if (b >= 0x80) {
            if (asciiStart != null) {
              int length = (int) (pos.getOffset() - asciiStart.getOffset());
              listing.clearCodeUnits(asciiStart, asciiStart.add(length - 1), false);
              createAsciiString(asciiStart, length);
              stringCount++;
              printf("  String #%d at $%04X, len=%d\n", stringCount, asciiStart.getOffset(), length);
              asciiStart = null;
            }
            decoded.append(String.format(" [%02Xh]", b));
            printf("  Opcode $%02X at $%04X\n", b, pos.getOffset());

          } else {
            if (asciiStart == null) {
              asciiStart = pos;
            }
            decoded.append((char) b);
          }

          pos = pos.add(1);
        }

        long sentEnd = pos.getOffset();
        long totalBytes = sentEnd - sentOffset + 1;
        printf("  Total bytes: %d (from $%04X to $%04X)\n", totalBytes, sentOffset, sentEnd);
        printf("  Strings created: %d\n", stringCount);
        printf("  Decoded: %s\n\n", decoded.toString().trim());
      }

      printf("============================================================\n");
      printf("Processed %d entries.\n\n", NUM_ENTRIES);

      success = commit;

    } finally {
      currentProgram.endTransaction(txId, success);
      if (success) {
        println(">>> Changes COMMITTED <<<");
      } else {
        println(">>> Changes ROLLED BACK (test mode) <<<");
        println("    Set commit = true to apply.");
      }
    }
  }
}
