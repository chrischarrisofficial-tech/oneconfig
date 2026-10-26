package oneconfig;

import java.nio.file.*;
import java.util.*;
import org.antlr.v4.runtime.*;

/**
 * Parse a config with Batfish's NX-OS, Arista, flat Junos or ASA grammar and print every line it rejects as "line text<TAB>reason".
 * An error throws the lexer off for the rest of the file, so: report the first rejected line, remove it (with the
 * child lines of a block it opens), parse again, until clean. Exit status 1 if anything was rejected.
 */
public final class Check {
  /** First problem as {line number (1-based), message}, or null when the text parses cleanly. */
  static String[] firstError(String vendor, String text) {
    List<String[]> errs = new ArrayList<>();
    BaseErrorListener l = new BaseErrorListener() {
      @Override public void syntaxError(Recognizer<?, ?> r, Object o, int line, int col, String msg, RecognitionException e) {
        errs.add(new String[] {String.valueOf(line), msg});
      }
    };
    CharStream cs = CharStreams.fromString(text);
    ParserRuleContext root;
    if (vendor.equals("nxos")) {
      var lx = new org.batfish.vendor.cisco_nxos.grammar.CiscoNxosLexer(cs);
      lx.removeErrorListeners(); lx.addErrorListener(l);
      var p = new org.batfish.vendor.cisco_nxos.grammar.CiscoNxosParser(new CommonTokenStream(lx));
      p.removeErrorListeners(); p.addErrorListener(l);
      root = p.cisco_nxos_configuration();
    } else if (vendor.equals("junos")) {
      var lx = new org.batfish.grammar.flatjuniper.FlatJuniperLexer(cs);
      lx.removeErrorListeners(); lx.addErrorListener(l);
      var p = new org.batfish.grammar.flatjuniper.FlatJuniperParser(new CommonTokenStream(lx));
      p.removeErrorListeners(); p.addErrorListener(l);
      root = p.flat_juniper_configuration();
    } else if (vendor.equals("asa")) {
      var lx = new org.batfish.grammar.cisco_asa.AsaLexer(cs);
      lx.removeErrorListeners(); lx.addErrorListener(l);
      var p = new org.batfish.grammar.cisco_asa.AsaParser(new CommonTokenStream(lx));
      p.removeErrorListeners(); p.addErrorListener(l);
      root = p.asa_configuration();
    } else {
      var lx = new org.batfish.vendor.arista.grammar.AristaLexer(cs);
      lx.removeErrorListeners(); lx.addErrorListener(l);
      var p = new org.batfish.vendor.arista.grammar.AristaParser(new CommonTokenStream(lx));
      p.removeErrorListeners(); p.addErrorListener(l);
      root = p.arista_configuration();
    }
    // An indented line that starts its own top-level statement was not accepted inside its block:
    // the grammar silently ended the block there.
    String[] lines = text.split("\n", -1);
    for (int i = 0; i < root.getChildCount(); i++) {
      if (!(root.getChild(i) instanceof ParserRuleContext)) continue;
      Token t = ((ParserRuleContext) root.getChild(i)).getStart();
      if (t == null || t.getType() == Token.EOF) continue;
      String s = lines[t.getLine() - 1];
      if (!s.isEmpty() && Character.isWhitespace(s.charAt(0)) && t.getCharPositionInLine() == s.indexOf(s.trim()))
        errs.add(new String[] {String.valueOf(t.getLine()), "not valid inside its block (parsed as a new top-level statement)"});
    }
    return errs.stream().min(Comparator.comparingInt(e -> Integer.parseInt(e[0]))).orElse(null);
  }

  static int indent(String s) { return s.length() - s.stripLeading().length(); }

  public static void main(String[] a) throws Exception {
    List<String> lines = new ArrayList<>();
    for (String s : Files.readAllLines(Paths.get(a[1]))) if (!s.isBlank()) lines.add(s);
    boolean bad = false;
    for (int round = 0; round < 500; round++) {
      String[] e = firstError(a[0], String.join("\n", lines) + "\n");
      if (e == null) break;
      bad = true;
      int n = Math.max(0, Math.min(Integer.parseInt(e[0]), lines.size()) - 1);
      System.out.println(lines.get(n) + "\t" + e[1].replace("\n", "\\n").replace("\t", " "));
      int end = n + 1;
      while (end < lines.size() && indent(lines.get(end)) > indent(lines.get(n))) end++;
      lines.subList(n, end).clear();
    }
    System.exit(bad ? 1 : 0);
  }
}
