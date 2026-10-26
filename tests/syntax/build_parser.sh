#!/usr/bin/env bash
# Build Batfish's NX-OS, Arista EOS, Junos (flat "set" format) and Cisco ASA parsers (from its ANTLR grammars) for tests/test_syntax.py.
# Needs: git, a JDK, ANTLR 4 and Guava (Debian/Ubuntu: apt-get install default-jdk antlr4 libantlr4-runtime-java libguava-java).
# Output: ~/.cache/oneconfig-bfparse/classes (override with ONECONFIG_BATFISH_PARSER=<somewhere>/oneconfig-bfparse/classes)
set -euo pipefail
COMMIT=cf100e56c06c306b4a7e3b1150cc4a34504316d6   # batfish/batfish, the version the tests were written against
OUT=$(dirname "${ONECONFIG_BATFISH_PARSER:-$HOME/.cache/oneconfig-bfparse/classes}")
HERE=$(cd "$(dirname "$0")" && pwd)
J=/usr/share/java
case "$OUT" in */oneconfig-bfparse) ;; *) echo "refusing to delete $OUT: the folder above classes/ must be named oneconfig-bfparse" >&2; exit 1;; esac
rm -rf "$OUT" && mkdir -p "$OUT" && cd "$OUT"
git init -q bf && cd bf && git remote add origin https://github.com/batfish/batfish
git sparse-checkout set --no-cone /projects/common/src/main/java/org/batfish/grammar/ \
  '/projects/batfish/src/main/antlr4/org/batfish/vendor/cisco_nxos/grammar/' '/projects/batfish/src/main/antlr4/org/batfish/vendor/arista/grammar/' \
  '/projects/batfish/src/main/java/org/batfish/vendor/cisco_nxos/grammar/CiscoNxosBase*.java' \
  '/projects/batfish/src/main/java/org/batfish/vendor/arista/grammar/AristaBase*.java' \
  '/projects/batfish/src/main/antlr4/org/batfish/grammar/flatjuniper/' '/projects/batfish/src/main/java/org/batfish/grammar/flatjuniper/parsing/FlatJuniperBaseLexer.java' \
  '/projects/batfish/src/main/antlr4/org/batfish/grammar/cisco_asa/' '/projects/batfish/src/main/java/org/batfish/grammar/cisco_asa/parsing/AsaBase*.java'
git fetch -q --depth 1 --filter=blob:none origin "$COMMIT" && git checkout -q FETCH_HEAD
cd "$OUT" && mkdir -p src/org/batfish/grammar src/org/batfish/vendor src/javax/annotation src/oneconfig classes
for a in Nullable Nonnull ParametersAreNonnullByDefault; do
  printf 'package javax.annotation;\nimport java.lang.annotation.*;\n@Retention(RetentionPolicy.CLASS)\npublic @interface %s {}\n' $a > src/javax/annotation/$a.java
done
G=bf/projects/common/src/main/java/org/batfish/grammar
cp $G/BatfishLexer.java $G/BatfishParser.java $G/BatfishLexerRecoveryStrategy.java src/org/batfish/grammar/
mkdir -p src/org/batfish/grammar/flatjuniper/parsing src/org/batfish/grammar/cisco_asa/parsing
cp bf/projects/batfish/src/main/java/org/batfish/grammar/flatjuniper/parsing/FlatJuniperBaseLexer.java src/org/batfish/grammar/flatjuniper/parsing/
cp bf/projects/batfish/src/main/java/org/batfish/grammar/cisco_asa/parsing/AsaBase*.java src/org/batfish/grammar/cisco_asa/parsing/
# Keep only what a plain ANTLR parse needs: drop Batfish's own error-reporting hooks.
python3 - <<'PY'
import re
for f, pats in (("src/org/batfish/grammar/BatfishLexer.java", [r"\n  public void initErrorListener\(BatfishCombinedParser<\?, \?> parser\) \{.*?\n  \}\n", r"  private BatfishCombinedParser<\?, \?> _parser;\n", r"    _parser\.updateTokenModes\(_mode\);\n"]),
                ("src/org/batfish/grammar/BatfishParser.java", [r"\n  public void initErrorListener\(BatfishCombinedParser<\?, \?> parser\) \{.*?\n  \}\n", r"\n  public void createErrorNodeLine\(\) \{.*?\n  \}\n"])):
    s = open(f).read()
    for p in pats:
        s = re.sub(p, "\n", s, flags=re.S)
    open(f, "w").write(s)
PY
cp -r bf/projects/batfish/src/main/java/org/batfish/vendor/cisco_nxos bf/projects/batfish/src/main/java/org/batfish/vendor/arista src/org/batfish/vendor/
cp "$HERE/Check.java" src/oneconfig/
TOOL="$J/antlr4.jar:$J/antlr4-runtime.jar:$J/antlr3-runtime.jar:$J/stringtemplate4.jar"
A=bf/projects/batfish/src/main/antlr4/org/batfish
for v in vendor/cisco_nxos/grammar vendor/arista/grammar grammar/flatjuniper grammar/cisco_asa; do
  pkg=org.batfish.${v//\//.}
  mkdir -p gen/$v && cp $A/$v/*.g4 gen/$v/
  (cd gen/$v && java -cp "$TOOL" org.antlr.v4.Tool -package $pkg -o out -no-listener -no-visitor *Lexer.g4 \
     && java -cp "$TOOL" org.antlr.v4.Tool -package $pkg -o out -lib out -no-listener -no-visitor *Parser.g4)
done
find src gen -path '*/out/*.java' -o -path 'src/*.java' | grep '\.java$' > files.txt
javac -nowarn -J-Xmx3g -cp "$J/antlr4-runtime.jar:$J/guava.jar" -d classes @files.txt
echo "Built $OUT/classes"
