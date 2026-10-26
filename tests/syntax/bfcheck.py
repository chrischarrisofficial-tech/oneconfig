"""Parse a generated config with Batfish's own NX-OS / Arista EOS grammar and list every line it rejects.

The parser is built from Batfish's ANTLR grammars by build_parser.sh (needs Java, ANTLR 4 and Guava).
Check.java reports every rejected line in one run (see its comment for how)."""
import os
import subprocess
import tempfile
from pathlib import Path

CLASSES = Path(os.environ.get("ONECONFIG_BATFISH_PARSER", Path.home() / ".cache" / "oneconfig-bfparse" / "classes"))
JARS = ["/usr/share/java/antlr4-runtime.jar", "/usr/share/java/guava.jar"]


def available() -> bool:
    return (CLASSES / "oneconfig" / "Check.class").exists() and all(Path(j).exists() for j in JARS)


def rejected(vendor: str, text: str) -> list[tuple[str, str]]:
    """[(line text, parser message)] for every line Batfish's grammar does not accept."""
    with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False) as f:
        f.write(text)
    try:
        out = subprocess.run(["java", "-cp", ":".join([str(CLASSES), *JARS]), "oneconfig.Check", vendor, f.name],
                             capture_output=True, text=True, timeout=300).stdout
    finally:
        os.unlink(f.name)
    return [tuple(l.split("\t", 1)) for l in out.splitlines() if "\t" in l]
