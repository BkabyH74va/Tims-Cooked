#!/usr/bin/env python3
"""Disassemble an extracted kext (annotated) and cache the text output."""
import subprocess
import sys
from pathlib import Path
import kx

IPSW = r"G:/REPO\tools\ipsw\ipsw.exe"
CACHE = Path(r"G:/REPO\tools\opencode-temp\lifetime-triage\disasm")
CACHE.mkdir(parents=True, exist_ok=True)


def disasm(name, section="__TEXT_EXEC.__text", quiet=False):
    out = CACHE / (name.replace(".", "_") + "." + section.replace(".", "_") + ".txt")
    if not out.exists():
        cmd = [IPSW, "macho", "disass", str(kx.EXTRACT / name), "-x", section]
        if quiet:
            cmd.append("-q")
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        out.write_text(r.stdout, encoding="utf-8", errors="replace")
    return out


if __name__ == "__main__":
    name = sys.argv[1]
    section = sys.argv[2] if len(sys.argv) > 2 else "__TEXT_EXEC.__text"
    quiet = len(sys.argv) > 3 and sys.argv[3] == "q"
    p = disasm(name, section, quiet)
    print(p, p.stat().st_size)
