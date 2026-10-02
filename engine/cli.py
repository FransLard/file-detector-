from __future__ import annotations
import sys
import pathlib
from engine.detector import scan_file

def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python -m engine.cli <file>")
        return 2
    p = pathlib.Path(sys.argv[1])
    data = p.read_bytes()
    r = scan_file(data, p.name, check_reputation=False)
    print(str(r["score"]) + " " + r["verdict"]["level"] + " " + r["family"])
    for x in r["reasons"][:10]:
        print("+" + str(x["weight"]) + " " + x["label"])
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
