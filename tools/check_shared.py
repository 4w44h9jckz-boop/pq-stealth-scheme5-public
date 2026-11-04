#!/usr/bin/env python3
"""Check that the files this tree shares with the schemeId 3 tree are unchanged copies.

    check_shared.py [--root ROOT]           compare with tools/shared_with_scheme3.json
    check_shared.py --against SCHEME3       compare file by file with a schemeId 3 checkout
    check_shared.py --update SCHEME3        copy nothing, record SCHEME3's hashes in the manifest

`crates/core`, `crates/ec`, `crates/kem` and the other paths below are copied unchanged from
the schemeId 3 repository (ERC-8441), so a wallet that uses both schemes can build one copy of
them. Exit 0 if every shared file matches, 1 if one differs or is missing, 2 on a usage error.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = Path("tools/shared_with_scheme3.json")

# Directories are taken whole; every file under them is shared.
SHARED = (
    "crates/core",
    "crates/ec",
    "crates/kem",
    "tools/vecprim.py",
    "vectors/tier1/ml-kem-768-acvp.json",
    "contracts",
    "harness/eip7623.py",
    "harness/evm.py",
    "harness/erc5564.py",
    "harness/announcement/deployed_bytecode.hex",
    "harness/registration/deployed_bytecode.hex",
)


def shared_files(root: Path) -> list[str]:
    out: list[str] = []
    for entry in SHARED:
        path = root / entry
        if path.is_dir():
            out += sorted(
                str(p.relative_to(root))
                for p in path.rglob("*")
                if p.is_file() and "__pycache__" not in p.parts
            )
        else:
            out.append(entry)
    return out


def digest(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def commit_of(root: Path) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main(argv: list[str]) -> int:
    args = argv[1:]
    root, against, update = ROOT, None, None
    while args:
        flag = args.pop(0)
        if flag in ("--root", "--against", "--update") and args:
            value = Path(args.pop(0)).resolve()
            if flag == "--root":
                root = value
            elif flag == "--against":
                against = value
            else:
                update = value
        else:
            print(__doc__, file=sys.stderr)
            return 2

    if update is not None:
        files = {f: digest(update / f) for f in shared_files(update)}
        body = {"scheme3_commit": commit_of(update), "files": files}
        (root / MANIFEST).write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
        print(f"recorded {len(files)} shared file(s) from {body['scheme3_commit']}")
        return 0

    if against is not None:
        want = {f: digest(against / f) for f in shared_files(against)}
        source = f"the schemeId 3 checkout at {against}"
    else:
        try:
            body = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"usage error: cannot read {MANIFEST}: {exc}", file=sys.stderr)
            return 2
        want = body["files"]
        source = f"{MANIFEST} (schemeId 3 commit {body['scheme3_commit']})"

    have = {f: digest(root / f) for f in sorted(set(want) | set(shared_files(root)))}
    bad = [f for f in have if have[f] != want.get(f)]
    for f in bad:
        state = "missing here" if have[f] is None else (
            "not in the schemeId 3 set" if f not in want else "differs")
        print(f"  {state}: {f}")
    if bad:
        print(f"FAIL: {len(bad)} shared file(s) do not match {source}")
        return 1
    print(f"OK: {len(have)} shared file(s) match {source}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
