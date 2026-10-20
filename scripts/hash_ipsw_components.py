#!/usr/bin/env python3
"""Stream SHA-256 of selected unencrypted IPSW ZIP entries.

ZIP entries may contain encrypted IMG4/DMG payloads. Hashes measure packaged
bytes, not decrypted executable code. No device interaction or exploitation.
"""
import argparse
import hashlib
import json
import zipfile
from pathlib import Path

KEYWORDS = ("kernelcache", "trustcache", "iboot", "sep-firmware", "devicetree", "restore", "buildmanifest")
MAX_BYTES = 2 * 1024**3

def manifest(path, build, max_bytes=MAX_BYTES):
    entries = []
    with zipfile.ZipFile(path) as archive:
        for item in archive.infolist():
            if item.is_dir() or not any(x in item.filename.lower() for x in KEYWORDS):
                continue
            record = {"path": item.filename, "size": item.file_size, "crc32": f"{item.CRC:08x}"}
            if item.file_size > max_bytes:
                record["sha256"] = None
                record["reason"] = "entry exceeds configured hashing limit"
            else:
                h = hashlib.sha256()
                with archive.open(item) as source:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        h.update(chunk)
                record["sha256"] = h.hexdigest()
            entries.append(record)
    return {"device": "iPhone16,2", "build": build, "entries": sorted(entries, key=lambda x: x["path"]),
            "note": "SHA-256 is of packaged ZIP entry bytes, not decrypted IMG4/DMG contents."}

def compare(a, b):
    old = {r["path"]: r for r in a["entries"]}
    new = {r["path"]: r for r in b["entries"]}
    changed = []
    for path in sorted(old.keys() | new.keys()):
        left, right = old.get(path), new.get(path)
        if left != right:
            changed.append({"path": path, "old": left, "new": right,
                            "status": "added" if left is None else "removed" if right is None else "changed"})
    return {"device": "iPhone16,2", "old_build": a["build"], "new_build": b["build"], "changes": changed,
            "limitations": ["Only selected firmware ZIP entries were hashed.",
                            "Encrypted payloads were not decrypted or disassembled.",
                            "A hash difference is not evidence of exploitability."]}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("old", type=Path)
    p.add_argument("new", type=Path)
    p.add_argument("--output", type=Path, default=Path("firmware-component-diff.json"))
    args = p.parse_args()
    a = json.loads(args.old.read_text())
    b = json.loads(args.new.read_text())
    if a.get("device") != "iPhone16,2" or b.get("device") != "iPhone16,2":
        p.error("both manifests must target iPhone16,2")
    args.output.write_text(json.dumps(compare(a, b), indent=2) + "\n")

if __name__ == "__main__":
    main()
