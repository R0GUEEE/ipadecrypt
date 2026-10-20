#!/usr/bin/env python3
"""Inventory firmware ZIP entries; no extraction, flashing, or exploit claims."""
import argparse
import hashlib
import json
import zipfile
from pathlib import Path

TOKENS = ("kernelcache", "trustcache", "iboot", "sep-firmware", "dtre", "device", "manifest", "apfs", "restore")
def inventory(path, build):
    records = []
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = info.filename
            if any(t in name.lower() for t in TOKENS):
                # Metadata only. SHA-256 of the whole archive is checked by the workflow.
                records.append({"path": name, "size": info.file_size, "crc32": f"{info.CRC:08x}"})
    return {"build": build, "entries": sorted(records, key=lambda x: x["path"])}
def compare(old, new):
    a = {x["path"]: x for x in old["entries"]}
    b = {x["path"]: x for x in new["entries"]}
    changes = []
    for path in sorted(a.keys() | b.keys()):
        before, after = a.get(path), b.get(path)
        if before != after:
            changes.append({"path": path, "before": before, "after": after})
    return {"device": "iPhone16,2", "old_build": old["build"], "new_build": new["build"], "changed": changes,
            "limitations": "ZIP metadata differences only. CRC32 is not a cryptographic integrity proof. Encrypted DMG contents and kernel code are not inspected; no exploit demonstrated."}
def main():
    p = argparse.ArgumentParser()
    p.add_argument("old", type=Path)
    p.add_argument("new", type=Path)
    p.add_argument("--output", type=Path, default=Path("firmware-zip-diff.json"))
    args = p.parse_args()
    result = compare(json.loads(args.old.read_text()), json.loads(args.new.read_text()))
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Compared {len(result['changed'])} changed ZIP entries; wrote {args.output}")
if __name__ == "__main__":
    main()
