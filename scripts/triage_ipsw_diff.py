#!/usr/bin/env python3
"""Read-only classification of ipsw JSON differences. No exploitability claims."""
import argparse
import hashlib
import json
from pathlib import Path

CATEGORIES = {
    "kernel": ("kernelcache", "kernel.", "/kernel/", "applemobilefileintegrity"),
    "gpu": ("agx", "iogpu", "gpu", "iosurface", "iomobileframebuffer"),
    "sandbox": ("sandbox", "seatbelt", "container", "profile"),
    "codesigning": ("amfi", "codesign", "coretrust", "trustcache", "mobilefileintegrity"),
    "boot": ("iboot", "sep", "bootchain", "firmware", "img4"),
}
def categorize(name):
    low = name.lower()
    return [group for group, patterns in CATEGORIES.items() if any(p in low for p in patterns)] or ["other"]

def flatten(value, path="", depth=0):
    """Extract file/path-like names from a JSON report, with bounded recursion."""
    if depth > 40:
        raise ValueError("JSON nesting too deep")
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in ("path", "file", "filename", "name", "binary", "macho") and isinstance(item, str):
                if "/" in item or "." in item or "kernelcache" in item.lower():
                    yield item
            if isinstance(item, (dict, list)):
                yield from flatten(item, path, depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from flatten(item, path, depth + 1)

def analyze(raw, device):
    data = json.loads(raw)
    if device != "iPhone16,2":
        raise ValueError("only iPhone16,2 target evidence is accepted")
    if not isinstance(data, (list, dict)):
        raise ValueError("unexpected JSON report structure")
    names = sorted(set(flatten(data)))
    records = [{"path": n, "categories": categorize(n)} for n in names]
    return {
        "device": device,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "entries": len(records),
        "categories": {category: sum(category in r["categories"] for r in records) for category in CATEGORIES},
        "records": records,
        "limitations": [
            "Path-based triage only; classification is heuristic.",
            "JSON contents have not been independently authenticated.",
            "A changed component or crash does not establish exploitability.",
            "This report does not demonstrate a jailbreak or privilege escalation.",
        ],
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("report", type=Path)
    p.add_argument("--device", default="iPhone16,2")
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    raw = args.report.read_bytes()
    result = json.dumps(analyze(raw, args.device), indent=2) + "\n"
    if args.output:
        args.output.write_text(result, encoding="utf-8")
    else:
        print(result, end="")

if __name__ == "__main__":
    main()
