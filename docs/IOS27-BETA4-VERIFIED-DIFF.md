# iOS 27.2 beta 3 → beta 4: verified public firmware evidence

## Verified source

- Catalog: https://github.com/ipsw-diffs/catalog
- Pinned source manifest: https://github.com/ipsw-diffs/ios-27/blob/68a69ee85507ca6cabadf0c1e0703e2e40b165d6/manifests/27_2_24B5099f_vs_27_2_24B5110a.json
- Diff entrypoint: https://github.com/ipsw-diffs/ios-27/blob/68a69ee85507ca6cabadf0c1e0703e2e40b165d6/diffs/27_2_24B5099f_vs_27_2_24B5110a/README.md

Manifest records:
- From build: 24B5099f
- To build: 24B5110a
- Device: **iPhone18,1**, not iPhone16,2
- Tracked files: 2,240
- Logical bytes: 14,270,279
- Payload git tree: b8c873eda57411f3ce0eaae3493d677bd7f1c69d

## Evidence constraints

This corpus is NOT a device-matched kernel diff for iPhone 15 Pro Max (iPhone16,2). Its changes may suggest shared iOS areas for further analysis, but cannot prove that an A17 Pro-specific security defect is present. No kernel privilege escalation, sandbox escape, FairPlay bypass, or jailbreak has been established.

## Reproduction with device-matched inputs

1. Obtain two Apple firmware images explicitly targeting iPhone16,2 for the builds above.
2. Confirm model identifiers, build numbers and firmware provenance before running analysis.
3. Use blacktop/ipsw: `ipsw diff old.ipsw new.ipsw --fw --ent --launchd --markdown --output diff-report`.
4. Record source hashes and review actual component changes.
5. Do not report a crash or changed binary as an exploit without independent, authorized runtime validation.

Reference: https://blacktop.github.io/ipsw/docs/cli/ipsw/diff/
