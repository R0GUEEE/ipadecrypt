# Offline FairPlay feasibility and validation

## Objective
Establish, with reproducible evidence, whether an encrypted iOS App Store IPA can be reconstructed without a compatible physical device. No standalone FairPlay decryption capability is claimed.

## Boundaries
- The ZIP container and Mach-O headers are inspectable without decrypting protected executable bytes.
- A Mach-O `LC_ENCRYPTION_INFO(_64)` load command identifies `cryptoff`, `cryptsize`, and `cryptid`. A zeroed `cryptid` does **not** decrypt the region.
- A macOS GitHub-hosted runner does not provide the user's FairPlay authorization, device key material, or a jailbroken iOS runtime.
- Apple's iOS Simulator runs simulator-compatible binaries, not arbitrary encrypted device IPAs. Simulator success does not validate FairPlay decryption.
- Do not upload personal IPA purchase metadata, Apple ID credentials, device pairing records, or signing secrets to public CI artifacts.

## Experiment design
1. **Static inventory**: inspect every Mach-O in the IPA; record architecture, encrypted region, code signature presence, deployment target and archive path.
2. **Reference fixture**: create a known unencrypted Mach-O and a controlled test fixture with a nonzero encryption marker. Verify that merely changing the marker is rejected as proof of decryption.
3. **Offline hypothesis**: identify any candidate method and state its required inputs, runtime assumptions, and licensing requirements before implementation.
4. **Independent verification**: compare output to a legitimately decrypted reference where available; ensure protected bytes changed as expected, all output slices parse, and decrypted executable functionality is actually demonstrated on a compatible runtime.
5. **Negative control**: fail validation when the cryptid is zeroed but the encrypted payload remains unchanged.
6. **Repeatability**: run portable tests on Ubuntu, Windows and macOS, with a separate macOS simulator smoke test using a purpose-built simulator fixture only.

## Decision gates
- If a method requires device-only authorization or keys, classify it as **device-dependent**, not offline.
- If it can only inspect headers or extract plaintext resources, classify it as **inspection/extraction**, not decryption.
- Only describe the method as **offline decryption** after an encrypted sample is recovered and validated against a trusted plaintext reference.
