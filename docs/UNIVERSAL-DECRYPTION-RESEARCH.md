# Universal decryption feasibility and backend service

Status: research design, not an operational universal FairPlay bypass.

## Verified constraints
- FairPlay-encrypted Mach-O code requires valid authorization and platform-specific cryptographic handling. Clearing cryptid is not decryption.
- Kernel access, sandbox escape and AMFI changes are separate from recovering FairPlay plaintext.
- A hosted macOS runner does not substitute for an authorized iOS device.
- DarkSword/LARA support is release- and device-dependent; avoid treating their claims as universal.
- New SC_Info formats may be incompatible with older iOS kernels; treat version compatibility as an observed capability, not a promise.

## Backend contract
Each backend should report:
1. Host/device OS build, CPU subtype and environment (no identifying device secrets).
2. Required app minimum OS and architecture.
3. FairPlay SC_Info format presence and sizes (never upload license material).
4. Whether the backend can actually load the app, not merely inspect its IPA.
5. Whether an authorized runtime was used to recover plaintext.
6. Independent output validation: source/candidate crypt region, structural checks, signature metadata, and known-plaintext reference where available.

## Service pipeline
- Inspect: local IPA inventory, Mach-O architecture, encryption commands, code-signature blobs, entitlements and SC_Info version metadata.
- Plan: choose an explicitly supported backend or return an actionable incompatibility reason.
- Execute: only on an authorized device or a user-owned test application. No kernel exploit deployment in unattended CI.
- Verify: compare protected bytes, validate Mach-O layout, record reproducible hashes, and distinguish 'candidate changed' from 'plaintext verified'.
- Export: emit a redacted machine-readable report and artifact only when independently validated.

## Research lanes
A. Static parser robustness: fuzz Mach-O, SuperBlob, entitlement and SC_Info metadata readers.
B. Compatibility: record per-iOS build capability without collecting user credentials or FairPlay keys.
C. Device-assisted authorized decryption: study existing backend behavior and verify on test fixtures.
D. Offline hypothesis testing: use known plaintext and synthetic encrypted fixtures; reject unsupported claims.
E. Vulnerability disclosure: document reproducible findings and coordinate remediation rather than deploying unknown exploit chains.

## Acceptance criteria
- Tests pass on Linux, Windows and macOS.
- No private app payloads or credentials enter public GitHub Actions.
- Unknown backends fail closed with a precise reason.
- A changed cryptid, modified encrypted payload or valid Mach-O header alone never yields 'decrypted'.
- Any universal-support claim requires independent evidence across supported iOS builds, CPUs and FairPlay formats.

## Research references
- https://github.com/opa334/darksword-kexploit
- https://github.com/rooootdev/lara
- https://github.com/londek/ipadecrypt/issues/34
- https://mas.owasp.org/MASTG/0x06a-Platform-Overview/
- https://support.corellium.com/features/apps/testing-ios-apps
