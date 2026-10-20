# Portable backend architecture (research branch)

## Verified existing flow
The CLI accepts bundle IDs and local IPA paths. For a source IPA, the device helper streams replacement Mach-O binaries and the host assembles them into the original archive using pipeline.Assemble. For an installed app without a host source, the helper packages and streams an IPA. pipeline.Verify checks cryptid, all-zero encrypted regions, and optional comparisons outside encrypted regions.

## Scope
This branch introduces a platform-neutral Go backend contract only. It does **not** implement offline FairPlay decryption or imply that encrypted iOS binaries can be decrypted without authorized Apple runtime support.

## Backend candidates
- iOS device worker: existing privileged memory-dump workflow over SSH/USB.
- macOS worker: capability probe only until supported runtime behavior is demonstrated.
- Offline: parsing, reconstruction and verification of already-plaintext inputs; never claim to decrypt FairPlay.
- Windows/Linux: CLI orchestration and host-side assembly, optionally delegating to an iOS worker.

## Integration steps
1. Adapt internal/device Client methods into a backend implementation.
2. Move source-IPA assembly behind an orchestration service.
3. Preserve exact source binary paths, reject duplicate/unsafe ZIP paths.
4. Verify each replacement's Mach-O architecture, crypt range and plaintext bytes before publishing output.
5. Add mock backends and cancellation/error-path tests.
6. Retain existing CLI behavior until regression tests pass.

## Security
Never log credentials, cookies, device tokens or decrypted memory. Use bounded streaming and temporary files with restrictive permissions. Treat IPA ZIP paths and helper output paths as untrusted. Never change cryptid without replacing the encrypted bytes.

## Compatibility caveat
A device must support and be able to execute the selected application version. A newer minimum-iOS target cannot be decrypted through the existing launch-and-dump workflow on an older device.
