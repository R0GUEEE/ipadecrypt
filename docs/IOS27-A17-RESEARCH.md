# iPhone 15 Pro Max / iOS 27.2 beta 4 research

Target: iPhone16,2 (A17 Pro, arm64e), iOS 27.2 beta 4, build 24B5110a.

## Evidence policy
- A panic, crash, or changed binary is not evidence of privilege escalation.
- Do not claim jailbreak support without an independently reproduced end-to-end demonstration on the exact target build.
- Preserve firmware build, hardware identifier, source commit, reproduction conditions, crash logs, and hashes.
- Perform device experiments only on an owned or expressly authorized test device; obtain backups before testing.
- Keep production-device experiments non-destructive. Do not run historical fuzz phases known to panic a device without separate authorization and recovery preparation.

## Public baselines
- https://github.com/Kurt-228/ios27-research — A17 GPU/IOSurface research; experimental, no confirmed privilege escalation.
- https://github.com/blacktop/ipsw-diffs — firmware delta reports including 24B5099f versus 24B5110a.
- https://github.com/vvirei333/ABrake27 — AMFI and IOKit static analysis, not a jailbreak.
- https://calif.io/research/ios-endpoint-security — EndpointSecuritySE is research-mode-restricted; not a retail jailbreak entry point.

## Initial candidate registry
| ID | Surface | Observed evidence | Missing evidence | Status |
|---|---|---|---|---|
| GPU-001 | AGX resource lifetime | post-destroy GPU work reported on earlier 27 beta | controlled reuse, security impact, beta 4 reproduction | research only |
| SURF-001 | IOSurface user client | sandbox-accessible selectors and mutation coverage | reproducible memory-safety violation on beta 4 | research only |
| AMFI-001 | entitlement validation | binary differences across 27 builds | surviving validation flaw and security impact on beta 4 | research only |
| ES-001 | EndpointSecuritySE | firmware component appears in 27.2 | retail-device reachability; published analysis suggests unavailable | unlikely retail surface |

## Next gates
1. Verify firmware build/device pair and download provenance.
2. Use `ipadecrypt firmware-diff` or public `ipsw-diffs` to catalog changed components.
3. Triage each candidate against the exact target build using controlled tests and logs.
4. Mark candidates rejected, unresolved, or reproduced; never infer exploitability from a crash alone.
5. Keep FairPlay plaintext recovery as a separate, independently verified milestone.

No working iOS 27.2 beta 4 exploit is claimed.
