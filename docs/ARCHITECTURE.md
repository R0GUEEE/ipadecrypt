# Architecture

ipadecrypt has four moving parts. Three of them run on the phone, one runs on
your computer.

```
                    ┌──────────────────────────────────────────┐
   desktop          │  ipadecrypt (Go CLI)                     │
   ──────────────── │  cmd/ipadecrypt                          │
                    │    bootstrap / decrypt / versions        │
                    │    SSH + SFTP to the device              │
                    └───────────────┬──────────────────────────┘
                                    │ ssh / sftp
   ─────────────────────────────────┼──────────────────────────────
   phone                            ▼
                    ┌──────────────────────────────────────────┐
                    │  /var/jb/usr/libexec/ipadecryptd (Go)    │
                    │  unix socket, root LaunchDaemon           │
                    │    orchestrates the helper                │
                    └───────────────┬──────────────────────────┘
                                    │ spawn
                                    ▼
                    ┌──────────────────────────────────────────┐
                    │  helper.arm64 (C)                        │
                    │  task_for_pid + mach_vm_read from a       │
                    │  suspended spawn, dyld patch, dump        │
                    └──────────────────────────────────────────┘

                    ┌──────────────────────────────────────────┐
                    │  ipadecrypt.app (ObjC)   + appstore-     │
                    │  talks to ipadecryptd    │ helper.arm64  │
                    │  StoreKitUI download     │ (Go, ios)     │
                    └──────────────────────────────────────────┘

                    ┌──────────────────────────────────────────┐
                    │  ipadecryptautoalert (Logos tweak)       │
                    │  injects into SpringBoard                 │
                    └──────────────────────────────────────────┘
```

## The pieces

| Path | Language | Runs on | Purpose |
|---|---|---|---|
| `cmd/ipadecrypt` | Go | desktop | The CLI: bootstrap, decrypt, versions, download |
| `cmd/ipadecryptd` | Go | phone (root) | Daemon behind a unix socket; drives the helper |
| `cmd/ipadecrypt-appstore-helper` | Go | phone (mobile) | App Store lookups, auth, IPA verification |
| `helper/` | C | phone (root) | `task_for_pid` + `mach_vm_read`, dyld patch, dump |
| `app/` | Objective-C | phone | The SwiftUI-free UIKit app (Theos `APPLICATION`) |
| `helper/ipadecryptautoalert/` | Logos | phone (SpringBoard) | Auto-confirms the "Download an older version" alert |

## Where the code is shared, and where it is not

`internal/macho`, `internal/pipeline` and `internal/config` are shared by every
binary. `internal/appstore` and `internal/sap` are **not** portable to the
phone — see [COMPATIBILITY.md](COMPATIBILITY.md#on-device-vs-desktop-why-the-app-does-not-use-upstreams-sap-path)
for the full reasoning.

The rule when syncing from upstream:

- take `helper/`, `internal/macho`, `internal/pipeline`, `internal/config`,
  `internal/device` and CLI fixes freely;
- leave `internal/appstore` and `internal/sap` alone on the app branch.

## The rootless requirement

On iOS 16.7.x the only jailbreak is palera1n rootless, so every path in the
packages is `/var/jb`-prefixed and every package is `Architecture:
iphoneos-arm64`. RootHide is built from the same source with
`THEOS_PACKAGE_SCHEME=roothide` and `-lroothide`, which resolves the jailbreak
root at runtime instead of hard-coding `/var/jb`.

The rootful/rootless split is a **build-time** choice for the app and the tweak,
but a **path-table** choice for the Go code: `internal/device/client.go` maps a
detected jailbreak to a remote root, so one CLI binary drives rootful,
rootless and RootHide devices.
