# Compatibility

## Supported targets

| Device class | SoC | iOS | Jailbreak | Package |
|---|---|---|---|---|
| iPhone 8 / 8 Plus / X | A11 | 14.0 – 16.7.16 | palera1n rootless | `iphoneos-arm64` |
| iPad 5 / 6, iPad Pro 10.5 | A10 / A10X | 14.0 – 16.7.16 | palera1n rootless | `iphoneos-arm64` |
| iPhone 6s / 7, iPad (2017) | A9 / A9X | 14.0 – 16.7.16 | palera1n rootless | `iphoneos-arm64` |
| A12 – A14 devices | A12+ | 14.0 – 17.x | Dopamine / palera1n / RootHide | `iphoneos-arm64` or `iphoneos-arm64e` |
| Any of the above, RootHide | – | same | RootHide | `iphoneos-arm64e` |

Rootful (`iphoneos-arm`) and checkra1n are handled by the CLI, not by these
packages.

### iOS 16.7.16

iOS 16.7.16 is the final release of the 16.x branch and exists only for
A9–A11 hardware. Two consequences matter:

- **The jailbreak is palera1n rootless.** Dopamine stops at 16.6.1, so there is
  no Dopamine option on 16.7.x. Everything therefore lives behind `/var/jb`
  (`/var/jb/Applications/ipadecrypt.app`, `/var/jb/usr/libexec/ipadecryptd`,
  `/var/jb/Library/LaunchDaemons/com.korboy.ipadecryptd.plist`).
- **No arm64e.** A9/A10/A11 are plain arm64. The app and the tweak are fat
  binaries carrying both arm64 and arm64e slices, so the arm64 slice is the one
  that loads; the helper and the daemon are arm64-only, which is exactly right
  for this hardware.

The CLI classifies the jailbreak by following `/var/jb` back to its bootstrap
link and accepts `/jb-*` directories as palera1n (`internal/device/ops.go`,
`classifyJailbreak`).

#### Verified: nothing in the shipped packages requires more than iOS 14/15

Parsed from the Mach-O load commands of the `0.7.4-korboy.1` rootless `.deb`:

| Binary | Arch | Platform | minOS | SDK |
|---|---|---|---|---|
| `ipadecrypt` (app) | arm64 + arm64e | iOS | 15.0 | 18.5 |
| `appstore-helper.arm64` | arm64 | iOS | 15.0 | 16.5 |
| `ipadecryptd` | arm64 | iOS | 15.0 | 16.5 |
| `helper.arm64` | arm64 | iOS | 14.0 | 26.4 |
| `ipadecryptautoalert.dylib` | arm64 + arm64e | iOS | 15.0 | – |

Reproduce with `python3 Tools/macho_info.py <binary>`. Because every `minOS` is
at or below 16.7.16, the packages install and launch on 16.7.x unchanged; the
SDK column only records which SDK compiled the file and does not gate runtime.

There is no iOS-version whitelist, no `respondsToSelector:` gate on a version
number, and no version-dependent path in the app, the daemon, the helper or the
tweak. The auto-confirm tweak hooks `UIAlertController` generically rather than
matching on OS version.

## On-device vs desktop: why the app does not use upstream's SAP path

Upstream (desktop) and this fork (on-device app) share the Go core but
deliberately differ in how they talk to the App Store.

Upstream signs App Store request bodies with **SAP**: `internal/sap` downloads
Apple's macOS `OSXUpd10.9.pkg`, extracts `CommerceKit` and friends, and executes
them inside a **Unicorn x86_64 virtual machine** driven through `purego`. That
is fine on a desktop and impossible on iOS — there is no `libunicorn` for the
device and no way to run Apple's macOS binaries there. Upstream builds a signer
on *every* authentication call, so importing that code into the app would break
on-device sign-in outright.

The app therefore uses the **device's own App Store** for downloads
(`SKUIItem` + `SKUIItemStateCenter` from StoreKitUI, `dlopen`ed in-process), and
uses the bundled `appstore-helper` only for `--list-versions`,
`--version-metadata`, `--auth-only`, `--auth-status` and `--verify-ipa`.
Decryption runs through the `ipadecryptd` daemon socket.

**Practical consequence:** upstream's `internal/appstore` and `internal/sap`
cannot be merged into the app branch as-is. When syncing from upstream, take
helper/CLI fixes and leave the App Store protocol layer alone. See
[`docs/ARCHITECTURE.md`](ARCHITECTURE.md), and
[`docs/APPLE-ID-LOGIN.md`](APPLE-ID-LOGIN.md) for what the app does instead of a
sign-in.
