# Apple ID login

## Short version

On iOS, **signing in with an Apple ID cannot work** and no longer needs to. The
app uses the App Store session the phone already has. On the desktop CLI nothing
changed: `ipadecrypt bootstrap` still logs in with an Apple ID.

## Why a password login cannot work on iOS

The App Store protocol needs a signature on exactly one request:

```go
// internal/appstore/http.go
// The authenticate endpoint requires the request body to be signed with a
// virtual machine identity (SAP action signing). When a signer is provided
// its signature is attached as the X-Apple-ActionSignature header.
if signer != nil { ... }
```

`Login` is the only caller that passes a signer - the bag, lookup, download and
purchase calls all pass `nil`. So `authenticate` needs an
`X-Apple-ActionSignature`, and the only thing that can produce one is SAP.

SAP does not emulate a CPU for fun; `internal/sap` downloads Apple's macOS
`OSXUpd10.9.pkg`, extracts `CommerceKit`/`CoreFP`, and runs those x86_64
binaries inside a Unicorn VM. The Unicorn library itself comes from a PyPI
wheel:

```go
// internal/sap/unicorn/artifact.go
func artifactFor(goos, goarch string) (artifact, error) {
	switch goos + "/" + goarch {
	case "darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64", /* windows */ :
	...
```

There is no `ios/arm64` case, and PyPI publishes no iOS wheels. **libunicorn
does not exist for iOS**, so SAP cannot start on a phone, so no action signature
can be produced, so `authenticate` is unreachable. Upstream made the signer
mandatory, which is exactly why a fork that predates SAP - this one - fails with
`login: failed to unmarshal xml` (Apple answers the unsigned request with an HTML
page) or a bare `login failed`.

## What the app does instead

Every *other* App Store call is unsigned and authenticates from the session
cookies plus the account id. `volumeDownload` - which backs both
`ListVersions` and `GetVersionMetadata` - is the clearest example:

```go
payload := map[string]any{"creditDisplay": "", "guid": g, "salableAdamId": app.ID}
headers["X-Dsid"] = acc.DirectoryServicesID     // no password token anywhere
```

The phone is already signed in to its own App Store, so the app reuses that
session:

1. **`IDDeviceStoreAccount`** (app, Objective-C) reads the signed-in identity
   through StoreServices (`SSAccountStore.defaultAccount` ->
   `DsPersonId`), plus the storefront from `SSDevice` or, failing that, the
   country code from `NSLocale`. Private frameworks are reached with `dlopen`
   and `performSelector`, so a missing StoreServices degrades to "no device
   session" instead of a crash.
2. **`appstore-helper`** is spawned with `--device-session --dsid … --storefront …`.
3. **`internal/appstore`** parses Apple's `Cookies.binarycookies` from the
   stores under `/var/mobile/Library/Cookies/` and
   `/var/mobile/Containers/Data/Application/*/Library/Cookies/`, keeps the
   MZFinance cookies (`myacinfo`, `mz`, …), and serves them alongside the
   persistent jar - read-only, never written back.
4. The device identity is applied to `cfg.Apple` in memory, so every existing
   call site that reads `cfg.Apple.Account()` picks it up, with no password
   token attached.

If no usable session is found, the helper says so (`phase=device-session-failed`
with a reason) and the app falls back to asking for an Apple ID - which will
fail on iOS for the reason above, but the *reason* is now visible in the log
instead of a bare "login failed".

## Verifying it on a device

The scan prints what it looked at, so there is no guessing:

```sh
# as root on the phone
/var/jb/Applications/ipadecrypt.app/appstore-helper.arm64 --device-session-report
```

```
patterns:            6
cookie jars found:   214
  readable:          210
  with session:      1
session:             dsidLength=10 storefront="143441" cookies=3
```

`--auth-status --device-session` is the same check in event form, which is what
the app runs:

```sh
/var/jb/Applications/ipadecrypt.app/appstore-helper.arm64 --auth-status --device-session
```

```
@evt phase="device-session" dsidLength="10" storefront="143441" cookies="3" jars="1"
@evt phase="done" name="authenticated"
```

Common failures, in the order the scan can hit them:

| Reason | Meaning |
|---|---|
| `no cookie jars matched the App Store paths` | the helper cannot see any app container - it is sandboxed away from them |
| `N cookie jars matched but none could be read` | the files exist but are not readable by the helper's user |
| `N cookie jars readable but none held an App Store session` | the device has no App Store session - sign in and open the App Store once |
| `an App Store session was found but it carries no Apple ID (DSID)` | cookies are there but StoreServices did not report an account id; pass `--dsid` explicitly |

The DSID is a personal identifier: it is never written to the app log, only its
length is, and `--device-session-report` prints the cookie *names* it found but
never their values.

## Why a password sign-in reports HTTP 404

If the device session is unavailable the app used to fall back to a password
prompt. That request cannot succeed, and Apple's refusal is cryptic: the bag's
`authenticateAccount` (`https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate`)
answers an unsigned POST with a **404 and an HTML body**, which used to surface
as `failed to unmarshal xml ... unexpected hex digit 'h'`.

`internal/appstore` now recognises that shape and returns `ErrSignatureRequired`
(helper exit code 22, `reason=signature-required`) instead. The app no longer
offers the prompt when the device-session scan already explained the problem; it
shows the reason and what to do about it.
