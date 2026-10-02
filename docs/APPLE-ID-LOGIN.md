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
patterns:            9
cookie jars found:   24
  readable:          24
  decoded:           24
  with session:      1
    pattern /var/mobile/Containers/Data/*/*/Library/Cookies/*.binarycookies -> 24 files
    pattern /var/containers/Data/*/*/Library/Cookies/*.binarycookies -> 0 files
    pattern /var/mobile/Library/Cookies/*.binarycookies -> 0 files
    /var/mobile/Containers/Data/Application/5B1C.../Library/Cookies/Cookies.binarycookies (7 cookies: dsid itctx mz myacinfo ...)
cookie names seen:   dsid(3) itctx(1) mz(1) myacinfo(3) ...
session:             dsidLength=10 storefront="143441" cookies=3
```

Three counts matter when it fails, and each points somewhere different:

- **found: 0** - the globs are outside what the helper can see.
- **decoded: 0** while `readable` is not - the files are not in the format this
  build parses, which is a bug here, not on the device.
- **cookie names seen** - if `myacinfo` is in the list but no session was built,
  the selection is wrong; if it is absent, the device keeps its session
  somewhere these paths do not reach.

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

## There is no App Store session to harvest on iOS

A real device produced this scan:

```
24 cookie jars decoded but none held an App Store session; cookie names seen:
  ACCOUNT_CHOOSER(2) AEC(4) APISID(2) BEC(2) Device(2) Firmware(6) HSID(2)
  LSID(2) NID(4) OSID(2) SAPISID(2) SEARCH_SAMESITE(2) SID(2) SIDCC(2)
  SMSV(2) SNID(2) SSID(2) UDID(6) XSRF-TOKEN(4) __Host-1PLSID(2)
  __Secure-next-auth.session-token(2) __cf_bm(4) __dcfduid(4) _ga(2) …
```

Every one of those is a third-party **web** cookie - Google (`SID`, `HSID`,
`SAPISID`, `NID`), Cloudflare (`__cf_bm`, `__dcfduid`), Discord (`__dcfduid`),
analytics (`_ga`), a NextAuth site, and WebKit's own `Device`/`Firmware`/`UDID`.
**There is not a single Apple cookie**, and in particular no `myacinfo`.

That is the answer, not a scanning bug: the parser decoded all 24 jars and read
hundreds of names out of them, and the paths are the ones that hold cookies. iOS
simply does not keep its App Store session in a cookie jar, because the device
App Store does not speak the Mac-Configurator protocol this tool emulates. It
authenticates through **StoreServices** with a device identity and signed
headers.

So the cookie-harvesting path in `internal/appstore` cannot supply a session, no
matter how wide the globs are. It is kept because it costs nothing and would
work if a device ever did hold such cookies, but the app no longer tells you to
sign in again as if that were the problem - the failure message says what is
actually missing and points at the paths that work.

### What that means for the version picker

| Feature | Needs | Works on-device |
|---|---|---|
| Decrypt installed build | nothing | yes |
| Latest iOS-compatible | the device's own App Store (StoreKit) | yes |
| Latest from App Store / version picker | an authenticated App Store session | **no** |

The two working paths cover "give me a runnable copy of this app", including the
older-version prompt the device App Store raises for free. Choosing a *specific*
historical version needs either the desktop CLI (where SAP runs) or a tweak that
borrows the App Store app's own authenticated session - see the release notes for
the trade-offs.

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
