package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/londek/ipadecrypt/internal/appstore"
	"github.com/londek/ipadecrypt/internal/appstoreworkflow"
	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/pipeline"
	"howett.net/plist"
)

var defaultRootDir = "/var/mobile/Documents/ipadecrypt"

var rootDir = firstNonEmpty(strings.TrimSpace(os.Getenv("IPADECRYPT_ROOT_DIR")), defaultRootDir)

// Device-session options are package level because the code paths that use
// them - prepareAppStore, runAuthStatus, runAuthOnly - are not methods of
// anything and cannot see main's locals.
var (
	deviceSessionFlag bool
	deviceDSID        string
	deviceStoreFront  string
	deviceCookieJar   string

	deviceSessionReport bool
)

var errAuthRequired = errors.New("sign in with Apple ID required")

type appleLoginFunc func(email, password, authCode string) error

type commandRunner func(name string, args ...string) error

type installedApp struct {
	BundleID string
	Name     string
	Version  string
	Path     string
}

func main() {
	var bundleID, trackID, email, password, authCode string
	var verifyIPA string
	var listVersions bool
	var versionMetadata bool
	var authOnly bool
	var authStatus bool
	var externalVersionID string
	var decryptHelper, decryptBundleID, decryptBundlePath, decryptOutIPA string
	flag.StringVar(&bundleID, "bundle-id", "", "bundle identifier")
	flag.StringVar(&trackID, "track-id", "", "App Store track ID")
	flag.StringVar(&email, "email", "", "Apple ID email")
	flag.StringVar(&password, "password", "", "Apple ID password")
	flag.StringVar(&authCode, "auth-code", "", "Apple 2FA code")
	flag.StringVar(&verifyIPA, "verify-ipa", "", "verify cryptid in IPA and exit")
	flag.BoolVar(&listVersions, "list-versions", false, "list App Store external version IDs")
	flag.BoolVar(&versionMetadata, "version-metadata", false, "fetch metadata for one App Store external version ID")
	flag.BoolVar(&authOnly, "auth-only", false, "refresh App Store authentication and exit")
	flag.BoolVar(&authStatus, "auth-status", false, "report whether complete saved App Store authentication is available")
	flag.StringVar(&externalVersionID, "external-version-id", "", "pin to a specific historical App Store version")
	flag.BoolVar(&deviceSessionFlag, "device-session", false,
		"use the device's own App Store session instead of an Apple ID sign-in")
	flag.StringVar(&deviceDSID, "dsid", "", "Directory Services id to pair with the device session")
	flag.StringVar(&deviceStoreFront, "storefront", "", "numeric App Store storefront for the device session")
	flag.StringVar(&deviceCookieJar, "cookie-jar", "", "explicit Cookies.binarycookies path to read the device session from")
	flag.BoolVar(&deviceSessionReport, "device-session-report", false,
		"print what the device-session scan found, then exit")
	flag.StringVar(&decryptHelper, "decrypt-helper", "", "run decrypt helper and relay events")
	flag.StringVar(&decryptBundleID, "decrypt-bundle-id", "", "bundle identifier for decrypt helper")
	flag.StringVar(&decryptBundlePath, "decrypt-bundle-path", "", "installed bundle path for decrypt helper")
	flag.StringVar(&decryptOutIPA, "decrypt-out-ipa", "", "output IPA path for decrypt helper")
	flag.Parse()

	if deviceSessionReport {
		runDeviceSessionReport()
		return
	}

	if decryptHelper != "" {
		if err := runDecryptHelper(decryptHelper, decryptBundleID, decryptBundlePath, decryptOutIPA); err != nil {
			fail(31, "decrypt-helper-failed", err.Error())
		}
		return
	}

	if verifyIPA != "" {
		if err := verifyCryptid(verifyIPA); err != nil {
			fail(30, "verify-failed", err.Error())
		}
		return
	}

	if authOnly {
		if err := runAuthOnly(email, password, authCode); err != nil {
			code := 1
			reason := "error"
			if errors.Is(err, appstore.ErrAuthCodeRequired) {
				code = 21
				reason = "auth-code-required"
			} else if errors.Is(err, appstore.ErrSignatureRequired) {
				code = 22
				reason = "signature-required"
			} else if errors.Is(err, errAuthRequired) || errors.Is(err, appstore.ErrInvalidCredentials) {
				code = 20
				reason = "auth-required"
			}
			fail(code, reason, err.Error())
		}
		return
	}

	if authStatus {
		if err := runAuthStatus(); err != nil {
			code := 1
			reason := "error"
			if errors.Is(err, errAuthRequired) {
				code = 20
				reason = "auth-required"
			}
			fail(code, reason, err.Error())
		}
		return
	}

	if bundleID == "" && trackID == "" {
		fail(2, "missing-target", "bundle-id or track-id is required")
	}

	var err error
	if versionMetadata {
		err = runVersionMetadata(bundleID, trackID, email, password, authCode, externalVersionID)
	} else if listVersions {
		err = runListVersions(bundleID, trackID, email, password, authCode)
	} else {
		err = run(bundleID, trackID, email, password, authCode, externalVersionID)
	}
	if err != nil {
		code := 1
		reason := "error"
		if errors.Is(err, appstore.ErrAuthCodeRequired) {
			code = 21
			reason = "auth-code-required"
		} else if errors.Is(err, appstore.ErrSignatureRequired) {
			code = 22
			reason = "signature-required"
		} else if errors.Is(err, errAuthRequired) || errors.Is(err, appstore.ErrInvalidCredentials) {
			code = 20
			reason = "auth-required"
		}
		fail(code, reason, err.Error())
	}
}

func runAuthStatus() error {
	emit("phase", "step", "name", "loading-config")

	// The device's own App Store session is a complete credential on iOS - it
	// is what replaced the Apple ID sign-in this app cannot perform.
	if deviceSessionFlag {
		if session, err := resolveDeviceSession(); err == nil {
			emit("phase", "device-session",
				"dsidLength", strconv.Itoa(len(session.DSID)),
				"storefront", session.StoreFront,
				"cookies", strconv.Itoa(len(session.Cookies)),
				"jars", strconv.Itoa(len(session.Sources)))
			emit("phase", "done", "name", "authenticated")

			return nil
		} else {
			emitDeviceSessionFailure(resolvedReport)
		}
	}

	cfg, err := config.LoadReadOnly(configFile())
	if errors.Is(err, os.ErrNotExist) {
		return errAuthRequired
	}
	if err != nil {
		return err
	}
	if !savedAppleAuthAvailable(cfg) {
		emit("phase", "auth-required")
		return errAuthRequired
	}

	emit("phase", "done", "name", "authenticated")
	return nil
}

func savedAppleAuthAvailable(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	a := cfg.Apple
	return strings.TrimSpace(a.Email) != "" &&
		a.Password != "" &&
		strings.TrimSpace(a.PasswordToken) != "" &&
		strings.TrimSpace(a.DirectoryServicesIdentifier) != "" &&
		strings.TrimSpace(a.StoreFront) != ""
}

func runAuthOnly(email, password, authCode string) error {
	emit("phase", "step", "name", "loading-config")
	defer chownConfig()

	// Signing in with an Apple ID cannot work on iOS (Apple requires the SAP
	// action signature, which needs an x86_64 Unicorn library that has no iOS
	// build), so the device's own App Store session is the whole credential.
	// Only fall through to a password login when that is unavailable.
	if deviceSessionFlag {
		if session, err := resolveDeviceSession(); err == nil {
			emit("phase", "device-session",
				"dsidLength", strconv.Itoa(len(session.DSID)),
				"storefront", session.StoreFront,
				"cookies", strconv.Itoa(len(session.Cookies)),
				"jars", strconv.Itoa(len(session.Sources)))
			emit("phase", "done", "name", "authenticated")

			return nil
		} else {
			emitDeviceSessionFailure(resolvedReport)
		}
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	as, err := appstore.New(filepath.Join(rootDir, "cookies"))
	if err != nil {
		return fmt.Errorf("appstore client: %w", err)
	}

	err = refreshAppleAuth(cfg, email, password, authCode, func(email, password, authCode string) error {
		emit("phase", "step", "name", "authenticating")
		return appstoreworkflow.LoginAndSave(cfg, as, email, password, authCode)
	})
	if err != nil {
		if errors.Is(err, errAuthRequired) {
			emit("phase", "auth-required")
		}
		return err
	}

	emit("phase", "done", "name", "authenticated")
	return nil
}

func refreshAppleAuth(cfg *config.Config, email, password, authCode string, login appleLoginFunc) error {
	if email == "" && password == "" {
		email = cfg.Apple.Email
		password = cfg.Apple.Password
		if email == "" || password == "" {
			return errAuthRequired
		}
	} else if email == "" || password == "" {
		return errors.New("missing Apple ID email or password")
	}

	return login(email, password, authCode)
}

func run(bundleID, trackID, email, password, authCode, externalVersionID string) error {
	emit("phase", "step", "name", "loading-config")
	defer chownConfig()

	cfg, as, app, err := prepareAppStore(bundleID, trackID, email, password, authCode)
	if err != nil {
		return err
	}
	if app.BundleID != "" {
		bundleID = app.BundleID
	}

	paths, err := config.NewPaths(rootDir)
	if err != nil {
		return err
	}

	ipa, version, cached, err := fetchEncrypted(cfg, paths, as, app, externalVersionID)
	if err != nil {
		return err
	}
	if cached {
		emit("phase", "cached", "path", ipa, "version", version)
	} else {
		emit("phase", "downloaded", "path", ipa, "version", version)
	}

	targetOS := iosVersion()
	deviceFamily := deviceFamily()
	installIPA, cleanup, err := patchForInstall(ipa, targetOS, deviceFamily)
	if err != nil {
		return err
	}
	defer cleanup()

	appinst, err := locateAppinst()
	if err != nil {
		return err
	}
	if appinst == "" {
		return errors.New("appinst not found; install AppSync/appinst first")
	}

	emit("phase", "step", "name", "install", "appinst", appinst)
	if err := runAppinst(appinst, installIPA); err != nil {
		return err
	}

	installed, err := findInstalled(bundleID)
	if err != nil {
		return err
	}
	emit("phase", "installed", "bundle", installed.BundleID, "version", installed.Version, "path", installed.Path)

	registrationErr := refreshApplicationRegistration(
		installed.Path,
		jailbreakCandidates("/var/jb/usr/bin/uicache", "/usr/bin/uicache"),
		fileExists,
		func(name string, args ...string) error {
			return exec.Command(name, args...).Run()
		},
	)
	if registrationErr != nil {
		emit("phase", "registration", "status", "warning", "message", registrationErr.Error())
	} else {
		emit("phase", "registration", "status", "ok")
	}

	return nil
}

// deviceSessionOnce caches the resolved device session for the process: the
// cookie-jar scan touches hundreds of files and each command needs it at most
// once.
var (
	deviceSessionOnce sync.Once
	resolvedReport    appstore.DeviceSessionReport
)

// resolveStoreFront accepts either the numeric id the device reports or a
// two-letter country code, which is all the app can get without private
// frameworks.
func resolveStoreFront() string {
	storeFront := strings.TrimSpace(deviceStoreFront)
	if storeFront == "" {
		return ""
	}

	if resolved, err := appstore.ResolveStorefront(storeFront); err == nil {
		return resolved
	}

	return ""
}

// deviceSessionPatterns are the cookie jars to scan: an explicit override
// first, then every place iOS keeps an App Store session.
func deviceSessionPatterns() []string {
	patterns := make([]string, 0, 8)
	if strings.TrimSpace(deviceCookieJar) != "" {
		patterns = append(patterns, deviceCookieJar)
	}

	return append(patterns, appstore.DefaultCookieJarPatterns()...)
}

// resolveDeviceSession reads the App Store session the phone already has.
//
// The on-device app cannot sign in with an Apple ID at all. Apple requires an
// X-Apple-ActionSignature on the authenticate request, and producing one needs
// SAP, which runs a prebuilt x86_64 Unicorn library that simply does not exist
// for iOS. Every other App Store call is sent unsigned and authenticates from
// the session cookies, so reusing the device's own App Store session is the
// supported path here.
func resolveDeviceSession() (*appstore.DeviceSession, error) {
	deviceSessionOnce.Do(func() {
		resolvedReport = appstore.ScanDeviceSession(deviceSessionPatterns(), deviceDSID, resolveStoreFront(), "")
	})

	if resolvedReport.Session != nil {
		return resolvedReport.Session, nil
	}

	return nil, fmt.Errorf("device session: %s", resolvedReport.Reason())
}

// emitDeviceSessionFailure explains a failed scan in the event stream, so the
// app can show which of the four possible causes it hit instead of a bare
// "sign-in required".
func emitDeviceSessionFailure(report appstore.DeviceSessionReport) {
	emit("phase", "device-session-failed",
		"reason", report.Reason(),
		"found", strconv.Itoa(len(report.Found)),
		"readable", strconv.Itoa(len(report.Readable)),
		"sessions", strconv.Itoa(len(report.WithSessionCookies)))
}

// runDeviceSessionReport prints the scan verbatim and exits: the fastest way
// to tell why the app cannot see the phone's App Store session. Read-only.
func runDeviceSessionReport() {
	report := appstore.ScanDeviceSession(deviceSessionPatterns(), deviceDSID, resolveStoreFront(), "")

	fmt.Print(report.Describe())

	emit("phase", "device-session-report",
		"found", strconv.Itoa(len(report.Found)),
		"readable", strconv.Itoa(len(report.Readable)),
		"sessions", strconv.Itoa(len(report.WithSessionCookies)),
		"usable", boolString(report.Session != nil),
		"reason", report.Reason())

	if report.Session == nil {
		os.Exit(23)
	}
}

// installDeviceSession attaches the device session to the client when one is
// available and reports the outcome as events for the app to display.
func installDeviceSession(cfg *config.Config, as *appstore.Client) *appstore.DeviceSession {
	emit("phase", "step", "name", "device-session")

	session, err := resolveDeviceSession()
	if err != nil {
		emitDeviceSessionFailure(resolvedReport)
		return nil
	}

	as.UseDeviceSession(session)
	installDeviceIdentity(cfg, session)
	emit("phase", "device-session",
		"dsidLength", strconv.Itoa(len(session.DSID)),
		"storefront", session.StoreFront,
		"cookies", strconv.Itoa(len(session.Cookies)),
		"jars", strconv.Itoa(len(session.Sources)))

	return session
}

// installDeviceIdentity copies the device session's identity into the config.
//
// Every App Store call site reads cfg.Apple.Account(), so putting the device
// identity there covers all of them - version listing, metadata, download
// tickets - without threading an account through each one. Nothing is saved:
// the config is only written by an explicit sign-in.
func installDeviceIdentity(cfg *config.Config, session *appstore.DeviceSession) {
	if cfg == nil || session == nil {
		return
	}

	if dsid := strings.TrimSpace(session.DSID); dsid != "" {
		cfg.Apple.DirectoryServicesIdentifier = dsid
	}

	if storeFront := strings.TrimSpace(session.StoreFront); storeFront != "" {
		cfg.Apple.StoreFront = storeFront
	}

	// A device session has no password token, and leaving a stale one behind
	// would make the App Store treat the request as a different session.
	cfg.Apple.PasswordToken = ""
}

func prepareAppStore(bundleID, trackID, email, password, authCode string) (*config.Config, *appstore.Client, appstore.App, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, nil, appstore.App{}, err
	}

	as, err := appstore.New(filepath.Join(rootDir, "cookies"))
	if err != nil {
		return nil, nil, appstore.App{}, fmt.Errorf("appstore client: %w", err)
	}

	var session *appstore.DeviceSession
	if deviceSessionFlag {
		session = installDeviceSession(cfg, as)
	}

	// A device session replaces the Apple ID sign-in entirely; a password login
	// would only fail (Apple insists on the SAP signature that iOS cannot
	// produce), so it is skipped rather than attempted.
	if session == nil && (email != "" || password != "" || authCode != "") {
		err := refreshAppleAuth(cfg, email, password, authCode, func(email, password, authCode string) error {
			emit("phase", "step", "name", "authenticating")
			return appstoreworkflow.LoginAndSave(cfg, as, email, password, authCode)
		})
		if err != nil {
			return nil, nil, appstore.App{}, err
		}
		emit("phase", "done", "name", "authenticated")
	}

	account := cfg.Apple.Account()
	switch {
	case session != nil:
		// The device's session stands in for a password login: it carries the
		// account id and cookies the App Store actually authenticates against.
		account = session.Account()
	case cfg.Apple.PasswordToken == "" || cfg.Apple.DirectoryServicesIdentifier == "":
		emit("phase", "auth-required")
		return nil, nil, appstore.App{}, errAuthRequired
	}
	var app appstore.App
	if trackID != "" && trackID != "0" {
		emit("phase", "step", "name", "lookup-track")
		app, err = as.LookupByAppID(account, trackID)
	} else {
		emit("phase", "step", "name", "lookup-bundle")
		app, err = as.LookupByBundleID(account, bundleID)
	}
	if err != nil {
		return nil, nil, appstore.App{}, err
	}

	emit("phase", "app", "bundle", app.BundleID, "version", app.Version, "track", strconv.FormatInt(app.ID, 10))

	return cfg, as, app, nil
}

func runListVersions(bundleID, trackID, email, password, authCode string) error {
	emit("phase", "step", "name", "loading-config")
	defer chownConfig()

	cfg, as, app, err := prepareAppStore(bundleID, trackID, email, password, authCode)
	if err != nil {
		return err
	}

	emit("phase", "step", "name", "list-versions")
	list, err := appstoreworkflow.WithAuth(cfg, as, app, 3, func(e appstoreworkflow.AuthEvent) {
		switch e {
		case appstoreworkflow.AuthReauth:
			emit("phase", "auth", "name", "reauth")
		case appstoreworkflow.AuthLicense:
			emit("phase", "auth", "name", "license")
		case appstoreworkflow.AuthRetryingDownload:
			emit("phase", "auth", "name", "retry")
		}
	}, func() (appstore.ListVersionsOutput, error) {
		return as.ListVersions(cfg.Apple.Account(), app)
	})
	if err != nil {
		return err
	}

	ids := newestFirst(list.ExternalVersionIDs)
	emit("phase", "version-list",
		"bundle", app.BundleID,
		"latest", list.LatestExternalVersionID,
		"count", strconv.Itoa(len(ids)))

	for i, id := range ids {
		emit("phase", "version-row",
			"index", strconv.Itoa(i),
			"external", id,
			"latest", boolString(id == list.LatestExternalVersionID),
			"status", "unfetched")
	}

	for i := 0; i < len(ids) && i < 3; i++ {
		id := ids[i]
		meta, err := appstoreworkflow.WithAuth(cfg, as, app, 3, nil, func() (appstore.VersionMetadata, error) {
			return as.GetVersionMetadata(cfg.Apple.Account(), app, id)
		})
		if err != nil {
			emit("phase", "version-row",
				"index", strconv.Itoa(i),
				"external", id,
				"latest", boolString(id == list.LatestExternalVersionID),
				"status", "error",
				"message", err.Error())
			continue
		}

		emit("phase", "version-row",
			"index", strconv.Itoa(i),
			"external", id,
			"latest", boolString(id == list.LatestExternalVersionID),
			"status", "fetched",
			"version", meta.DisplayVersion,
			"build", meta.BundleVersion,
			"devices", joinInts(meta.SupportedDevices))
	}

	emit("phase", "version-list-done")
	return nil
}

func runVersionMetadata(bundleID, trackID, email, password, authCode, externalVersionID string) error {
	if externalVersionID == "" {
		return errors.New("version metadata requires external-version-id")
	}

	emit("phase", "step", "name", "loading-config")
	defer chownConfig()

	cfg, as, app, err := prepareAppStore(bundleID, trackID, email, password, authCode)
	if err != nil {
		return err
	}

	emit("phase", "step", "name", "version-metadata")
	meta, err := appstoreworkflow.WithAuth(cfg, as, app, 3, func(e appstoreworkflow.AuthEvent) {
		switch e {
		case appstoreworkflow.AuthReauth:
			emit("phase", "auth", "name", "reauth")
		case appstoreworkflow.AuthLicense:
			emit("phase", "auth", "name", "license")
		case appstoreworkflow.AuthRetryingDownload:
			emit("phase", "auth", "name", "retry")
		}
	}, func() (appstore.VersionMetadata, error) {
		return as.GetVersionMetadata(cfg.Apple.Account(), app, externalVersionID)
	})
	if err != nil {
		return err
	}

	emit("phase", "version-row",
		"external", externalVersionID,
		"status", "fetched",
		"version", meta.DisplayVersion,
		"build", meta.BundleVersion,
		"devices", joinInts(meta.SupportedDevices))
	emit("phase", "version-metadata-done")
	return nil
}

func loadConfig() (*config.Config, error) {
	cfg, err := config.Load(configFile())
	if err == nil {
		return cfg, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return config.New(configFile()), nil
	}
	return nil, err
}

func fetchEncrypted(cfg *config.Config, paths *config.Paths, as *appstore.Client, app appstore.App, externalVersionID string) (path string, version string, cached bool, err error) {
	if externalVersionID == "" && app.Version != "" {
		encPath, err := paths.CachedEncryptedIPA(app.BundleID, app.Version)
		if err != nil {
			return "", "", false, err
		}
		if fileExists(encPath) {
			return encPath, app.Version, true, nil
		}
	}

	emit("phase", "step", "name", "prepare-download")
	ticket, err := appstoreworkflow.WithAuth(cfg, as, app, 3, func(e appstoreworkflow.AuthEvent) {
		switch e {
		case appstoreworkflow.AuthReauth:
			emit("phase", "auth", "name", "reauth")
		case appstoreworkflow.AuthLicense:
			emit("phase", "auth", "name", "license")
		case appstoreworkflow.AuthRetryingDownload:
			emit("phase", "auth", "name", "retry")
		}
	}, func() (appstore.DownloadTicket, error) {
		return as.PrepareDownload(cfg.Apple.Account(), app, externalVersionID)
	})
	if err != nil {
		return "", "", false, err
	}

	version = ticket.Version()
	encPath, err := paths.CachedEncryptedIPA(app.BundleID, version)
	if err != nil {
		return "", "", false, err
	}
	if fileExists(encPath) {
		return encPath, version, true, nil
	}

	emit("phase", "download", "version", version, "total", strconv.FormatInt(ticket.FileSize(), 10))
	_, err = as.CompleteDownload(cfg.Apple.Account(), ticket, encPath, func(cur, total int64) {
		emit("phase", "download-progress", "current", strconv.FormatInt(cur, 10), "total", strconv.FormatInt(total, 10))
	})
	if err != nil {
		return "", "", false, err
	}

	return encPath, version, false, nil
}

func newestFirst(ids []string) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[len(ids)-1-i] = id
	}
	return out
}

func joinInts(vals []int) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ",")
}

func patchForInstall(src, targetOS string, family int) (string, func(), error) {
	if targetOS == "" {
		targetOS = "15.0"
	}

	dst := strings.TrimSuffix(src, ".ipa") + ".patched.ipa"
	emit("phase", "step", "name", "patch", "ios", targetOS, "family", strconv.Itoa(family))
	res, err := pipeline.PatchForInstall(src, dst, targetOS, family, true, false)
	if err != nil {
		os.Remove(dst)
		return "", func() {}, err
	}
	if !res.MinOSChanged && res.WatchRemoved == 0 && !res.DeviceFamilyExpanded {
		os.Remove(dst)
		emit("phase", "patch", "changed", "0")
		return src, func() {}, nil
	}
	emit("phase", "patch", "changed", "1", "minos", boolString(res.MinOSChanged), "watchRemoved", strconv.Itoa(res.WatchRemoved))
	return dst, func() { os.Remove(dst) }, nil
}

func locateAppinst() (string, error) {
	if out, err := exec.Command("sh", "-c", "command -v appinst 2>/dev/null || true").Output(); err == nil {
		if p := strings.TrimSpace(string(out)); p != "" && fileExists(p) {
			return p, nil
		}
	}

	for _, p := range jailbreakCandidates(
		"/usr/bin/appinst",
		"/usr/local/bin/appinst",
		"/var/jb/usr/bin/appinst",
		"/var/jb/usr/local/bin/appinst",
	) {
		if fileExists(p) {
			return p, nil
		}
	}
	return "", nil
}

func runAppinst(appinst, ipa string) error {
	cmd := exec.Command(appinst, ipa)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line != "" {
				emit("phase", "appinst", "line", line)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("appinst: %w", err)
	}
	return nil
}

func refreshApplicationRegistration(appPath string, candidates []string, exists func(string) bool, run commandRunner) error {
	var lastErr error
	for _, candidate := range candidates {
		if !exists(candidate) {
			continue
		}
		if err := run(candidate, "-p", appPath); err != nil {
			lastErr = err
			continue
		}
		return nil
	}

	if lastErr != nil {
		return fmt.Errorf("uicache: %w", lastErr)
	}
	return errors.New("uicache not found")
}

func findInstalled(bundleID string) (installedApp, error) {
	root := "/var/containers/Bundle/Application"
	uuids, err := os.ReadDir(root)
	if err != nil {
		return installedApp{}, err
	}

	for _, uuid := range uuids {
		if !uuid.IsDir() {
			continue
		}
		uuidPath := filepath.Join(root, uuid.Name())
		children, _ := os.ReadDir(uuidPath)
		for _, child := range children {
			if child.IsDir() && strings.HasSuffix(child.Name(), ".app") {
				appPath := filepath.Join(uuidPath, child.Name())
				info, err := readInfo(appPath)
				if err != nil || info.BundleID != bundleID {
					continue
				}
				info.Path = appPath
				return info, nil
			}
		}
	}
	return installedApp{}, fmt.Errorf("installed bundle not found: %s", bundleID)
}

func readInfo(appPath string) (installedApp, error) {
	data, err := os.ReadFile(filepath.Join(appPath, "Info.plist"))
	if err != nil {
		return installedApp{}, err
	}
	var m map[string]any
	if _, err := plist.Unmarshal(data, &m); err != nil {
		return installedApp{}, err
	}
	s := func(k string) string {
		if v, ok := m[k]; ok {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}
	return installedApp{
		BundleID: s("CFBundleIdentifier"),
		Name:     firstNonEmpty(s("CFBundleDisplayName"), s("CFBundleName")),
		Version:  firstNonEmpty(s("CFBundleShortVersionString"), s("CFBundleVersion")),
	}, nil
}

func iosVersion() string {
	data, err := os.ReadFile("/System/Library/CoreServices/SystemVersion.plist")
	if err != nil {
		return ""
	}
	var m map[string]any
	if _, err := plist.Unmarshal(data, &m); err != nil {
		return ""
	}
	if v, ok := m["ProductVersion"]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func deviceFamily() int {
	out, err := exec.Command("uname", "-m").Output()
	if err != nil {
		if runtime.GOOS == "ios" {
			return 1
		}
		return 0
	}
	machine := strings.TrimSpace(string(out))
	if strings.HasPrefix(machine, "iPad") {
		return 2
	}
	return 1
}

func emit(kv ...string) {
	fmt.Print("@evt")
	for i := 0; i+1 < len(kv); i += 2 {
		fmt.Printf(" %s=%q", kv[i], kv[i+1])
	}
	fmt.Println()
}

func fail(code int, reason, message string) {
	emit("phase", "failed", "reason", reason, "message", message)
	fmt.Fprintln(os.Stderr, message)
	os.Exit(code)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func boolString(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func verifyCryptid(ipa string) error {
	emit("event", "verify", "phase", "begin")

	res, err := pipeline.Verify(ipa, "", false)
	if err != nil {
		return err
	}

	emit("event", "verify", "phase", "scanned",
		"scanned", strconv.Itoa(res.Scanned),
		"encrypted", strconv.Itoa(len(res.StillEncrypted)),
		"skipped", strconv.Itoa(len(res.Skipped)))

	for _, name := range res.StillEncrypted {
		emit("event", "verify", "phase", "encrypted", "name", name)
	}
	for _, name := range res.Skipped {
		emit("event", "verify", "phase", "skipped", "name", name)
	}

	if len(res.StillEncrypted) > 0 {
		return fmt.Errorf("%d binary(ies) still have cryptid != 0", len(res.StillEncrypted))
	}

	emit("event", "verify", "phase", "done")
	return nil
}

func runDecryptHelper(helper, bundleID, bundlePath, outIPA string) error {
	if helper == "" || bundlePath == "" || outIPA == "" {
		return errors.New("decrypt helper, bundle path, and output IPA are required")
	}

	cmd := exec.Command(helper, bundleID, bundlePath, outIPA)
	cmd.Dir = "/var/root"
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		pathEnv = "/var/jb/usr/bin:/var/jb/usr/sbin:/usr/bin:/bin:/usr/sbin:/sbin"
	}
	cmd.Env = append(os.Environ(),
		"PATH="+pathEnv,
		"HOME=/var/root",
		"TMPDIR=/tmp",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func configFile() string {
	return filepath.Join(rootDir, "config.json")
}

func jailbreakCandidates(paths ...string) []string {
	out := append([]string(nil), paths...)
	if jbroot := findJBRootCommand(); jbroot != "" {
		for _, p := range paths {
			converted, err := exec.Command(jbroot, p).Output()
			if err == nil {
				if s := strings.TrimSpace(string(converted)); s != "" {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

func findJBRootCommand() string {
	if p, err := exec.LookPath("jbroot"); err == nil {
		return p
	}
	for _, p := range []string{
		"/usr/bin/jbroot",
		"/usr/local/bin/jbroot",
		"/var/jb/usr/bin/jbroot",
		"/var/jb/usr/local/bin/jbroot",
	} {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

func chownConfig() {
	_ = syscall.Chown(rootDir, 501, 501)
	_ = syscall.Chown(configFile(), 501, 501)
	_ = syscall.Chown(configFile()+".tmp", 501, 501)
}
