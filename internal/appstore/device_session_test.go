package appstore

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"howett.net/plist"
)

type stubJar struct {
	cookies []*http.Cookie
}

func (s *stubJar) Cookies(*url.URL) []*http.Cookie     { return s.cookies }
func (s *stubJar) SetCookies(*url.URL, []*http.Cookie) {}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}

	return u
}

func TestSessionFromCookiesDerivesDSIDFromMyacinfo(t *testing.T) {
	payload, err := plist.Marshal(map[string]any{"DsPersonId": "1234567890", "appleId": "someone@example.com"}, plist.XMLFormat)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	cookies := []*http.Cookie{
		{Name: "unrelated", Value: "ignored"},
		{Name: "myacinfo", Value: base64.StdEncoding.EncodeToString(payload)},
		{Name: "mz", Value: "something"},
	}

	session := sessionFromCookies(cookies)

	if session.DSID != "1234567890" {
		t.Fatalf("DSID = %q, want 1234567890", session.DSID)
	}

	if len(session.Cookies) != 2 {
		t.Fatalf("kept %d cookies, want myacinfo and mz", len(session.Cookies))
	}
}

func TestSessionFromCookiesPrefersExplicitDSIDCookie(t *testing.T) {
	cookies := []*http.Cookie{
		{Name: "dsid", Value: "9999999999"},
		{Name: "myacinfo", Value: "not-base64-!!"},
	}

	session := sessionFromCookies(cookies)

	if session.DSID != "9999999999" {
		t.Fatalf("DSID = %q, want the dsid cookie", session.DSID)
	}
}

func TestDSIDFromMyacinfoFallsBackToRegex(t *testing.T) {
	raw := "garbage \"DsPersonId\":\"5555555555\" trailing"

	if got := dsidFromMyacinfo(raw); got != "5555555555" {
		t.Fatalf("dsidFromMyacinfo = %q, want 5555555555", got)
	}
}

func TestLoadDeviceSessionFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cookies.binarycookies")

	payload, err := plist.Marshal(map[string]any{"DsPersonId": "1112223333"}, plist.XMLFormat)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	data := buildBinaryCookieFile(t, []binaryCookieFixture{
		{domain: ".apple.com", name: "myacinfo", path: "/", value: base64.StdEncoding.EncodeToString(payload), flags: cookieFlagSecure},
		{domain: ".example.com", name: "irrelevant", path: "/", value: "x"},
	})

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	session, err := LoadDeviceSession([]string{path}, "", "143441", "someone@example.com")
	if err != nil {
		t.Fatalf("LoadDeviceSession: %v", err)
	}

	if session.DSID != "1112223333" {
		t.Fatalf("DSID = %q, want 1112223333", session.DSID)
	}

	if session.StoreFront != "143441" {
		t.Fatalf("storefront = %q, want 143441", session.StoreFront)
	}

	if len(session.Cookies) != 1 || session.Cookies[0].Name != "myacinfo" {
		t.Fatalf("cookies = %v, want only myacinfo", session.Cookies)
	}

	if !session.Usable() {
		t.Fatal("session should be usable")
	}

	account := session.Account()
	if account.DirectoryServicesID != "1112223333" || account.StoreFront != "143441" {
		t.Fatalf("account = %+v", account)
	}

	if account.PasswordToken != "" {
		t.Fatal("a device session must not carry a password token")
	}
}

func TestLoadDeviceSessionRejectsJarWithoutSessionCookies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cookies.binarycookies")

	data := buildBinaryCookieFile(t, []binaryCookieFixture{
		{domain: ".example.com", name: "irrelevant", path: "/", value: "x"},
	})

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	if _, err := LoadDeviceSession([]string{path}, "", "", ""); err == nil {
		t.Fatal("expected an error when no App Store session cookies are present")
	}
}

func TestLoadDeviceSessionNeedsDSID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cookies.binarycookies")

	data := buildBinaryCookieFile(t, []binaryCookieFixture{
		{domain: ".apple.com", name: "myacinfo", path: "/", value: "not-a-plist"},
	})

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	if _, err := LoadDeviceSession([]string{path}, "", "", ""); err == nil {
		t.Fatal("expected an error when the DSID cannot be determined")
	}

	// An explicit DSID is the documented escape hatch.
	session, err := LoadDeviceSession([]string{path}, "4445556666", "", "")
	if err != nil {
		t.Fatalf("LoadDeviceSession with explicit DSID: %v", err)
	}

	if session.DSID != "4445556666" {
		t.Fatalf("DSID = %q, want the explicit override", session.DSID)
	}
}

func TestDiscoverCookieJarsExpandsGlobs(t *testing.T) {
	dir := t.TempDir()
	appDir := filepath.Join(dir, "Containers", "Data", "Application", "AAAA")

	if err := os.MkdirAll(filepath.Join(appDir, "Library", "Cookies"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	jarPath := filepath.Join(appDir, "Library", "Cookies", "Cookies.binarycookies")
	if err := os.WriteFile(jarPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	pattern := filepath.Join(dir, "Containers", "Data", "Application", "*", "Library", "Cookies", "Cookies.binarycookies")

	found := DiscoverCookieJars([]string{pattern, pattern})
	if len(found) != 1 || found[0] != jarPath {
		t.Fatalf("DiscoverCookieJars = %v, want [%s]", found, jarPath)
	}
}

func TestMergeJarServesDeviceCookiesOnlyForMatchingHosts(t *testing.T) {
	jar := &mergeJar{
		base: &stubJar{cookies: []*http.Cookie{{Name: "base"}}},
		device: []*http.Cookie{
			{Name: "myacinfo", Domain: "apple.com", Path: "/", Value: "s", Secure: true},
		},
	}

	apple := jar.Cookies(mustURL(t, "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeDownload"))
	if len(apple) != 2 {
		t.Fatalf("apple host got %d cookies, want base + device", len(apple))
	}

	other := jar.Cookies(mustURL(t, "https://example.com/"))
	if len(other) != 1 || other[0].Name != "base" {
		t.Fatalf("unrelated host got %v, want only the base cookie", other)
	}

	plain := jar.Cookies(mustURL(t, "http://buy.itunes.apple.com/"))
	if len(plain) != 1 {
		t.Fatalf("secure cookie leaked over plain http: %v", plain)
	}
}

func TestCookieMatchesURL(t *testing.T) {
	cases := []struct {
		name   string
		cookie *http.Cookie
		url    string
		want   bool
	}{
		{"suffix match", &http.Cookie{Domain: ".apple.com", Path: "/"}, "https://init.itunes.apple.com/x", true},
		{"exact host", &http.Cookie{Domain: "itunes.apple.com", Path: "/"}, "https://itunes.apple.com/", true},
		{"domain not a suffix", &http.Cookie{Domain: ".apple.com", Path: "/"}, "https://apple.com.evil.test/", false},
		{"path miss", &http.Cookie{Domain: ".apple.com", Path: "/private/"}, "https://buy.itunes.apple.com/public", false},
		{"empty domain matches all", &http.Cookie{Path: "/"}, "https://anywhere.test/", true},
	}

	for _, tc := range cases {
		if got := cookieMatchesURL(tc.cookie, mustURL(t, tc.url)); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestDeviceSessionSnapshotDoesNotLeakValues(t *testing.T) {
	session := &DeviceSession{
		DSID: "1234567890",
		Cookies: []*http.Cookie{
			{Name: "myacinfo", Value: "super-secret"},
		},
	}

	snapshot := session.SessionSnapshot()

	if snapshot == "" {
		t.Fatal("snapshot is empty")
	}

	if strings.Contains(snapshot, "super-secret") {
		t.Fatalf("snapshot leaked a cookie value: %s", snapshot)
	}
}

func TestScanDeviceSessionExplainsEachFailure(t *testing.T) {
	dir := t.TempDir()

	sessionPayload, err := plist.Marshal(map[string]any{"DsPersonId": "1234567890"}, plist.XMLFormat)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	plainJar := filepath.Join(dir, "plain.binarycookies")
	writeJar(t, plainJar, []binaryCookieFixture{
		{domain: ".example.com", name: "nope", path: "/", value: "x"},
	})

	// Session cookies, but nothing that identifies the account.
	noDSIDJar := filepath.Join(dir, "nodsaid.binarycookies")
	writeJar(t, noDSIDJar, []binaryCookieFixture{
		{domain: ".apple.com", name: "myacinfo", path: "/", value: "not-a-plist"},
	})

	sessionJar := filepath.Join(dir, "session.binarycookies")
	writeJar(t, sessionJar, []binaryCookieFixture{
		{domain: ".apple.com", name: "myacinfo", path: "/", value: base64.StdEncoding.EncodeToString(sessionPayload)},
	})

	cases := []struct {
		name     string
		patterns []string
		want     string
	}{
		{"no patterns", nil, "no cookie-jar paths were configured"},
		{"nothing matched", []string{filepath.Join(dir, "missing-*.binarycookies")}, "no cookie jars matched"},
		{"readable but no session", []string{plainJar}, "none held an App Store session"},
		{"session without a DSID", []string{noDSIDJar}, "carries no Apple ID (DSID)"},
	}

	for _, tc := range cases {
		report := ScanDeviceSession(tc.patterns, "", "", "")
		if report.Session != nil {
			t.Fatalf("%s: expected no session", tc.name)
		}

		if !strings.Contains(report.Reason(), tc.want) {
			t.Errorf("%s: reason = %q, want it to contain %q", tc.name, report.Reason(), tc.want)
		}

		if _, err := LoadDeviceSession(tc.patterns, "", "", ""); err == nil {
			t.Errorf("%s: LoadDeviceSession should have failed", tc.name)
		}
	}

	report := ScanDeviceSession([]string{sessionJar}, "", "143441", "")
	if report.Session == nil {
		t.Fatalf("expected a session, got: %s", report.Reason())
	}

	if report.Reason() != "" {
		t.Fatalf("Reason() = %q, want empty for a good session", report.Reason())
	}

	if len(report.WithSessionCookies) != 1 {
		t.Fatalf("WithSessionCookies = %v", report.WithSessionCookies)
	}

	if !strings.Contains(report.Describe(), "session:") {
		t.Fatal("Describe() should report the session")
	}
}

func TestScanDeviceSessionAcceptsAnExplicitDSIDWhenCookiesLackOne(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nodsaid.binarycookies")

	writeJar(t, path, []binaryCookieFixture{
		{domain: ".apple.com", name: "myacinfo", path: "/", value: "not-a-plist"},
	})

	report := ScanDeviceSession([]string{path}, "5555555555", "", "")
	if report.Session == nil {
		t.Fatalf("expected a session with an explicit DSID, got: %s", report.Reason())
	}

	if report.Session.DSID != "5555555555" {
		t.Fatalf("DSID = %q, want the explicit override", report.Session.DSID)
	}
}

func writeJar(t *testing.T, path string, cookies []binaryCookieFixture) {
	t.Helper()

	if err := os.WriteFile(path, buildBinaryCookieFile(t, cookies), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestScanDeviceSessionReportsUndecodableJars(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.binarycookies")

	if err := os.WriteFile(path, []byte("this is not a cook file"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	report := ScanDeviceSession([]string{path}, "", "", "")

	if report.Session != nil {
		t.Fatal("expected no session")
	}

	if len(report.Jars) != 0 {
		t.Fatalf("Jars = %v, want none", report.Jars)
	}

	if len(report.Failed) != 1 {
		t.Fatalf("Failed = %v, want the undecodable jar", report.Failed)
	}

	if !strings.Contains(report.Reason(), "none decoded") {
		t.Errorf("reason = %q, want it to name the decode failure", report.Reason())
	}

	if !strings.Contains(report.Describe(), "undecodable") {
		t.Error("Describe() should list the undecodable jar")
	}
}

func TestScanDeviceSessionNamesTheCookiesItSaw(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "other.binarycookies")

	writeJar(t, path, []binaryCookieFixture{
		{domain: ".apple.com", name: "somethingElse", path: "/", value: "x"},
		{domain: ".apple.com", name: "anotherOne", path: "/", value: "y"},
	})

	report := ScanDeviceSession([]string{path}, "", "", "")
	if report.Session != nil {
		t.Fatal("expected no session")
	}

	reason := report.Reason()

	for _, name := range []string{"somethingElse", "anotherOne"} {
		if !strings.Contains(reason, name) {
			t.Errorf("reason %q should name the cookie %q", reason, name)
		}
	}

	if len(report.Jars) != 1 || report.Jars[0].Cookies != 2 {
		t.Fatalf("Jars = %v, want one jar with two cookies", report.Jars)
	}
}

func TestPatternMatchesCountsPerPattern(t *testing.T) {
	dir := t.TempDir()
	appDir := filepath.Join(dir, "Data", "Application", "AAAA", "Library", "Cookies")

	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(appDir, "Cookies.binarycookies"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	hit := filepath.Join(dir, "Data", "*", "*", "Library", "Cookies", "*.binarycookies")
	miss := filepath.Join(dir, "Nowhere", "*", "*.binarycookies")

	matches := PatternMatches([]string{hit, miss})
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want 2", len(matches))
	}

	if matches[0].Matches != 1 {
		t.Errorf("hit pattern matched %d files, want 1", matches[0].Matches)
	}

	if matches[1].Matches != 0 {
		t.Errorf("miss pattern matched %d files, want 0", matches[1].Matches)
	}
}
