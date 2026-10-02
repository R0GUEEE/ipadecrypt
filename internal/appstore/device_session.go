package appstore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"howett.net/plist"
)

// DeviceSession is an App Store session lifted from the device itself.
//
// It exists because of a hard constraint: Apple's `authenticate` endpoint
// requires the X-Apple-ActionSignature header, which only the SAP signer can
// produce - and SAP runs a prebuilt x86_64 Unicorn library (internal/sap/unicorn)
// that simply does not exist for iOS. A phone therefore cannot *log in* to the
// Configurator App Store protocol at all.
//
// It does not have to. Every other App Store call - lookups, version listings,
// download tickets, purchases - is sent unsigned, and `volumeDownload` (which
// backs ListVersions and GetVersionMetadata) authenticates purely from the
// session cookies plus the X-Dsid header. The phone is already signed in to its
// own App Store, so we reuse that session instead of authenticating again.
type DeviceSession struct {
	// DSID is the Directory Services person id (Apple's numeric account id).
	DSID string
	// StoreFront is the numeric App Store front, e.g. "143441" for the US.
	StoreFront string
	// Email is the Apple ID address, when the caller knows it.
	Email string
	// Pod is an optional store pod prefix ("42"), as returned by a login.
	Pod string
	// Cookies are the live session cookies taken from the device's cookie jar.
	Cookies []*http.Cookie
	// Sources lists the cookie files that were read, most useful first.
	Sources []string
}

// Account renders the session in the shape the App Store client wants. It has
// no PasswordToken - that is precisely the point.
func (s *DeviceSession) Account() *Account {
	if s == nil {
		return nil
	}

	return &Account{
		Email:               s.Email,
		DirectoryServicesID: s.DSID,
		StoreFront:          s.StoreFront,
		Pod:                 s.Pod,
	}
}

// Usable reports whether the session carries enough to make an authenticated
// App Store call: an account id and at least one session cookie.
func (s *DeviceSession) Usable() bool {
	return s != nil && s.DSID != "" && len(s.Cookies) > 0
}

// deviceSessionCookieNames are the MZFinance session cookies. `myacinfo` is the
// one that actually carries the account; the others are kept because Apple has
// moved between them over time and sending a superset is harmless.
var deviceSessionCookieNames = []string{"myacinfo", "mz", "mzf_in", "itctx", "dsid"}

// DefaultCookieJarPatterns are the places a signed-in App Store session can
// live on iOS.
//
// The wildcard depth matters: the App Store app is an ordinary application
// container, but the processes that actually hold the MZFinance session
// (appstored, itunesstored, storeaccountd) are daemons, and daemon containers
// live under a different class directory. Globbing every class is what makes
// this work without knowing which process owns the session.
func DefaultCookieJarPatterns() []string {
	patterns := []string{
		"/var/mobile/Containers/Data/*/*/Library/Cookies/*.binarycookies",
		"/var/mobile/Library/Cookies/*.binarycookies",
	}

	// /var is a symlink to /private/var on iOS, and RootHide relocates the
	// whole tree under /rootfs. Scan the other spellings too rather than
	// guessing which one the running jailbreak exposes.
	extra := make([]string, 0, len(patterns)*2)
	for _, pattern := range patterns {
		extra = append(extra, "/private"+pattern, "/rootfs"+pattern)
	}

	return append(patterns, extra...)
}

// DeviceSessionReport records what a session scan saw, so a failure can name
// its cause instead of reporting "no session".
type DeviceSessionReport struct {
	Patterns           []string
	Found              []string
	Readable           []string
	WithSessionCookies []string
	Session            *DeviceSession
}

// Reason explains why no session was produced. Empty when one was.
func (r DeviceSessionReport) Reason() string {
	if r.Session != nil {
		return ""
	}

	switch {
	case len(r.Patterns) == 0:
		return "no cookie-jar paths were configured"
	case len(r.Found) == 0:
		return "no cookie jars matched the App Store paths - the helper cannot see any app container"
	case len(r.Readable) == 0:
		return fmt.Sprintf("%d cookie jars matched but none could be read - the helper is sandboxed away from them", len(r.Found))
	case len(r.WithSessionCookies) == 0:
		return fmt.Sprintf("%d cookie jars readable but none held an App Store session - open the App Store on the device while signed in", len(r.Readable))
	default:
		return "an App Store session was found but it carries no Apple ID (DSID) - pass --dsid to override"
	}
}

// Describe renders the report for a terminal, one fact per line.
func (r DeviceSessionReport) Describe() string {
	var b strings.Builder

	fmt.Fprintf(&b, "patterns:            %d\n", len(r.Patterns))
	fmt.Fprintf(&b, "cookie jars found:   %d\n", len(r.Found))
	fmt.Fprintf(&b, "  readable:          %d\n", len(r.Readable))
	fmt.Fprintf(&b, "  with session:      %d\n", len(r.WithSessionCookies))

	for _, path := range r.Found {
		b.WriteString("    " + path + "\n")
	}

	if r.Session != nil {
		fmt.Fprintf(&b, "session:             dsidLength=%d storefront=%q cookies=%d\n",
			len(r.Session.DSID), r.Session.StoreFront, len(r.Session.Cookies))

		for _, c := range r.Session.Cookies {
			fmt.Fprintf(&b, "    cookie %s (domain=%s)\n", c.Name, c.Domain)
		}
	} else {
		fmt.Fprintf(&b, "session:             none (%s)\n", r.Reason())
	}

	return b.String()
}

// ScanDeviceSession reads every candidate jar and reports what it found,
// whether or not a usable session came out of it.
//
// dsid and storeFront are caller-supplied overrides (the app gets them from
// StoreServices and the device locale); they win over anything derived from
// the cookies, and a session that ends up without a DSID is rejected because
// the App Store needs the X-Dsid header.
func ScanDeviceSession(patterns []string, dsid, storeFront, email string) DeviceSessionReport {
	report := DeviceSessionReport{Patterns: patterns}
	report.Found = DiscoverCookieJars(patterns)

	var sources []string

	for _, jarPath := range report.Found {
		data, err := os.ReadFile(jarPath)
		if err != nil {
			continue
		}

		report.Readable = append(report.Readable, jarPath)

		cookies, err := ParseBinaryCookies(data)
		if err != nil {
			continue
		}

		session := sessionFromCookies(cookies)
		if len(session.Cookies) == 0 {
			continue
		}

		report.WithSessionCookies = append(report.WithSessionCookies, jarPath)
		sources = append(sources, jarPath)

		if report.Session != nil {
			continue
		}

		session.Sources = append([]string(nil), sources...)
		session.DSID = firstNonEmpty(dsid, session.DSID)
		session.StoreFront = storeFront
		session.Email = email

		if session.Usable() {
			report.Session = session
		}
	}

	return report
}

// LoadDeviceSession is ScanDeviceSession for callers that only want the
// session, with the report's reason as the error.
func LoadDeviceSession(jars []string, dsid, storeFront, email string) (*DeviceSession, error) {
	report := ScanDeviceSession(jars, dsid, storeFront, email)
	if report.Session != nil {
		return report.Session, nil
	}

	return nil, fmt.Errorf("device session: %s", report.Reason())
}

// DiscoverCookieJars expands the given glob patterns, de-duplicating and
// keeping the first-seen order so callers can present a stable "most likely
// source" list.
func DiscoverCookieJars(patterns []string) []string {
	seen := map[string]bool{}

	var out []string

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}

		for _, match := range matches {
			if seen[match] {
				continue
			}

			if info, err := os.Stat(match); err != nil || info.IsDir() {
				continue
			}

			seen[match] = true

			out = append(out, match)
		}
	}

	return out
}

func sessionFromCookies(cookies []*http.Cookie) *DeviceSession {
	session := &DeviceSession{}

	for _, c := range cookies {
		if !isDeviceSessionCookie(c.Name) {
			continue
		}

		if session.DSID == "" && strings.EqualFold(c.Name, "dsid") {
			session.DSID = strings.TrimSpace(c.Value)
		}

		session.Cookies = append(session.Cookies, c)
	}

	if session.DSID == "" {
		for _, c := range session.Cookies {
			if strings.EqualFold(c.Name, "myacinfo") {
				session.DSID = dsidFromMyacinfo(c.Value)
				break
			}
		}
	}

	return session
}

func isDeviceSessionCookie(name string) bool {
	for _, wanted := range deviceSessionCookieNames {
		if strings.EqualFold(name, wanted) {
			return true
		}
	}

	return false
}

var dsidPattern = regexp.MustCompile(`(?i)"?(?:DsPersonId|dsid)"?\s*[:=]\s*"?(\d{5,12})`)

// dsidFromMyacinfo digs the account id out of the myacinfo cookie, which is a
// base64 (sometimes twice) plist describing the session. Best effort: the
// caller can always pass an explicit DSID instead.
func dsidFromMyacinfo(value string) string {
	for _, decoded := range decodeBase64Layers(value) {
		var payload map[string]any
		if _, err := plist.Unmarshal(decoded, &payload); err == nil {
			for _, key := range []string{"DsPersonId", "dsPersonId", "dsid"} {
				if raw, ok := payload[key]; ok {
					if s := strings.TrimSpace(fmt.Sprintf("%v", raw)); s != "" && s != "<nil>" {
						return s
					}
				}
			}
		}

		if m := dsidPattern.FindSubmatch(decoded); m != nil {
			return string(m[1])
		}
	}

	if m := dsidPattern.FindStringSubmatch(value); m != nil {
		return m[1]
	}

	return ""
}

func decodeBase64Layers(value string) [][]byte {
	var out [][]byte

	current := []byte(strings.TrimSpace(value))

	for range 2 {
		decoded, ok := decodeBase64(current)
		if !ok {
			break
		}

		out = append(out, decoded)
		current = decoded
	}

	return out
}

func decodeBase64(data []byte) ([]byte, bool) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := encoding.DecodeString(string(data)); err == nil && len(decoded) > 0 {
			return decoded, true
		}
	}

	return nil, false
}

// mergeJar serves the device's session cookies alongside the persistent jar.
//
// The device cookies are returned live and never stored: they are read-only
// copies of someone else's session, and keeping them out of the jar means a
// mis-parsed expiry can never silently delete them.
type mergeJar struct {
	base   http.CookieJar
	device []*http.Cookie
}

func (j *mergeJar) Cookies(u *url.URL) []*http.Cookie {
	out := j.base.Cookies(u)

	if u == nil {
		return out
	}

	for _, c := range j.device {
		if cookieMatchesURL(c, u) {
			out = append(out, c)
		}
	}

	return out
}

func (j *mergeJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.base.SetCookies(u, cookies)
}

// SessionSnapshot renders just the non-secret facts about the live cookie set,
// for diagnostics.
func (s *DeviceSession) SessionSnapshot() string {
	if s == nil {
		return "{}"
	}

	names := make([]string, 0, len(s.Cookies))
	for _, c := range s.Cookies {
		names = append(names, c.Name)
	}

	out, err := json.Marshal(map[string]any{
		"dsid":       s.DSID,
		"storeFront": s.StoreFront,
		"cookies":    names,
		"sources":    len(s.Sources),
	})
	if err != nil {
		return "{}"
	}

	return string(out)
}

func cookieMatchesURL(c *http.Cookie, u *url.URL) bool {
	if c == nil || u == nil {
		return false
	}

	if c.Secure && u.Scheme != "https" {
		return false
	}

	host := strings.ToLower(u.Hostname())
	domain := strings.ToLower(strings.TrimPrefix(c.Domain, "."))

	if domain != "" && host != domain && !strings.HasSuffix(host, "."+domain) {
		return false
	}

	path := c.Path
	if path == "" {
		path = "/"
	}

	return strings.HasPrefix(u.Path, path)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}

	return ""
}
