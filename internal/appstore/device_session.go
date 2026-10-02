package appstore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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
// live on iOS. The per-application jars come first because that is where the
// App Store and the store daemons keep theirs.
func DefaultCookieJarPatterns() []string {
	return []string{
		"/var/mobile/Containers/Data/Application/*/Library/Cookies/Cookies.binarycookies",
		"/private/var/mobile/Containers/Data/Application/*/Library/Cookies/Cookies.binarycookies",
		"/var/mobile/Library/Cookies/Cookies.binarycookies",
		"/private/var/mobile/Library/Cookies/Cookies.binarycookies",
		"/rootfs/var/mobile/Containers/Data/Application/*/Library/Cookies/Cookies.binarycookies",
		"/rootfs/var/mobile/Library/Cookies/Cookies.binarycookies",
	}
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

// LoadDeviceSession reads the first cookie jar that yields a usable session.
//
// dsid and storeFront are caller-supplied overrides (the app gets them from
// StoreServices / the device locale); they win over anything derived from the
// cookies, and a session that ends up without a DSID is rejected because the
// App Store needs the X-Dsid header.
func LoadDeviceSession(jars []string, dsid, storeFront, email string) (*DeviceSession, error) {
	if len(jars) == 0 {
		return nil, errors.New("device session: no cookie jars found")
	}

	var (
		lastErr error
		sources []string
	)

	for _, jarPath := range jars {
		data, err := os.ReadFile(jarPath)
		if err != nil {
			lastErr = err
			continue
		}

		cookies, err := ParseBinaryCookies(data)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", jarPath, err)
			continue
		}

		sources = append(sources, jarPath)

		session := sessionFromCookies(cookies)
		if len(session.Cookies) == 0 {
			continue
		}

		session.Sources = sources
		session.DSID = firstNonEmpty(dsid, session.DSID)
		session.StoreFront = storeFront
		session.Email = email

		if !session.Usable() {
			lastErr = fmt.Errorf("%s: session cookies found but no Apple ID (DSID)", jarPath)
			continue
		}

		return session, nil
	}

	if lastErr == nil {
		lastErr = errors.New("device session: no App Store session cookies in any cookie jar")
	}

	return nil, lastErr
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
