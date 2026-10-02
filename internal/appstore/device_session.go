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
	"sort"
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
		// User apps: /var/mobile/Containers/Data/Application/<uuid>.
		"/var/mobile/Containers/Data/*/*/Library/Cookies/*.binarycookies",
		// System daemons (appstored, itunesstored, storeaccountd) keep their
		// containers in a separate tree entirely.
		"/var/containers/Data/*/*/Library/Cookies/*.binarycookies",
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

// DeviceSessionReport records what a session scan saw, so a failure can name
// its cause instead of reporting "no session".
type DeviceSessionReport struct {
	Patterns           []string
	Found              []string
	Readable           []string
	WithSessionCookies []string
	// Jars describes every readable jar that decoded, including ones holding
	// nothing useful: when the scan finds no session, the cookie names in here
	// are what says whether the session is somewhere else or named something
	// else.
	Jars []JarSummary
	// Failed lists readable jars that would not decode at all.
	Failed []string
	// PatternMatches says how many files each glob matched, so a report can
	// show which places were actually consulted.
	PatternMatches []PatternMatch
	Session        *DeviceSession
}

// PatternMatch records how many files one glob matched.
type PatternMatch struct {
	Pattern string
	Matches int
	Err     string
}

// PatternMatches evaluates each pattern on its own. A pattern that matches
// nothing is the difference between "the session is not there" and "we never
// looked".
func PatternMatches(patterns []string) []PatternMatch {
	out := make([]PatternMatch, 0, len(patterns))

	for _, pattern := range patterns {
		match := PatternMatch{Pattern: pattern}

		matches, err := filepath.Glob(pattern)
		if err != nil {
			match.Err = err.Error()
		} else {
			match.Matches = len(matches)
		}

		out = append(out, match)
	}

	return out
}

// JarSummary is one decoded cookie jar.
type JarSummary struct {
	Path    string
	Cookies int
	Names   []string
}

// CookieNameCounts tallies cookie names across every decoded jar. A candidate
// session cookie that shows up here but not in the session is a selection bug;
// one that does not show up at all means the session is not in these files.
func (r DeviceSessionReport) CookieNameCounts() map[string]int {
	counts := map[string]int{}

	for _, jar := range r.Jars {
		for _, name := range jar.Names {
			counts[name]++
		}
	}

	return counts
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
	case len(r.Jars) == 0:
		return fmt.Sprintf("%d cookie jars were readable but none decoded - the on-disk format is not what this build parses", len(r.Readable))
	case len(r.WithSessionCookies) == 0:
		return fmt.Sprintf("%d cookie jars decoded but none held an App Store session (iOS keeps the App Store sign-in in StoreServices, not in cookies); cookie names seen: %s",
			len(r.Jars), summariseCookieNames(r.CookieNameCounts()))
	default:
		return "an App Store session was found but it carries no Apple ID (DSID) - pass --dsid to override"
	}
}

// Describe renders the report for a terminal, one fact per line.
func (r DeviceSessionReport) Describe() string {
	const maxListed = 40

	var b strings.Builder

	fmt.Fprintf(&b, "patterns:            %d\n", len(r.Patterns))
	fmt.Fprintf(&b, "cookie jars found:   %d\n", len(r.Found))
	fmt.Fprintf(&b, "  readable:          %d\n", len(r.Readable))
	fmt.Fprintf(&b, "  decoded:           %d\n", len(r.Jars))
	fmt.Fprintf(&b, "  with session:      %d\n", len(r.WithSessionCookies))

	for _, match := range r.PatternMatches {
		if match.Err != "" {
			fmt.Fprintf(&b, "    pattern %s -> error: %s\n", match.Pattern, match.Err)
			continue
		}

		fmt.Fprintf(&b, "    pattern %s -> %d files\n", match.Pattern, match.Matches)
	}

	listed := 0

	for _, jar := range r.Jars {
		if jar.Cookies == 0 {
			continue
		}

		if listed == maxListed {
			fmt.Fprintf(&b, "    ... more jars with cookies omitted\n")
			break
		}

		fmt.Fprintf(&b, "    %s (%d cookies: %s)\n", jar.Path, jar.Cookies, strings.Join(jar.Names, " "))
		listed++
	}

	for _, path := range r.Failed {
		fmt.Fprintf(&b, "    undecodable: %s\n", path)
	}

	names := r.CookieNameCounts()
	if len(names) > 0 {
		fmt.Fprintf(&b, "cookie names seen:   %s\n", summariseCookieNames(names))
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

func summariseCookieNames(counts map[string]int) string {
	if len(counts) == 0 {
		return "(none)"
	}

	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}

	sort.Strings(names)

	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s(%d)", name, counts[name]))
	}

	const maxNames = 40
	if len(parts) > maxNames {
		parts = append(parts[:maxNames], fmt.Sprintf("... and %d more", len(names)-maxNames))
	}

	return strings.Join(parts, " ")
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
	report.PatternMatches = PatternMatches(patterns)
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
			report.Failed = append(report.Failed, jarPath)
			continue
		}

		report.Jars = append(report.Jars, describeJar(jarPath, cookies))

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

func describeJar(path string, cookies []*http.Cookie) JarSummary {
	summary := JarSummary{Path: path, Cookies: len(cookies)}

	seen := map[string]bool{}

	for _, c := range cookies {
		if seen[c.Name] {
			continue
		}

		seen[c.Name] = true

		summary.Names = append(summary.Names, c.Name)
	}

	sort.Strings(summary.Names)

	return summary
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
