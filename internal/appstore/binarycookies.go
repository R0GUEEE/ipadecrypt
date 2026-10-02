package appstore

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"
)

// Apple stores HTTP cookies in a compact binary file ("Cookies.binarycookies",
// magic "cook"). On iOS this is where the App Store's authenticated session
// lives, and reusing that session is how the on-device helper talks to the App
// Store without an X-Apple-ActionSignature - see device_session.go.
//
// Layout:
//
//	file:  "cook" | uint32 BE page count | uint32 BE page size * N | pages
//	page:  uint32 BE marker | uint32 LE cookie count | uint32 LE cookie
//	       offsets | uint32 LE footer
//	cookie: uint32 LE size | uint32 LE version | uint32 LE flags |
//	        uint32 LE has-port | uint32 LE domain | name | path | value |
//	        comment offsets | float64 LE expiry | float64 LE creation |
//	        [uint32 LE port] | NUL-terminated strings
//
// The header size is *not* hardcoded: every string offset is relative to the
// start of the record, so the first (smallest) offset is exactly where the
// fixed-size header ends. That keeps the parser correct across the two header
// variants that ship in the wild.

const (
	binaryCookiesMagic = "cook"

	cookieFlagSecure   = 0x1
	cookieFlagHTTPOnly = 0x4

	// Apple timestamps count seconds from 2001-01-01, not from the Unix epoch.
	appleEpochOffset = 978307200

	// Offsets of the four string pointers inside a cookie record.
	cookieDomainOffset = 16
	cookieNameOffset   = 20
	cookiePathOffset   = 24
	cookieValueOffset  = 28
	cookieFlagsOffset  = 8
	cookieExpiryOffset = 36

	cookieRecordMinSize = 36
)

// ParseBinaryCookies decodes an Apple Cookies.binarycookies blob.
//
// Individual malformed records are skipped rather than failing the whole file:
// a phone has dozens of these files and one bad page should not cost us the
// session in another.
func ParseBinaryCookies(data []byte) ([]*http.Cookie, error) {
	if len(data) < 8 || string(data[:4]) != binaryCookiesMagic {
		return nil, errors.New("binarycookies: not a Cookies.binarycookies file")
	}

	pages := int(binary.BigEndian.Uint32(data[4:8]))
	if pages <= 0 || 8+pages*4 > len(data) {
		return nil, fmt.Errorf("binarycookies: implausible page count %d", pages)
	}

	sizes := make([]int, pages)
	total := 8 + pages*4
	for i := range sizes {
		sizes[i] = int(binary.BigEndian.Uint32(data[8+i*4:]))
		if sizes[i] < 8 {
			return nil, fmt.Errorf("binarycookies: page %d is only %d bytes", i, sizes[i])
		}

		total += sizes[i]
	}

	if total > len(data) {
		return nil, errors.New("binarycookies: file is truncated")
	}

	var cookies []*http.Cookie

	off := 8 + pages*4
	for _, size := range sizes {
		cookies = append(cookies, parseBinaryCookiePage(data[off:off+size])...)
		off += size
	}

	return cookies, nil
}

func parseBinaryCookiePage(page []byte) []*http.Cookie {
	if len(page) < 12 {
		return nil
	}

	count := int(binary.LittleEndian.Uint32(page[4:8]))
	if count <= 0 || 8+count*4+4 > len(page) {
		return nil
	}

	var cookies []*http.Cookie

	for i := 0; i < count; i++ {
		off := int(binary.LittleEndian.Uint32(page[8+i*4:]))
		if off <= 0 || off >= len(page) {
			continue
		}

		if c, err := parseBinaryCookie(page[off:]); err == nil && c != nil {
			cookies = append(cookies, c)
		}
	}

	return cookies
}

func parseBinaryCookie(rec []byte) (*http.Cookie, error) {
	if len(rec) < cookieRecordMinSize {
		return nil, errors.New("binarycookies: short record")
	}

	le := binary.LittleEndian
	flags := le.Uint32(rec[cookieFlagsOffset:])

	offsets := [4]int{
		int(le.Uint32(rec[cookieDomainOffset:])),
		int(le.Uint32(rec[cookieNameOffset:])),
		int(le.Uint32(rec[cookiePathOffset:])),
		int(le.Uint32(rec[cookieValueOffset:])),
	}

	header := 0
	for _, off := range offsets {
		if off > 0 && (header == 0 || off < header) {
			header = off
		}
	}

	if header < cookieRecordMinSize || header > len(rec) {
		// Fall back to the two documented header sizes.
		header = 52
		if le.Uint32(rec[12:]) != 0 {
			header = 56
		}
	}

	c := &http.Cookie{
		Domain:   strings.TrimPrefix(readCString(rec, offsets[0]), "."),
		Name:     readCString(rec, offsets[1]),
		Path:     readCString(rec, offsets[2]),
		Value:    readCString(rec, offsets[3]),
		Secure:   flags&cookieFlagSecure != 0,
		HttpOnly: flags&cookieFlagHTTPOnly != 0,
	}
	if c.Path == "" {
		c.Path = "/"
	}

	if c.Name == "" || c.Domain == "" {
		return nil, errors.New("binarycookies: record without a name or domain")
	}

	if header >= cookieExpiryOffset+8 {
		// Only surface an expiry that is still in the future: a stale cookie is
		// indistinguishable from a parse miss, and the caller decides liveness.
		mac := math.Float64frombits(le.Uint64(rec[cookieExpiryOffset:]))
		if !math.IsNaN(mac) && mac > 0 {
			if exp := time.Unix(int64(mac)+appleEpochOffset, 0); exp.After(time.Now()) {
				c.Expires = exp
			}
		}
	}

	return c, nil
}

func readCString(rec []byte, off int) string {
	if off <= 0 || off >= len(rec) {
		return ""
	}

	end := off
	for end < len(rec) && rec[end] != 0 {
		end++
	}

	return string(rec[off:end])
}
