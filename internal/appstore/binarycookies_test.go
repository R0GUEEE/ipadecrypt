package appstore

import (
	"encoding/binary"
	"math"
	"testing"
)

// binaryCookieFixture mirrors the fields the parser reads back out.
type binaryCookieFixture struct {
	domain string
	name   string
	path   string
	value  string
	flags  uint32
	expiry float64
}

// buildBinaryCookieFile lays out a Cookies.binarycookies blob the same way
// Apple does, so the parser is exercised against the real container shape
// rather than a mock.
func buildBinaryCookieFile(t *testing.T, cookies []binaryCookieFixture) []byte {
	t.Helper()

	records := make([][]byte, 0, len(cookies))
	for _, c := range cookies {
		records = append(records, buildBinaryCookieRecord(t, c))
	}

	pageHeaderSize := 8 + 4*len(records) + 4

	page := make([]byte, pageHeaderSize)
	binary.BigEndian.PutUint32(page[0:], 0x00000100)
	binary.LittleEndian.PutUint32(page[4:], uint32(len(records)))

	offset := pageHeaderSize
	for i, record := range records {
		binary.LittleEndian.PutUint32(page[8+i*4:], uint32(offset))
		offset += len(record)
	}

	for _, record := range records {
		page = append(page, record...)
	}

	out := make([]byte, 8)
	copy(out, binaryCookiesMagic)
	binary.BigEndian.PutUint32(out[4:], 1)

	size := make([]byte, 4)
	binary.BigEndian.PutUint32(size, uint32(len(page)))

	out = append(out, size...)
	out = append(out, page...)

	return out
}

func buildBinaryCookieRecord(t *testing.T, c binaryCookieFixture) []byte {
	t.Helper()

	const headerSize = 52

	fields := []string{c.domain, c.name, c.path, c.value}
	offsets := make([]int, 0, len(fields))

	body := make([]byte, 0, 64)
	next := headerSize
	for _, field := range fields {
		offsets = append(offsets, next)
		body = append(body, field...)
		body = append(body, 0)
		next += len(field) + 1
	}

	record := make([]byte, headerSize, headerSize+len(body))
	record = append(record, body...)

	binary.LittleEndian.PutUint32(record[0:], uint32(len(record)))
	binary.LittleEndian.PutUint32(record[4:], 1)
	binary.LittleEndian.PutUint32(record[8:], c.flags)
	binary.LittleEndian.PutUint32(record[12:], 0)
	binary.LittleEndian.PutUint32(record[16:], uint32(offsets[0]))
	binary.LittleEndian.PutUint32(record[20:], uint32(offsets[1]))
	binary.LittleEndian.PutUint32(record[24:], uint32(offsets[2]))
	binary.LittleEndian.PutUint32(record[28:], uint32(offsets[3]))
	binary.LittleEndian.PutUint32(record[32:], 0)
	binary.LittleEndian.PutUint64(record[36:], math.Float64bits(c.expiry))
	binary.LittleEndian.PutUint64(record[44:], 0)

	return record
}

func TestParseBinaryCookiesReadsFields(t *testing.T) {
	data := buildBinaryCookieFile(t, []binaryCookieFixture{
		{domain: ".apple.com", name: "myacinfo", path: "/", value: "session-value", flags: cookieFlagSecure | cookieFlagHTTPOnly},
		{domain: ".apple.com", name: "dsid", path: "/", value: "1234567890"},
	})

	cookies, err := ParseBinaryCookies(data)
	if err != nil {
		t.Fatalf("ParseBinaryCookies: %v", err)
	}

	if len(cookies) != 2 {
		t.Fatalf("got %d cookies, want 2", len(cookies))
	}

	first := cookies[0]
	if first.Name != "myacinfo" || first.Value != "session-value" {
		t.Fatalf("name/value = %q/%q", first.Name, first.Value)
	}

	// The leading dot is storage detail, not part of the domain match.
	if first.Domain != "apple.com" {
		t.Fatalf("domain = %q, want apple.com", first.Domain)
	}

	if !first.Secure || !first.HttpOnly {
		t.Fatalf("secure/httpOnly = %v/%v, want true/true", first.Secure, first.HttpOnly)
	}

	if first.Path != "/" {
		t.Fatalf("path = %q, want /", first.Path)
	}
}

func TestParseBinaryCookiesRejectsBadMagic(t *testing.T) {
	if _, err := ParseBinaryCookies([]byte("not-a-cook-file")); err == nil {
		t.Fatal("expected an error for a file without the cook magic")
	}
}

func TestParseBinaryCookiesRejectsTruncatedPage(t *testing.T) {
	data := buildBinaryCookieFile(t, []binaryCookieFixture{{domain: ".apple.com", name: "myacinfo", value: "x"}})

	if _, err := ParseBinaryCookies(data[:len(data)-8]); err == nil {
		t.Fatal("expected an error for a truncated file")
	}
}

func TestParseBinaryCookiesSkipsRecordWithNoName(t *testing.T) {
	data := buildBinaryCookieFile(t, []binaryCookieFixture{
		{domain: ".apple.com", name: "", value: "nameless"},
		{domain: ".apple.com", name: "myacinfo", value: "kept"},
	})

	cookies, err := ParseBinaryCookies(data)
	if err != nil {
		t.Fatalf("ParseBinaryCookies: %v", err)
	}

	if len(cookies) != 1 || cookies[0].Name != "myacinfo" {
		t.Fatalf("got %d cookies (%v), want only myacinfo", len(cookies), cookies)
	}
}

func TestParseBinaryCookiesDropsExpiredExpiry(t *testing.T) {
	// 100 seconds after the Apple epoch, i.e. long past.
	expired := buildBinaryCookieFile(t, []binaryCookieFixture{
		{domain: ".apple.com", name: "myacinfo", value: "x", expiry: 100},
	})

	cookies, err := ParseBinaryCookies(expired)
	if err != nil {
		t.Fatalf("ParseBinaryCookies: %v", err)
	}

	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}

	if !cookies[0].Expires.IsZero() {
		t.Fatalf("expiry = %v, want zero for an already-expired cookie", cookies[0].Expires)
	}
}
