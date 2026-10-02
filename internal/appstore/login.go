package appstore

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// ErrSignatureRequired reports that Apple refused an unsigned sign-in request.
//
// The App Store's authenticate endpoint requires the body to carry an
// X-Apple-ActionSignature, and the only thing that can produce one is SAP -
// which runs Apple's macOS CommerceKit inside a Unicorn x86_64 VM whose library
// ships as a PyPI wheel with no iOS build. On a phone there is no way to sign in
// with a password; the device's own App Store session is the only path (see
// device_session.go).
var ErrSignatureRequired = errors.New("Apple requires a signed sign-in request (X-Apple-ActionSignature)")

// signatureRequiredError turns Apple's transport-level refusal into something
// actionable. An unsigned authenticate gets a bare 404/403 HTML page instead of
// a plist, which would otherwise surface as an opaque plist parse failure.
func signatureRequiredError(err error) error {
	var decodeErr *ResponseDecodeError
	if !errors.As(err, &decodeErr) {
		return nil
	}

	switch decodeErr.StatusCode {
	case http.StatusNotFound, http.StatusForbidden, http.StatusUnauthorized:
	default:
		return nil
	}

	return fmt.Errorf("%w: Apple answered HTTP %d (%s) instead of a plist; on iOS the device's own App Store session is the only supported path",
		ErrSignatureRequired, decodeErr.StatusCode, decodeErr.ContentType)
}

type loginResult struct {
	FailureType         string `plist:"failureType,omitempty"`
	CustomerMessage     string `plist:"customerMessage,omitempty"`
	DirectoryServicesID string `plist:"dsPersonId,omitempty"`
	PasswordToken       string `plist:"passwordToken,omitempty"`

	Account struct {
		Email   string `plist:"appleId,omitempty"`
		Address struct {
			FirstName string `plist:"firstName,omitempty"`
			LastName  string `plist:"lastName,omitempty"`
		} `plist:"address,omitempty"`
	} `plist:"accountInfo,omitempty"`
}

// Login authenticates against the App Store and returns the account.
// Pass authCode when a prior call returned ErrAuthCodeRequired (2FA).
// Internally fetches the bag to discover the authenticate endpoint.
func (c *Client) Login(email, password, authCode string) (*Account, error) {
	endpoint, err := c.bag()
	if err != nil {
		return nil, err
	}

	g, err := guid()
	if err != nil {
		return nil, err
	}

	authEndpoint := normalizeAuthEndpoint(endpoint)
	url := authEndpoint

	var (
		res *http.Response
		out loginResult
	)

	for attempt := 1; attempt <= 4; attempt++ {
		body, err := plistBody(map[string]any{
			"appleId":  email,
			"attempt":  strconv.Itoa(attempt),
			"guid":     g,
			"password": password + strings.ReplaceAll(authCode, " ", ""),
			"rmp":      "0",
			"why":      "signIn",
		})
		if err != nil {
			return nil, err
		}

		discoveryRetried := false
		for {
			out = loginResult{}

			res, err = c.send(http.MethodPost, url, map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}, body, formatXML, &out)
			if err == nil {
				break
			}

			discoveredEndpoint := authEndpointFromResponseError(err)
			if !discoveryRetried && discoveredEndpoint != "" && discoveredEndpoint != authEndpoint {
				authEndpoint = discoveredEndpoint
				url = authEndpoint
				discoveryRetried = true
				continue
			}

			if rejection := signatureRequiredError(err); rejection != nil {
				return nil, rejection
			}

			return nil, fmt.Errorf("login: %w", err)
		}

		next, retry, err := interpretLogin(res, &out, attempt, authCode)
		if err != nil {
			return nil, err
		}

		if !retry {
			break
		}

		if next != "" {
			url = next
		}
	}

	if out.PasswordToken == "" || out.DirectoryServicesID == "" {
		return nil, errors.New("login: no token after retries")
	}

	addr := out.Account.Address

	return &Account{
		Email:               out.Account.Email,
		PasswordToken:       out.PasswordToken,
		DirectoryServicesID: out.DirectoryServicesID,
		StoreFront:          res.Header.Get(hdrStoreFront),
		Password:            password,
		Pod:                 res.Header.Get(hdrPod),
		Name:                strings.TrimSpace(addr.FirstName + " " + addr.LastName),
	}, nil
}

// interpretLogin classifies an authenticate response.
// Returns (nextURL, retry, err):
//   - retry=true with nextURL set: follow the 302 redirect.
//   - retry=true with empty nextURL: server said "try again" (invalid-cred on attempt 1).
//   - retry=false, err=nil: login succeeded.
//   - retry=false, err!=nil: login failed permanently.
func interpretLogin(res *http.Response, out *loginResult, attempt int, authCode string) (string, bool, error) {
	if res.StatusCode == http.StatusFound {
		loc := res.Header.Get("Location")
		if loc == "" {
			return "", false, errors.New("login: redirect without Location")
		}

		return loc, true, nil
	}

	if attempt == 1 && out.FailureType == failureInvalidCredentials {
		return "", true, nil
	}
	if out.FailureType == failureInvalidCredentials {
		if out.CustomerMessage != "" {
			return "", false, fmt.Errorf("%w: %s", ErrInvalidCredentials, out.CustomerMessage)
		}
		return "", false, ErrInvalidCredentials
	}

	if out.FailureType == "" && authCode == "" && out.CustomerMessage == custMsgBadLogin {
		return "", false, ErrAuthCodeRequired
	}

	if out.FailureType == "" && out.CustomerMessage == custMsgAccountDisabled {
		return "", false, errors.New("account disabled")
	}

	if out.FailureType != "" {
		if out.CustomerMessage != "" {
			return "", false, errors.New(out.CustomerMessage)
		}

		return "", false, errors.New("login failed")
	}

	if res.StatusCode != http.StatusOK || out.PasswordToken == "" || out.DirectoryServicesID == "" {
		return "", false, errors.New("login failed")
	}

	return "", false, nil
}
