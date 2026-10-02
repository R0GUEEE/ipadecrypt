package appstore

import (
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	cookiejar "github.com/juju/persistent-cookiejar"
)

type Client struct {
	jar    *cookiejar.Jar
	http   *http.Client
	merged *mergeJar
	device *DeviceSession
}

// UseDeviceSession installs cookies taken from the device's own App Store
// session. They are served alongside the persistent jar and never written to
// it, so the client keeps them read-only.
func (c *Client) UseDeviceSession(session *DeviceSession) {
	if c == nil || session == nil {
		return
	}

	c.device = session
	c.merged.device = session.Cookies
}

// DeviceSession returns the session installed by UseDeviceSession.
func (c *Client) DeviceSession() *DeviceSession {
	if c == nil {
		return nil
	}

	return c.device
}

// DeviceAccount returns the account for the installed device session. It has
// no PasswordToken; callers must not assume one is present.
func (c *Client) DeviceAccount() *Account {
	if c == nil || c.device == nil {
		return nil
	}

	return c.device.Account()
}

func New(cookiesFile string) (*Client, error) {
	if cookiesFile != "" {
		if err := os.MkdirAll(filepath.Dir(cookiesFile), 0o755); err != nil {
			return nil, err
		}
	}

	jar, err := cookiejar.New(&cookiejar.Options{Filename: cookiesFile})
	if err != nil {
		return nil, err
	}

	hc := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.Referer() == authURL {
				return http.ErrUseLastResponse
			}

			return nil
		},
	}

	merged := &mergeJar{base: hc.Jar}
	hc.Jar = merged

	return &Client{jar: jar, http: hc, merged: merged}, nil
}

// guid returns the Configurator-shaped GUID: uppercase MAC address, no colons.
func guid() (string, error) {
	mac, err := macAddress()
	if err != nil {
		return "", err
	}

	return strings.ReplaceAll(strings.ToUpper(mac), ":", ""), nil
}

func macAddress() (string, error) {
	if iface, err := net.InterfaceByName("en0"); err == nil && iface.HardwareAddr != nil {
		if s := iface.HardwareAddr.String(); s != "" {
			return s, nil
		}
	}

	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, ni := range ifs {
		if s := ni.HardwareAddr.String(); s != "" {
			return s, nil
		}
	}

	return "", errors.New("no network interface with a MAC address")
}
