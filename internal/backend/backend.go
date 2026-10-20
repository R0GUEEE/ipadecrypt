package backend

import (
 "context"
 "errors"
 "io"
)

var ErrUnavailable = errors.New("decryption backend unavailable on this host")
var ErrUnsupported = errors.New("target is not supported by this backend")

// Target describes an input app without requiring a particular transport.
type Target struct {
 BundleID string
 IPAPath string
 InstalledPath string
}

// Capability is a backend's reported runtime availability, not a guarantee
// that any particular encrypted app can be decrypted.
type Capability struct {
 Name string
 Available bool
 Reason string
}

// Artifact describes a Mach-O replacement provided by a backend.
type Artifact struct {
 RelativePath string
 Data io.ReadCloser
}

// Backend abstracts the source of authorized plaintext executable pages.
// Implementations must not report success from metadata changes alone.
type Backend interface {
 Name() string
 Probe(ctx context.Context) (Capability, error)
 Decrypt(ctx context.Context, target Target, emit func(Artifact) error) error
}

// Select returns the first available backend. An explicit backend selection
// should be implemented by the caller rather than silently falling back.
func Select(ctx context.Context, backends ...Backend) (Backend, error) {
 for _, b := range backends {
  c, err := b.Probe(ctx)
  if err == nil && c.Available { return b, nil }
  if err := ctx.Err(); err != nil { return nil, err }
 }
 return nil, ErrUnavailable
}
