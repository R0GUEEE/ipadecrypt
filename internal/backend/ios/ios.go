// Package ios adapts the existing jailbroken-device transport to the portable backend API.
package ios

import (
 "context"
 "fmt"
 "strings"

 "github.com/londek/ipadecrypt/internal/backend"
 "github.com/londek/ipadecrypt/internal/config"
 "github.com/londek/ipadecrypt/internal/device"
)

type Connector func(context.Context, config.Device) (*device.Client, error)

type Backend struct {
 Device config.Device
 Connect Connector
}

func (b Backend) Name() string { return "ios" }

func (b Backend) Probe(ctx context.Context) (backend.Capability, error) {
 result := backend.Capability{Name:b.Name()}
 if err:=ctx.Err();err!=nil{return result,err}
 if strings.TrimSpace(b.Device.Host)=="" {
  result.Reason="device host is not configured"
  return result,nil
 }
 if b.Device.Port<1 || b.Device.Port>65535 {
  result.Reason="device SSH port is invalid"
  return result,nil
 }
 connect:=b.Connect
 if connect==nil {connect=device.Connect}
 client,err:=connect(ctx,b.Device)
 if err!=nil {
  result.Reason=fmt.Sprintf("device connection unavailable: %v",err)
  return result,nil
 }
 defer client.Close()
 p,err:=client.Probe()
 if err!=nil {
  result.Reason=fmt.Sprintf("device probe failed: %v",err)
  return result,nil
 }
 if p.IOSVersion=="" {
  result.Reason="device did not report an iOS version"
  return result,nil
 }
 result.Available=true
 result.Reason=fmt.Sprintf("iOS %s (%s, %s)",p.IOSVersion,p.Arch,p.Jailbreak)
 return result,nil
}

// Decrypt is intentionally not yet wired to the legacy helper protocol.
// The legacy CLI continues to own installation, dumping and reconstruction.
func (b Backend) Decrypt(ctx context.Context,target backend.Target,emit func(backend.Artifact)error)error {
 if err:=ctx.Err();err!=nil{return err}
 return backend.ErrUnsupported
}

var _ backend.Backend = Backend{}
