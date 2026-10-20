package ios

import (
 "context"
 "errors"
 "testing"

 "github.com/londek/ipadecrypt/internal/backend"
 "github.com/londek/ipadecrypt/internal/config"
)

func TestMissingHost(t *testing.T) {
 b:=Backend{}
 c,e:=b.Probe(context.Background())
 if e!=nil||c.Available||c.Reason=="" {t.Fatalf("unexpected capability: %+v, %v",c,e)}
}
func TestInvalidPort(t *testing.T) {
 b:=Backend{Device:config.Device{Host:"localhost",Port:-1}}
 c,e:=b.Probe(context.Background())
 if e!=nil||c.Available {t.Fatalf("unexpected capability: %+v, %v",c,e)}
}
func TestDecryptNotYetImplemented(t *testing.T){
 b:=Backend{}
 e:=b.Decrypt(context.Background(),backend.Target{},nil)
 if !errors.Is(e,backend.ErrUnsupported){t.Fatalf("unexpected error: %v",e)}
}
