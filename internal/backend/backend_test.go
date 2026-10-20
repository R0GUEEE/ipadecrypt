package backend

import (
 "context"
 "errors"
 "testing"
)

type fakeBackend struct { name string; available bool; err error }
func (f fakeBackend) Name() string { return f.name }
func (f fakeBackend) Probe(context.Context) (Capability,error) { return Capability{Name:f.name,Available:f.available},f.err }
func (f fakeBackend) Decrypt(context.Context,Target,func(Artifact)error)error{return ErrUnsupported}

func TestSelect(t *testing.T) {
 b,e:=Select(context.Background(),fakeBackend{name:"offline"},fakeBackend{name:"device",available:true})
 if e!=nil || b.Name()!="device" { t.Fatalf("selection: %v, %v",b,e) }
 _,e=Select(context.Background(),fakeBackend{name:"offline"})
 if !errors.Is(e,ErrUnavailable){t.Fatalf("expected unavailable, got %v",e)}
}
func TestSelectCancelled(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 _,e:=Select(ctx,fakeBackend{name:"bad"})
 if !errors.Is(e,context.Canceled){t.Fatalf("expected cancellation, got %v",e)}
}
