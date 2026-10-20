package compatibility

import (
 "archive/zip"
 "os"
 "path/filepath"
 "testing"
)
func TestInventory(t *testing.T){
 p:=filepath.Join(t.TempDir(),"sample.ipa")
 f,err:=os.Create(p);if err!=nil{t.Fatal(err)}
 z:=zip.NewWriter(f)
 for _,name:=range []string{"Payload/Test.app/SC_Info/Test.sinf","Payload/Test.app/Info.plist"}{
  w,e:=z.Create(name);if e!=nil{t.Fatal(e)}
  if _,e=w.Write([]byte("synthetic"));e!=nil{t.Fatal(e)}
 }
 if err:=z.Close();err!=nil{t.Fatal(err)}
 if err:=f.Close();err!=nil{t.Fatal(err)}
 got,err:=InspectIPA(p)
 if err!=nil{t.Fatal(err)}
 if len(got.Entries)!=1||got.TotalBytes!=9{t.Fatalf("unexpected inventory: %+v",got)}
}
func TestCapabilityFailClosed(t *testing.T){
 a:=Assess(Environment{},true)
 if a.Supported||len(a.Reasons)!=3{t.Fatalf("expected three incompatibilities: %+v",a)}
}
func TestCapabilitySupported(t *testing.T){
 a:=Assess(Environment{DeviceAvailable:true,CanRunTarget:true,Authorized:true},true)
 if !a.Supported{t.Fatalf("expected support: %+v",a)}
}
