package compatibility

import (
 "archive/zip"
 "os"
 "path/filepath"
 "testing"
)
func TestInspectAppMetadata(t *testing.T){
 p:=filepath.Join(t.TempDir(),"test.ipa")
 f,err:=os.Create(p);if err!=nil{t.Fatal(err)}
 z:=zip.NewWriter(f)
 w,err:=z.Create("Payload/Demo.app/Info.plist");if err!=nil{t.Fatal(err)}
 _,err=w.Write([]byte("<plist><dict><key>MinimumOSVersion</key><string>17.0</string><key>CFBundleIdentifier</key><string>test.demo</string></dict></plist>"));if err!=nil{t.Fatal(err)}
 if err:=z.Close();err!=nil{t.Fatal(err)}
 if err:=f.Close();err!=nil{t.Fatal(err)}
 got,err:=InspectAppMetadata(p);if err!=nil{t.Fatal(err)}
 if got.MinimumIOS!="17.0"||got.BundleID!="test.demo"{t.Fatalf("unexpected: %+v",got)}
}
