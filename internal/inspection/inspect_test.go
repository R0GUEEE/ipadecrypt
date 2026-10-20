package inspection

import (
 "archive/zip"
 "os"
 "path/filepath"
 "testing"
)
func TestEmptyIPA(t *testing.T){
 p:=filepath.Join(t.TempDir(),"test.ipa")
 f,e:=os.Create(p);if e!=nil{t.Fatal(e)}
 z:=zip.NewWriter(f);_,e=z.Create("Payload/Test.app/Info.plist");if e!=nil{t.Fatal(e)}
 if e=z.Close();e!=nil{t.Fatal(e)};f.Close()
 got,e:=IPA(p);if e!=nil||len(got)!=0{t.Fatalf("got %v err %v",got,e)}
}
