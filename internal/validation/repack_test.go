package validation

import (
 "archive/zip"
 "os"
 "path/filepath"
 "testing"
)

func TestRepackRejectsMissingReplacement(t *testing.T){
 dir:=t.TempDir()
 src:=filepath.Join(dir,"source.ipa")
 dst:=filepath.Join(dir,"output.ipa")
 f,err:=os.Create(src);if err!=nil{t.Fatal(err)}
 z:=zip.NewWriter(f)
 w,err:=z.Create("Payload/Demo.app/Info.plist");if err!=nil{t.Fatal(err)}
 if _,err=w.Write([]byte("metadata"));err!=nil{t.Fatal(err)}
 if err=z.Close();err!=nil{t.Fatal(err)}
 if err=f.Close();err!=nil{t.Fatal(err)}
 err=RepackIPA(src,dst,map[string][]byte{"Payload/Demo.app/Missing":[]byte("fake")})
 if err==nil{t.Fatal("accepted missing replacement")}
 if _,err=os.Stat(dst);!os.IsNotExist(err){t.Fatal("partial output persisted")}
}
func TestRepackRejectsUnsafePaths(t *testing.T){
 err:=RepackIPA("source.ipa","out.ipa",map[string][]byte{"Payload/../escape":[]byte("bad")})
 if err==nil{t.Fatal("accepted unsafe replacement path")}
}
