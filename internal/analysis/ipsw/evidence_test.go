package ipsw

import (
 "os"
 "path/filepath"
 "testing"
)
func TestA17EvidenceDemonstration(t *testing.T){
 oldDir,newDir:=filepath.Join(t.TempDir(),"beta3"),filepath.Join(t.TempDir(),"beta4")
 for _,dir:=range []string{oldDir,newDir}{if err:=os.MkdirAll(dir,0700);err!=nil{t.Fatal(err)}}
 files:=[]struct{dir,name,data string}{
  {oldDir,"kernelcache","synthetic beta3 bytes"},
  {newDir,"kernelcache","synthetic beta4 bytes"},
  {oldDir,"dyld_shared_cache","unchanged test bytes"},
  {newDir,"dyld_shared_cache","unchanged test bytes"},
 }
 for _,f:=range files{if err:=os.WriteFile(filepath.Join(f.dir,f.name),[]byte(f.data),0600);err!=nil{t.Fatal(err)}}
 report,err:=CompareComponents(oldDir,newDir,"24B5099f","24B5110a")
 if err!=nil{t.Fatal(err)}
 if report.Device!="iPhone16,2"||len(report.Components)!=2{t.Fatalf("unexpected evidence %+v",report)}
 if report.Components[0].Changed||!report.Components[1].Changed{t.Fatalf("wrong delta detection %+v",report.Components)}
 b,err:=report.JSON();if err!=nil{t.Fatal(err)}
 t.Logf("DEMONSTRATION (synthetic fixture; not a real firmware finding): %s",b)
}
func TestEvidenceRejectsMissingComponents(t *testing.T){
 if _,err:=CompareComponents(t.TempDir(),t.TempDir(),"24B5099f","24B5110a");err==nil{t.Fatal("accepted empty directories")}
}
