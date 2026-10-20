package ipsw

import (
 "context"
 "os"
 "path/filepath"
 "strings"
 "testing"
)
func TestFirmwarePair(t *testing.T){
 dir:=t.TempDir()
 a,b:=filepath.Join(dir,"old.ipsw"),filepath.Join(dir,"new.ipsw")
 if err:=os.WriteFile(a,[]byte("old"),0600);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(b,[]byte("new"),0600);err!=nil{t.Fatal(err)}
 pair,err:=ValidateFirmwarePair(a,b,"iPhone18,2")
 if err!=nil{t.Fatal(err)}
 if pair.OldSHA256==pair.NewSHA256||len(pair.OldSHA256)!=64{t.Fatal("bad hashes")}
 tool:=Tool{Run:func(_ context.Context,_ string,args ...string)([]byte,error){
  joined:=strings.Join(args," ")
  if !strings.Contains(joined,"diff ")||strings.Contains(joined,"--device"){t.Fatalf("unexpected arguments %v",args)}
  return []byte("firmware comparison"),nil
 }}
 output,err:=tool.DiffFirmware(context.Background(),pair)
 if err!=nil||string(output)!="firmware comparison"{t.Fatalf("bad output: %s %v",output,err)}
 if _,err:=ValidateFirmwarePair(a,a,"");err==nil{t.Fatal("same file accepted")}
}
