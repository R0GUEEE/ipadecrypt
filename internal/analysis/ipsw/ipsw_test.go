package ipsw

import (
 "context"
 "errors"
 "strings"
 "testing"
)
func TestProbe(t *testing.T){
 tool:=Tool{Run:func(_ context.Context,_ string,args ...string)([]byte,error){
  if len(args)!=1||args[0]!="version"{t.Fatalf("unexpected args: %v",args)}
  return []byte("ipsw version test"),nil
 }}
 status:=tool.Probe(context.Background())
 if !status.Installed||status.Version!="ipsw version test"{t.Fatalf("unexpected status: %+v",status)}
}
func TestMachOReadOnly(t *testing.T){
 tool:=Tool{Run:func(_ context.Context,_ string,args ...string)([]byte,error){
  if strings.Join(args,"|")!="macho|info|sample.bin|--json"{t.Fatalf("unexpected args: %v",args)}
  return []byte(`{"header":{"type":"EXECUTE"}}`),nil
 }}
 report,err:=tool.InspectMachO(context.Background(),"sample.bin")
 if err!=nil||report.Tool!="blacktop/ipsw"{t.Fatalf("unexpected report: %+v %v",report,err)}
}
func TestRejectNonJSON(t *testing.T){
 tool:=Tool{Run:func(context.Context,string,...string)([]byte,error){return []byte("not json"),nil}}
 if _,err:=tool.InspectMachO(context.Background(),"sample.bin");err==nil{t.Fatal("accepted non-JSON")}
}
func TestUnavailable(t *testing.T){
 tool:=Tool{Run:func(context.Context,string,...string)([]byte,error){return nil,errors.New("not installed")}}
 if tool.Probe(context.Background()).Installed{t.Fatal("unexpected availability")}
}
