package compatibility

import "testing"

func TestJailbreakDetection(t *testing.T){
 tests:=[]struct{name string; rootless,rootful bool; want,layout string}{
  {"Dopamine 3",true,false,"dopamine","rootless"},
  {"palera1n",false,true,"palera1n","rootful"},
  {"unknown",false,false,"unknown","unknown"},
 }
 for _,tc:=range tests{
  got:=AssessJailbreak(JailbreakEnvironment{Name:tc.name,Rootless:tc.rootless,Rootful:tc.rootful})
  if got.Detected!=tc.want||got.Layout!=tc.layout{t.Fatalf("%s: %+v",tc.name,got)}
 }
}
func TestConflictingLayout(t *testing.T){
 got:=AssessJailbreak(JailbreakEnvironment{Name:"palera1n",Rootless:true,Rootful:true})
 if got.Layout!="unknown"||len(got.Notes)<2{t.Fatalf("expected fail-closed assessment: %+v",got)}
}
