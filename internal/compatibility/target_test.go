package compatibility

import (
 "strings"
 "testing"
)
func TestVersionCompare(t *testing.T){
 a,e:=ParseVersion("16.7.16");if e!=nil{t.Fatal(e)}
 b,e:=ParseVersion("17.0");if e!=nil{t.Fatal(e)}
 if a.Compare(b)>=0{t.Fatal("older iOS accepted")}
 if _,e:=ParseVersion("17.beta");e==nil{t.Fatal("invalid version accepted")}
}
func TestTargetTooNew(t *testing.T){
 a:=AssessTarget(Target{MinimumIOS:"17.0",CPU:"arm64"},Runtime{IOSVersion:"16.7.16",CPU:"arm64",DeviceAvailable:true,Authorized:true})
 if a.Supported||len(a.Reasons)!=1||!strings.Contains(a.Reasons[0],"requires iOS 17.0"){t.Fatalf("unexpected: %+v",a)}
}
func TestTargetMatches(t *testing.T){
 a:=AssessTarget(Target{MinimumIOS:"16.0",CPU:"arm64"},Runtime{IOSVersion:"16.7.16",CPU:"arm64",DeviceAvailable:true,Authorized:true})
 if !a.Supported{t.Fatalf("unexpected: %+v",a)}
}
func TestUnknownFailsClosed(t *testing.T){
 a:=AssessTarget(Target{},Runtime{})
 if a.Supported||len(a.Reasons)<3{t.Fatalf("unexpected: %+v",a)}
}
