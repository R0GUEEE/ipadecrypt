package signature

import (
 "encoding/binary"
 "testing"
)
func superblobFixture()[]byte{
 b:=make([]byte,44)
 binary.BigEndian.PutUint32(b[0:4],0xfade0cc0)
 binary.BigEndian.PutUint32(b[4:8],44)
 binary.BigEndian.PutUint32(b[8:12],1)
 binary.BigEndian.PutUint32(b[12:16],5)
 binary.BigEndian.PutUint32(b[16:20],20)
 binary.BigEndian.PutUint32(b[20:24],0xfade7171)
 binary.BigEndian.PutUint32(b[24:28],24)
 copy(b[28:],[]byte("<plist></plist>"))
 return b
}
func TestEntitlementsSlot(t *testing.T){
 s,err:=ParseSuperBlob(superblobFixture())
 if err!=nil{t.Fatal(err)}
 if len(s.EntitlementSlots())!=1{t.Fatalf("unexpected slots: %+v",s)}
}
func TestRejectInvalidIndex(t *testing.T){
 b:=superblobFixture()
 binary.BigEndian.PutUint32(b[8:12],100)
 if _,err:=ParseSuperBlob(b);err==nil{t.Fatal("expected index rejection")}
}
func TestRejectOutOfRangeBlob(t *testing.T){
 b:=superblobFixture()
 binary.BigEndian.PutUint32(b[24:28],1000)
 if _,err:=ParseSuperBlob(b);err==nil{t.Fatal("expected blob bounds rejection")}
}
func FuzzSuperBlob(f *testing.F){
 f.Add(superblobFixture());f.Add([]byte{});f.Add([]byte{0xff,0xff,0xff,0xff})
 f.Fuzz(func(t *testing.T,data []byte){
  if len(data)>1<<20{t.Skip()}
  _,_=ParseSuperBlob(data)
 })
}
