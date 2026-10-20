package validation

import (
 "encoding/binary"
 "errors"
 "testing"
)

func fixture(cryptid uint32)[]byte{
 b:=make([]byte,128)
 binary.LittleEndian.PutUint32(b[0:4],0xfeedfacf)
 binary.LittleEndian.PutUint32(b[4:8],0x0100000c)
 binary.LittleEndian.PutUint32(b[12:16],2)
 binary.LittleEndian.PutUint32(b[16:20],1)
 binary.LittleEndian.PutUint32(b[20:24],24)
 binary.LittleEndian.PutUint32(b[32:36],0x2c)
 binary.LittleEndian.PutUint32(b[36:40],24)
 binary.LittleEndian.PutUint32(b[40:44],64)
 binary.LittleEndian.PutUint32(b[44:48],32)
 binary.LittleEndian.PutUint32(b[48:52],cryptid)
 for i:=64;i<96;i++{b[i]=byte(i)}
 return b
}
func TestRejectCryptidOnly(t *testing.T){
 source:=fixture(1);candidate:=fixture(0)
 _,err:=Compare(source,candidate)
 if !errors.Is(err,ErrNotDecrypted){t.Fatalf("expected rejection: %v",err)}
}
func TestRejectZeroRegion(t *testing.T){
 source:=fixture(1);candidate:=fixture(0)
 for i:=64;i<96;i++{candidate[i]=0}
 _,err:=Compare(source,candidate)
 if !errors.Is(err,ErrNotDecrypted){t.Fatalf("expected rejection: %v",err)}
}
func TestChangedPayloadIsOnlyCandidateEvidence(t *testing.T){
 source:=fixture(1);candidate:=fixture(0)
 candidate[70]^=0xff
 result,err:=Compare(source,candidate)
 if err!=nil||!result.Valid||!result.ProtectedBytesChanged{t.Fatalf("expected changed-payload candidate: %+v %v",result,err)}
}
func TestRejectTruncatedCandidate(t *testing.T){
 source:=fixture(1);candidate:=fixture(0)[:80]
 _,err:=Compare(source,candidate)
 if !errors.Is(err,ErrNotDecrypted){t.Fatalf("expected bounds rejection: %v",err)}
}
