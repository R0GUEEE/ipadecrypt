package validation

import (
 "bytes"
 "encoding/binary"
 "testing"
)

func TestStructureRejectsArchitectureMismatch(t *testing.T){
 source:=fixture(1);candidate:=fixture(0)
 binary.LittleEndian.PutUint32(candidate[4:8],0x01000007)
 if err:=Structure(source,candidate);err==nil{t.Fatal("expected CPU mismatch")}
}
func TestStructureRejectsGarbage(t *testing.T){
 if err:=Structure(fixture(1),bytes.Repeat([]byte{0x41},128));err==nil{t.Fatal("expected invalid Mach-O")}
}
func TestValidateDoesNotClaimPlaintext(t *testing.T){
 source:=fixture(1);candidate:=fixture(0)
 candidate[70]^=0x80
 result,err:=Validate(source,candidate)
 if err!=nil{t.Fatalf("synthetic fixture should parse: %v",err)}
 if !result.Valid || result.Reason==""{t.Fatalf("missing candidate evidence: %+v",result)}
}
