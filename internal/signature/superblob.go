package signature

import (
 "encoding/binary"
 "errors"
 "fmt"
)

const (
 magicEmbeddedSignature = 0xfade0cc0
 magicEntitlementsXML = 0xfade7171
 magicEntitlementsDER = 0xfade7172
)

type Slot struct {
 Type uint32
 Magic uint32
 Offset uint32
 Length uint32
}
type SuperBlob struct { Slots []Slot }

// ParseSuperBlob reads an Apple embedded-signature index. It does not
// authenticate signatures or decode entitlements.
func ParseSuperBlob(data []byte)(SuperBlob,error){
 var result SuperBlob
 if len(data)<12{return result,errors.New("signature superblob truncated")}
 be:=binary.BigEndian
 if be.Uint32(data[:4])!=magicEmbeddedSignature{return result,errors.New("not an embedded-signature superblob")}
 length:=uint64(be.Uint32(data[4:8]))
 count:=uint64(be.Uint32(data[8:12]))
 if length<12 || length>uint64(len(data)){return result,errors.New("invalid superblob length")}
 if count>(length-12)/8{return result,errors.New("superblob slot index out of bounds")}
 result.Slots=make([]Slot,0,int(count))
 for i:=uint64(0);i<count;i++{
  p:=12+i*8
  typ:=be.Uint32(data[p:p+4])
  offset:=uint64(be.Uint32(data[p+4:p+8]))
  if offset>length || length-offset<8{return SuperBlob{},fmt.Errorf("slot %d offset outside superblob",i)}
  magic:=be.Uint32(data[offset:offset+4])
  blobLen:=uint64(be.Uint32(data[offset+4:offset+8]))
  if blobLen<8 || blobLen>length-offset{return SuperBlob{},fmt.Errorf("slot %d blob outside superblob",i)}
  result.Slots=append(result.Slots,Slot{Type:typ,Magic:magic,Offset:uint32(offset),Length:uint32(blobLen)})
 }
 return result,nil
}

func (s SuperBlob) EntitlementSlots()[]Slot{
 var out []Slot
 for _,slot:=range s.Slots{
  if slot.Magic==magicEntitlementsXML || slot.Magic==magicEntitlementsDER {
   out=append(out,slot)
  }
 }
 return out
}
