package signature

import (
 "encoding/binary"
 "testing"
)

func sample()[]byte{
 b:=make([]byte,128)
 binary.LittleEndian.PutUint32(b[:4],0xfeedfacf)
 binary.LittleEndian.PutUint32(b[16:20],1)
 binary.LittleEndian.PutUint32(b[20:24],16)
 binary.LittleEndian.PutUint32(b[32:36],0x1d)
 binary.LittleEndian.PutUint32(b[36:40],16)
 binary.LittleEndian.PutUint32(b[40:44],96)
 binary.LittleEndian.PutUint32(b[44:48],16)
 binary.BigEndian.PutUint32(b[96:100],0xfade0cc0)
 return b
}
func TestInspectSignature(t *testing.T){
 info,err:=Inspect(sample())
 if err!=nil||!info.Present||info.Offset!=96||info.Size!=16||info.Magic!=0xfade0cc0{t.Fatalf("%+v %v",info,err)}
}
func TestRejectOutOfBoundsSignature(t *testing.T){
 b:=sample();binary.LittleEndian.PutUint32(b[44:48],1000)
 if _,err:=Inspect(b);err==nil{t.Fatal("expected bounds failure")}
}
func TestRejectInvalidCommand(t *testing.T){
 b:=sample();binary.LittleEndian.PutUint32(b[36:40],4)
 if _,err:=Inspect(b);err==nil{t.Fatal("expected command rejection")}
}
func FuzzInspect(f *testing.F){
 f.Add(sample());f.Add([]byte{});f.Add([]byte{0xff,0xff,0xff,0xff})
 f.Fuzz(func(t *testing.T,data []byte){
  if len(data)>1<<20{t.Skip()}
  _,_=Inspect(data)
 })
}
