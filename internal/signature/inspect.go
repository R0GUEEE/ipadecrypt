// Package signature performs read-only inspection of Mach-O code-signature
// load commands. It does not validate CMS signatures or bypass FairPlay.
package signature

import (
 "encoding/binary"
 "errors"
 "fmt"
)

type Info struct {
 Present bool
 Offset uint32
 Size uint32
 Magic uint32
}

// Inspect parses the LC_CODE_SIGNATURE linkedit_data_command in a thin
// little-endian Mach-O, validating all offsets against the supplied bytes.
func Inspect(data []byte)(Info,error){
 var result Info
 if len(data)<28{return result,errors.New("truncated Mach-O header")}
 magic:=binary.LittleEndian.Uint32(data[:4])
 header:=uint64(28)
 switch magic {
 case 0xfeedface:
 case 0xfeedfacf:header=32
 default:return result,fmt.Errorf("unsupported Mach-O magic: 0x%x",magic)
 }
 if uint64(len(data))<header{return result,errors.New("truncated Mach-O header")}
 ncmds:=binary.LittleEndian.Uint32(data[16:20])
 sizeofcmds:=uint64(binary.LittleEndian.Uint32(data[20:24]))
 if sizeofcmds>uint64(len(data))-header{return result,errors.New("load commands outside file")}
 end:=header+sizeofcmds
 pos:=header
 if ncmds>uint32(sizeofcmds/8){return result,errors.New("invalid load-command count")}
 for i:=uint32(0);i<ncmds;i++ {
  if pos+8>end{return result,errors.New("truncated load command")}
  cmd:=binary.LittleEndian.Uint32(data[pos:pos+4])
  size:=uint64(binary.LittleEndian.Uint32(data[pos+4:pos+8]))
  if size<8 || size>end-pos{return result,errors.New("invalid load-command size")}
  if cmd==0x1d {
   if size<16{return result,errors.New("truncated code-signature command")}
   if result.Present{return result,errors.New("duplicate code-signature command")}
   result.Offset=binary.LittleEndian.Uint32(data[pos+8:pos+12])
   result.Size=binary.LittleEndian.Uint32(data[pos+12:pos+16])
   if uint64(result.Offset)>uint64(len(data)) || uint64(result.Size)>uint64(len(data))-uint64(result.Offset) {
    return result,errors.New("code-signature blob outside file")
   }
   result.Present=true
   if result.Size>=4 {
    result.Magic=binary.BigEndian.Uint32(data[result.Offset:result.Offset+4])
   }
  }
  pos+=size
 }
 return result,nil
}
