// Package inspection provides portable, read-only IPA Mach-O encryption inspection.
package inspection

import (
 "archive/zip"
 "bytes"
 "io"
 "debug/macho"
 "fmt"
 "path"
 "strings"
)

const encryptionInfo64 uint32 = 0x2c
const encryptionInfo32 uint32 = 0x21

type Binary struct {
 Path string
 CPU string
 Encrypted bool
 CryptOffset uint32
 CryptSize uint32
 CryptID uint32
}

func IPA(filename string)([]Binary,error){
 r,err:=zip.OpenReader(filename);if err!=nil{return nil,err};defer r.Close()
 var result []Binary
 for _,f:=range r.File {
  if f.FileInfo().IsDir() || !strings.HasPrefix(f.Name,"Payload/") {continue}
  if path.Clean(f.Name)!=f.Name || strings.Contains(f.Name,"../"){return nil,fmt.Errorf("unsafe archive path %q",f.Name)}
  h,err:=f.Open();if err!=nil{return nil,err}
  data,readErr:=io.ReadAll(io.LimitReader(h, 512<<20 + 1))
  if readErr!=nil {h.Close();return nil,readErr}
  if len(data)>512<<20 {h.Close();return nil,fmt.Errorf("Mach-O entry exceeds 512 MiB: %s",f.Name)}
  m,err:=macho.NewFile(bytes.NewReader(data))
  if err!=nil {h.Close();continue}
  b:=Binary{Path:f.Name,CPU:m.Cpu.String()}
  for _,l:=range m.Loads {
   raw:=l.Raw()
   if len(raw)<20 {continue}
   order:=m.ByteOrder
   cmd:=order.Uint32(raw[:4])
   if cmd!=encryptionInfo64 && cmd!=encryptionInfo32 {continue}
   b.CryptOffset=order.Uint32(raw[8:12])
   b.CryptSize=order.Uint32(raw[12:16])
   b.CryptID=order.Uint32(raw[16:20])
   b.Encrypted=b.CryptID!=0
  }
  m.Close();h.Close()
  result=append(result,b)
 }
 return result,nil
}
