package validation

import (
 "bytes"
 "debug/macho"
 "errors"
 "fmt"
 "io"
)

// Structure checks that a candidate is parseable as a Mach-O and that its
// architecture and file type match the source. This is not a FairPlay proof.
func Structure(source,candidate []byte) error {
 s,err:=openMachO(source);if err!=nil{return fmt.Errorf("source: %w",err)}
 defer s.Close()
 c,err:=openMachO(candidate);if err!=nil{return fmt.Errorf("candidate: %w",err)}
 defer c.Close()
 if s.Cpu!=c.Cpu || s.SubCpu!=c.SubCpu || s.Type!=c.Type {
  return fmt.Errorf("Mach-O identity mismatch: cpu/subcpu/type %v/%v/%v vs %v/%v/%v",s.Cpu,s.SubCpu,s.Type,c.Cpu,c.SubCpu,c.Type)
 }
 if len(s.Loads)!=len(c.Loads) {return fmt.Errorf("load-command count mismatch: %d vs %d",len(s.Loads),len(c.Loads))}
 return nil
}

func openMachO(data []byte)(*macho.File,error){
 if len(data)<32{return nil,io.ErrUnexpectedEOF}
 m,err:=macho.NewFile(bytes.NewReader(data))
 if err==nil{return m,nil}
 var fatErr *macho.FormatError
 if errors.As(err,&fatErr) {return nil,fmt.Errorf("unsupported or malformed Mach-O: %w",err)}
 return nil,err
}

// Validate combines geometry/payload checks with structural checks. It
// deliberately does not call the result 'decrypted' or 'executable'.
func Validate(source,candidate []byte)(Result,error){
 r,err:=Compare(source,candidate)
 if err!=nil{return r,err}
 if err:=Structure(source,candidate);err!=nil{
  r.Valid=false;r.Reason="candidate failed Mach-O structural checks"
  return r,fmt.Errorf("%w: %v",ErrNotDecrypted,err)
 }
 r.Reason="changed payload and matching Mach-O structure; plaintext remains unproven"
 return r,nil
}
