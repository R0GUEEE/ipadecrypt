package validation

import (
 "archive/zip"
 "bytes"
 "errors"
 "fmt"
 "io"
 "os"
 "path"
 "path/filepath"
 "strings"
)

// RepackIPA substitutes independently obtained executable bytes into an IPA.
// It never generates plaintext or alters an encryption marker by itself.
// Each replacement must pass the existing payload and Mach-O checks.
func RepackIPA(sourceIPA,outputIPA string,replacements map[string][]byte)error{
 if len(replacements)==0{return errors.New("no plaintext replacements supplied")}
 if sourceIPA==outputIPA{return errors.New("output must differ from input")}
 for name:=range replacements{
  if path.Clean(name)!=name||!strings.HasPrefix(name,"Payload/")||strings.Contains(name,"../"){return fmt.Errorf("unsafe replacement path %q",name)}
 }
 reader,err:=zip.OpenReader(sourceIPA);if err!=nil{return err}
 defer reader.Close()
 file,err:=os.CreateTemp(filepath.Dir(outputIPA),".ipadecrypt-*.ipa")
 if err!=nil{return err}
 tmp:=file.Name()
 defer os.Remove(tmp)
 writer:=zip.NewWriter(file)
 seen:=map[string]bool{}
 fail:=func(e error)error{writer.Close();file.Close();return e}
 for _,entry:=range reader.File{
  if path.Clean(entry.Name)!=entry.Name||strings.Contains(entry.Name,"../"){return fail(fmt.Errorf("unsafe IPA entry %q",entry.Name))}
  header:=entry.FileHeader
  dest,err:=writer.CreateHeader(&header);if err!=nil{return fail(err)}
  src,err:=entry.Open();if err!=nil{return fail(err)}
  replacement,ok:=replacements[entry.Name]
  if ok{
   original,readErr:=io.ReadAll(io.LimitReader(src,512<<20+1))
   src.Close()
   if readErr!=nil{return fail(readErr)}
   if len(original)>512<<20{return fail(errors.New("executable too large"))}
   if _,err=Validate(original,replacement);err!=nil{return fail(fmt.Errorf("%s: %w",entry.Name,err))}
   if _,err=io.Copy(dest,bytes.NewReader(replacement));err!=nil{return fail(err)}
   seen[entry.Name]=true
  }else{
   _,err=io.Copy(dest,src);src.Close()
   if err!=nil{return fail(err)}
  }
 }
 for name:=range replacements{if !seen[name]{return fail(fmt.Errorf("replacement not found in IPA: %s",name))}}
 if err=writer.Close();err!=nil{file.Close();return err}
 if err=file.Close();err!=nil{return err}
 return os.Rename(tmp,outputIPA)
}
