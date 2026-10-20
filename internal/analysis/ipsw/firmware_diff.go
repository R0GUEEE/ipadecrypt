package ipsw

import (
 "context"
 "crypto/sha256"
 "io"
 "encoding/hex"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "time"
)

// FirmwarePair records reproducible inputs before an external firmware diff.
// It does not infer vulnerabilities or exploitability from changed bytes.
type FirmwarePair struct {
 OldPath string `json:"old_path"`
 NewPath string `json:"new_path"`
 OldSHA256 string `json:"old_sha256"`
 NewSHA256 string `json:"new_sha256"`
 Device string `json:"device,omitempty"`
}
func fileHash(p string)(string,error){
 f,err:=os.Open(p);if err!=nil{return "",err};defer f.Close()
 s,err:=f.Stat();if err!=nil{return "",err}
 if !s.Mode().IsRegular(){return "",fmt.Errorf("not a regular file: %s",p)}
 h:=sha256.New()
 if _,err=io.Copy(h,f);err!=nil{return "",err}
 return hex.EncodeToString(h.Sum(nil)),nil
}
func ValidateFirmwarePair(old,new,device string)(FirmwarePair,error){
 var pair FirmwarePair
 if old==""||new==""{return pair,errors.New("two local firmware files are required")}
 oldAbs,err:=filepath.Abs(old);if err!=nil{return pair,err}
 newAbs,err:=filepath.Abs(new);if err!=nil{return pair,err}
 if oldAbs==newAbs{return pair,errors.New("firmware paths must differ")}
 a,err:=fileHash(oldAbs);if err!=nil{return pair,err}
 b,err:=fileHash(newAbs);if err!=nil{return pair,err}
 return FirmwarePair{OldPath:oldAbs,NewPath:newAbs,OldSHA256:a,NewSHA256:b,Device:device},nil
}
// DiffFirmware runs ipsw's existing static diff functionality without a shell.
// Output is raw CLI text, and is not an exploitability determination.
func (t Tool) DiffFirmware(ctx context.Context,pair FirmwarePair)([]byte,error){
 if pair.OldPath==""||pair.NewPath==""{return nil,errors.New("invalid firmware pair")}
 ctx,cancel:=context.WithTimeout(ctx,20*time.Minute);defer cancel()
 args:=[]string{"diff",pair.OldPath,pair.NewPath}
 if pair.Device!=""{args=append(args,"--device",pair.Device)}
 out,err:=t.run(ctx,args...)
 if err!=nil{return out,fmt.Errorf("ipsw firmware diff: %w",err)}
 return out,nil
}
