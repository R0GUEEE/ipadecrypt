package compatibility

import (
 "archive/zip"
 "fmt"
 "io"
 "path"
 "strings"

 "howett.net/plist"
)
type AppMetadata struct {
 BundleID string `json:"bundle_id,omitempty"`
 MinimumIOS string `json:"minimum_ios,omitempty"`
 Executable string `json:"executable,omitempty"`
}
const maxPlistBytes = 2 << 20

// InspectAppMetadata reads only the primary app's Info.plist, not extension
// metadata. It accepts binary and XML plists.
func InspectAppMetadata(filename string)(AppMetadata,error){
 var out AppMetadata
 z,err:=zip.OpenReader(filename);if err!=nil{return out,err}
 defer z.Close()
 var info *zip.File
 for _,f:=range z.File{
  name:=path.Clean(f.Name)
  if name!=f.Name || strings.HasPrefix(name,"../") || strings.HasPrefix(name,"/"){return out,fmt.Errorf("unsafe IPA entry path")}
  parts:=strings.Split(name,"/")
  if len(parts)==3 && parts[0]=="Payload" && strings.HasSuffix(parts[1],".app") && parts[2]=="Info.plist"{
   if info!=nil{return out,fmt.Errorf("multiple top-level app Info.plist files")}
   info=f
  }
 }
 if info==nil{return out,fmt.Errorf("primary app Info.plist not found")}
 if info.UncompressedSize64>maxPlistBytes{return out,fmt.Errorf("Info.plist too large")}
 f,err:=info.Open();if err!=nil{return out,err}
 defer f.Close()
 data,err:=io.ReadAll(io.LimitReader(f,maxPlistBytes+1));if err!=nil{return out,err}
 if len(data)>maxPlistBytes{return out,fmt.Errorf("Info.plist exceeds limit")}
 var m map[string]interface{}
 if _,err:=plist.Unmarshal(data,&m);err!=nil{return out,fmt.Errorf("decode Info.plist: %w",err)}
 if s,ok:=m["CFBundleIdentifier"].(string);ok{out.BundleID=s}
 if s,ok:=m["MinimumOSVersion"].(string);ok{out.MinimumIOS=s}
 if s,ok:=m["CFBundleExecutable"].(string);ok{out.Executable=s}
 return out,nil
}
