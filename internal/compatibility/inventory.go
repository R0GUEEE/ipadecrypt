// Package compatibility inventories non-secret FairPlay metadata and explains
// why a target cannot be processed by a given execution environment.
package compatibility

import (
 "archive/zip"
 "fmt"
 "io"
 "path"
 "strings"
)

type Entry struct {
 Path string `json:"path"`
 Size uint64 `json:"size"`
}
type Inventory struct {
 Entries []Entry `json:"entries"`
 TotalBytes uint64 `json:"total_bytes"`
}
const maxMetadataFile = 16 << 20
const maxEntries = 100000

// InspectIPA inventories SC_Info entries without reading or exporting their
// content. Never log license blobs, user credentials, or key material.
func InspectIPA(ipa string)(Inventory,error){
 var out Inventory
 r,err:=zip.OpenReader(ipa);if err!=nil{return out,err}
 defer r.Close()
 if len(r.File)>maxEntries{return out,fmt.Errorf("archive has too many entries")}
 for _,f:=range r.File{
  clean:=path.Clean(f.Name)
  if strings.HasPrefix(clean,"../") || strings.HasPrefix(clean,"/") || clean==".." {return out,fmt.Errorf("unsafe archive entry")}
  if f.FileInfo().IsDir(){continue}
  if !strings.Contains("/"+clean+"/","/SC_Info/"){continue}
  if f.UncompressedSize64>maxMetadataFile{return out,fmt.Errorf("oversized SC_Info entry")}
  // Metadata-only: no call to f.Open(), no FairPlay blob parsing.
  out.Entries=append(out.Entries,Entry{Path:clean,Size:f.UncompressedSize64})
  out.TotalBytes+=f.UncompressedSize64
 }
 return out,nil
}

type Environment struct {
 IOSVersion string `json:"ios_version"`
 DeviceAvailable bool `json:"device_available"`
 CanRunTarget bool `json:"can_run_target"`
 Authorized bool `json:"authorized"`
}
type Assessment struct {
 Supported bool `json:"supported"`
 Reasons []string `json:"reasons"`
}
func Assess(env Environment,requiresDevice bool) Assessment{
 a:=Assessment{}
 if requiresDevice&&!env.DeviceAvailable{a.Reasons=append(a.Reasons,"backend requires a connected iOS device")}
 if requiresDevice&&!env.CanRunTarget{a.Reasons=append(a.Reasons,"environment cannot run target app")}
 if requiresDevice&&!env.Authorized{a.Reasons=append(a.Reasons,"authorized runtime not confirmed")}
 a.Supported=len(a.Reasons)==0
 return a
}

// ReadMetadata is intentionally unsupported; the inventory only records file
// names and sizes. Keep encrypted license material out of hosted CI.
func ReadMetadata(_ io.Reader)error{return fmt.Errorf("SC_Info payload extraction is disabled")}
