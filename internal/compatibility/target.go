package compatibility

import (
 "fmt"
 "strconv"
 "strings"
)

// Version is an iOS version tuple. Pre-release suffixes are not accepted.
type Version struct {Major,Minor,Patch int}
func ParseVersion(raw string)(Version,error){
 var v Version
 parts:=strings.Split(strings.TrimSpace(raw),".")
 if len(parts)<1||len(parts)>3{return v,fmt.Errorf("invalid iOS version %q",raw)}
 values:=[3]int{}
 for i,p:=range parts{
  if p==""{return v,fmt.Errorf("invalid iOS version %q",raw)}
  for _,c:=range p{if c<'0'||c>'9'{return v,fmt.Errorf("invalid iOS version %q",raw)}}
  n,err:=strconv.Atoi(p);if err!=nil||n>999{return v,fmt.Errorf("invalid iOS version %q",raw)}
  values[i]=n
 }
 return Version{values[0],values[1],values[2]},nil
}
func (v Version) Compare(other Version)int{
 a:=[3]int{v.Major,v.Minor,v.Patch};b:=[3]int{other.Major,other.Minor,other.Patch}
 for i:=0;i<3;i++{if a[i]<b[i]{return -1};if a[i]>b[i]{return 1}}
 return 0
}
type Target struct{
 MinimumIOS string `json:"minimum_ios,omitempty"`
 CPU string `json:"cpu,omitempty"`
}
type Runtime struct{
 IOSVersion string `json:"ios_version,omitempty"`
 CPU string `json:"cpu,omitempty"`
 DeviceAvailable bool `json:"device_available"`
 Authorized bool `json:"authorized"`
}
func AssessTarget(target Target, runtime Runtime) Assessment{
 a:=Assessment{}
 if !runtime.DeviceAvailable{a.Reasons=append(a.Reasons,"device is not connected")}
 if !runtime.Authorized{a.Reasons=append(a.Reasons,"authorized runtime has not been established")}
 if target.MinimumIOS==""{a.Reasons=append(a.Reasons,"target minimum iOS version is unknown")}
 if runtime.IOSVersion==""{a.Reasons=append(a.Reasons,"device iOS version is unknown")}
 if target.MinimumIOS!=""&&runtime.IOSVersion!=""{
  minimum,e1:=ParseVersion(target.MinimumIOS);actual,e2:=ParseVersion(runtime.IOSVersion)
  if e1!=nil||e2!=nil{a.Reasons=append(a.Reasons,"iOS version could not be compared")}else if actual.Compare(minimum)<0{
   a.Reasons=append(a.Reasons,fmt.Sprintf("target requires iOS %s; device reports iOS %s",target.MinimumIOS,runtime.IOSVersion))
  }
 }
 if target.CPU!=""&&runtime.CPU!=""&&target.CPU!=runtime.CPU{
  a.Reasons=append(a.Reasons,fmt.Sprintf("CPU mismatch: target %s vs device %s",target.CPU,runtime.CPU))
 }
 a.Supported=len(a.Reasons)==0
 return a
}
