package ipsw

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "sort"
)

// Evidence is a static, reproducible binary-difference record. It is not an exploit.
type Evidence struct {
 Device string `json:"device"`
 OldBuild string `json:"old_build"`
 NewBuild string `json:"new_build"`
 Components []ComponentDelta `json:"components"`
 Conclusion string `json:"conclusion"`
}
type ComponentDelta struct {
 Name string `json:"name"`
 OldSHA256 string `json:"old_sha256"`
 NewSHA256 string `json:"new_sha256"`
 Changed bool `json:"changed"`
}
func HashComponent(data []byte)string{
 h:=sha256.Sum256(data)
 return hex.EncodeToString(h[:])
}
// CompareComponents performs an offline diff of already-extracted components.
// Caller must supply matching relative names for the two directories.
func CompareComponents(oldDir,newDir,oldBuild,newBuild string)(Evidence,error){
 result:=Evidence{Device:"iPhone16,2",OldBuild:oldBuild,NewBuild:newBuild,Conclusion:"Static differences only; no privilege escalation or jailbreak demonstrated."}
 if oldBuild==""||newBuild==""||oldBuild==newBuild{return result,errors.New("distinct build identifiers required")}
 oldFiles,err:=componentFiles(oldDir);if err!=nil{return result,err}
 newFiles,err:=componentFiles(newDir);if err!=nil{return result,err}
 if len(oldFiles)==0||len(newFiles)==0{return result,errors.New("component directories must be nonempty")}
 names:=make([]string,0)
 for n:=range oldFiles{if _,ok:=newFiles[n];ok{names=append(names,n)}}
 sort.Strings(names)
 if len(names)==0{return result,errors.New("no matching component filenames")}
 for _,name:=range names{
  a,b:=HashComponent(oldFiles[name]),HashComponent(newFiles[name])
  result.Components=append(result.Components,ComponentDelta{Name:name,OldSHA256:a,NewSHA256:b,Changed:a!=b})
 }
 return result,nil
}
func componentFiles(dir string)(map[string][]byte,error){
 result:=map[string][]byte{}
 err:=filepath.WalkDir(dir,func(p string,d os.DirEntry,err error)error{
  if err!=nil{return err}
  if d.IsDir(){return nil}
  if !d.Type().IsRegular(){return fmt.Errorf("nonregular entry %s",p)}
  rel,err:=filepath.Rel(dir,p);if err!=nil{return err}
  info,err:=d.Info();if err!=nil{return err}
  if info.Size()>64<<20{return fmt.Errorf("component too large: %s",rel)}
  b,err:=os.ReadFile(p);if err!=nil{return err}
  result[filepath.ToSlash(rel)]=b
  return nil
 })
 return result,err
}
func (e Evidence)JSON()([]byte,error){return json.MarshalIndent(e,"","  ")}
