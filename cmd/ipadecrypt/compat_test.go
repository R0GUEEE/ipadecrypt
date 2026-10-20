package main

import (
 "archive/zip"
 "bytes"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestCompatibilityCommand(t *testing.T){
 filename:=filepath.Join(t.TempDir(),"sample.ipa")
 f,err:=os.Create(filename);if err!=nil{t.Fatal(err)}
 z:=zip.NewWriter(f)
 w,err:=z.Create("Payload/Demo.app/Info.plist");if err!=nil{t.Fatal(err)}
 if _,err=w.Write([]byte("<plist><dict><key>MinimumOSVersion</key><string>17.0</string><key>CFBundleIdentifier</key><string>example.demo</string></dict></plist>"));err!=nil{t.Fatal(err)}
 if err=z.Close();err!=nil{t.Fatal(err)}
 if err=f.Close();err!=nil{t.Fatal(err)}
 cmd:=compatibilityCommand()
 var out bytes.Buffer
 cmd.SetOut(&out)
 cmd.SetArgs([]string{filename})
 if err=cmd.Execute();err!=nil{t.Fatal(err)}
 for _,value:=range []string{"example.demo","17.0","device_assessment","binaries"}{
  if !strings.Contains(out.String(),value){t.Fatalf("missing %s in %s",value,out.String())}
 }
}
