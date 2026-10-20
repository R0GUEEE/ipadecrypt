// Package ipsw provides optional, read-only integration with blacktop/ipsw.
// It never treats successful static analysis as evidence of FairPlay decryption.
package ipsw

import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "os/exec"
 "strings"
)

type Runner func(context.Context,string,...string)([]byte,error)
type Tool struct {
 Binary string
 Run Runner
}
type Status struct {
 Installed bool `json:"installed"`
 Version string `json:"version,omitempty"`
 Reason string `json:"reason,omitempty"`
}
func (t Tool) binary()string{
 if t.Binary==""{return "ipsw"}
 return t.Binary
}
func (t Tool) run(ctx context.Context,args ...string)([]byte,error){
 if t.Run!=nil{return t.Run(ctx,t.binary(),args...)}
 cmd:=exec.CommandContext(ctx,t.binary(),args...)
 return cmd.CombinedOutput()
}
func (t Tool) Probe(ctx context.Context)Status{
 b,err:=t.run(ctx,"version")
 if err!=nil{return Status{Reason:fmt.Sprintf("ipsw unavailable: %v",err)}}
 return Status{Installed:true,Version:strings.TrimSpace(string(b))}
}
type MachOReport struct{
 Tool string `json:"tool"`
 Data json.RawMessage `json:"data"`
}
// InspectMachO executes only the documented, read-only macho info operation.
// It requires a local path supplied by the caller; never passes through a shell.
func (t Tool) InspectMachO(ctx context.Context,filename string)(MachOReport,error){
 if strings.TrimSpace(filename)==""{return MachOReport{},errors.New("missing Mach-O path")}
 out,err:=t.run(ctx,"macho","info",filename,"--json")
 if err!=nil{return MachOReport{},fmt.Errorf("ipsw macho info failed: %w",err)}
 out=bytes.TrimSpace(out)
 if !json.Valid(out){return MachOReport{},errors.New("ipsw returned non-JSON output")}
 return MachOReport{Tool:"blacktop/ipsw",Data:json.RawMessage(out)},nil
}
