package main

import (
 "encoding/json"

 "github.com/londek/ipadecrypt/internal/analysis/ipsw"
 "github.com/londek/ipadecrypt/internal/compatibility"
 "github.com/londek/ipadecrypt/internal/inspection"
 "github.com/spf13/cobra"
)

func compatibilityCommand() *cobra.Command {
 var probeIPSW bool
 command:=&cobra.Command{
  Use:"compat <ipa>",
  Short:"Generate a read-only IPA compatibility and metadata report",
  Args:cobra.ExactArgs(1),
  RunE:func(cmd *cobra.Command,args []string)error{
   app,err:=compatibility.InspectAppMetadata(args[0]);if err!=nil{return err}
   metadata,err:=compatibility.InspectIPA(args[0]);if err!=nil{return err}
   binaries,err:=inspection.IPA(args[0]);if err!=nil{return err}
   assessment:=compatibility.AssessTarget(compatibility.Target{MinimumIOS:app.MinimumIOS},compatibility.Runtime{})
   report:=struct{
    App compatibility.AppMetadata `json:"app"`
    FairPlayMetadata compatibility.Inventory `json:"fairplay_metadata"`
    Binaries []inspection.Binary `json:"binaries"`
    DeviceAssessment compatibility.Assessment `json:"device_assessment"`
    IPSW *ipsw.Status `json:"ipsw,omitempty"`
    Notice string `json:"notice"`
   }{App:app,FairPlayMetadata:metadata,Binaries:binaries,DeviceAssessment:assessment,Notice:"No device probed; report is not evidence of successful decryption."}
   if probeIPSW {status:= (ipsw.Tool{}).Probe(cmd.Context());report.IPSW=&status}
   encoder:=json.NewEncoder(cmd.OutOrStdout())
   encoder.SetIndent("","  ")
   return encoder.Encode(report)
  },
 }
 command.Flags().BoolVar(&probeIPSW,"probe-ipsw",false,"check optional blacktop/ipsw CLI availability")
 return command
}
