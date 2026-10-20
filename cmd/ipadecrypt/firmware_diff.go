package main

import (
 "encoding/json"
 "fmt"
 "os"

 "github.com/londek/ipadecrypt/internal/analysis/ipsw"
 "github.com/spf13/cobra"
)

func firmwareDiffCommand()*cobra.Command{
 var device string
 var output string
 cmd:=&cobra.Command{
  Use:"firmware-diff <older.ipsw> <newer.ipsw>",
  Short:"Compare two local firmware files using optional blacktop/ipsw",
  Args:cobra.ExactArgs(2),
  RunE:func(cmd *cobra.Command,args []string)error{
   pair,err:=ipsw.ValidateFirmwarePair(args[0],args[1],device)
   if err!=nil{return err}
   result,err:=(ipsw.Tool{}).DiffFirmware(cmd.Context(),pair)
   if err!=nil{return fmt.Errorf("%w: %s",err,string(result))}
   if output!=""{
    if err:=os.WriteFile(output,result,0600);err!=nil{return err}
   }else{
    if _,err:=cmd.OutOrStdout().Write(result);err!=nil{return err}
   }
   metadata:=json.NewEncoder(cmd.ErrOrStderr())
   return metadata.Encode(pair)
  },
 }
 cmd.Flags().StringVar(&device,"device","","firmware product identifier (e.g. iPhone18,2)")
 cmd.Flags().StringVar(&output,"output","","save ipsw diff report to this file")
 return cmd
}
