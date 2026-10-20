package main

import (
 "github.com/londek/ipadecrypt/internal/analysis/ipsw"
 "github.com/spf13/cobra"
)

func evidenceCommand()*cobra.Command{
 cmd:=&cobra.Command{
  Use:"evidence <beta3-components-dir> <beta4-components-dir>",
  Short:"Compare extracted firmware components for iPhone16,2 without claiming exploitability",
  Args:cobra.ExactArgs(2),
  RunE:func(cmd *cobra.Command,args []string)error{
   result,err:=ipsw.CompareComponents(args[0],args[1],"24B5099f","24B5110a")
   if err!=nil{return err}
   data,err:=result.JSON();if err!=nil{return err}
   _,err=cmd.OutOrStdout().Write(append(data,'\n'))
   return err
  },
 }
 return cmd
}
