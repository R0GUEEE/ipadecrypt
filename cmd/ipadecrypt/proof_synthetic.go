package main

import (
 "encoding/json"
 "github.com/londek/ipadecrypt/internal/validation"
 "github.com/spf13/cobra"
)

func init() {}

// syntheticProofCommand demonstrates authenticated recovery of a generated
// test fixture. It does not interact with FairPlay, Apple IDs, or devices.
func syntheticProofCommand() *cobra.Command {
 return &cobra.Command{
  Use:"proof-synthetic",
  Short:"Demonstrate verified recovery of a synthetic encrypted test fixture",
  RunE:func(cmd *cobra.Command,args []string)error{
   proof,err:=validation.DemonstrateSyntheticRecovery()
   if err!=nil{return err}
   encoder:=json.NewEncoder(cmd.OutOrStdout())
   encoder.SetIndent("","  ")
   return encoder.Encode(proof)
  },
 }
}
