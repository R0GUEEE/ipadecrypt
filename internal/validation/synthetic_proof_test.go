package validation

import "testing"

func TestSyntheticRecovery(t *testing.T){
 proof,err:=DemonstrateSyntheticRecovery()
 if err!=nil{t.Fatal(err)}
 if !proof.Verified||!proof.CiphertextChanged||proof.PlaintextSHA256!=proof.RecoveredSHA256{t.Fatalf("invalid proof: %+v",proof)}
}
