package validation

import (
 "bytes"
 "testing"
)

// FuzzMachOStructure ensures malformed input cannot crash the offline
// structural parser. Inputs are synthetic and contain no licensed app data.
func FuzzMachOStructure(f *testing.F) {
 f.Add(fixture(1),fixture(0))
 f.Add([]byte{},[]byte{})
 f.Add(bytes.Repeat([]byte{0xff},128),fixture(0))
 f.Fuzz(func(t *testing.T,source,candidate []byte){
  if len(source)>1<<20 || len(candidate)>1<<20 {t.Skip()}
  _=Structure(source,candidate)
 })
}

// FuzzCandidateComparison exercises crypt-region bounds and header handling.
func FuzzCandidateComparison(f *testing.F) {
 f.Add(fixture(1),fixture(0))
 f.Add([]byte{},[]byte{})
 f.Fuzz(func(t *testing.T,source,candidate []byte){
  if len(source)>1<<20 || len(candidate)>1<<20 {t.Skip()}
  _,_=Compare(source,candidate)
 })
}
