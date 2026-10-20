// Package validation checks whether a proposed decrypted Mach-O differs
// from its encrypted source in a way consistent with actual code recovery.
package validation

import (
 "bytes"
 "crypto/sha256"
 "errors"
 "fmt"

 "github.com/londek/ipadecrypt/internal/macho"
)

var ErrNotDecrypted=errors.New("candidate is not proven decrypted")

type Result struct {
 SourceEncrypted bool
 CandidateEncrypted bool
 ProtectedBytesChanged bool
 SourceRegionSHA256 [32]byte
 CandidateRegionSHA256 [32]byte
 Valid bool
 Reason string
}

// Compare requires a thin, little-endian Mach-O source and candidate.
// It rejects header-only cryptid edits and zero-filled replacement regions.
// Passing is evidence of a changed payload, NOT proof of executable validity
// or successful FairPlay authorization.
func Compare(source,candidate []byte)(Result,error){
 var r Result
 s,err:=macho.ReadEncryptionInfo(source);if err!=nil{return r,fmt.Errorf("source: %w",err)}
 c,err:=macho.ReadEncryptionInfo(candidate);if err!=nil{return r,fmt.Errorf("candidate: %w",err)}
 r.SourceEncrypted=s.Cryptid!=0
 r.CandidateEncrypted=c.Cryptid!=0
 if s.CryptOff!=c.CryptOff || s.CryptSize!=c.CryptSize{return r,fmt.Errorf("%w: encrypted region geometry changed",ErrNotDecrypted)}
 if s.CryptOff>uint64(len(source)) || s.CryptSize>uint64(len(source))-s.CryptOff || s.CryptOff>uint64(len(candidate)) || s.CryptSize>uint64(len(candidate))-s.CryptOff{return r,fmt.Errorf("%w: protected region out of bounds",ErrNotDecrypted)}
 a:=source[s.CryptOff:s.CryptOff+s.CryptSize]
 b:=candidate[s.CryptOff:s.CryptOff+s.CryptSize]
 r.SourceRegionSHA256=sha256.Sum256(a)
 r.CandidateRegionSHA256=sha256.Sum256(b)
 r.ProtectedBytesChanged=!bytes.Equal(a,b)
 switch {
 case !r.SourceEncrypted:r.Reason="source has no active encryption marker"
 case r.CandidateEncrypted:r.Reason="candidate still has an encryption marker"
 case len(b)==0:r.Reason="empty protected region"
 case !r.ProtectedBytesChanged:r.Reason="protected bytes unchanged; cryptid-only patch"
 case allZero(b):r.Reason="protected region is all zero"
 default:r.Valid=true;r.Reason="candidate changed protected bytes; independent runtime verification still required"
 }
 if !r.Valid{return r,fmt.Errorf("%w: %s",ErrNotDecrypted,r.Reason)}
 return r,nil
}
func allZero(p []byte)bool{for _,v:=range p{if v!=0{return false}};return true}
