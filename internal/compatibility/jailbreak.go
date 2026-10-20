package compatibility

import "strings"

// JailbreakEnvironment represents an observed, not inferred, device state.
// Never claim that jailbreak presence proves FairPlay plaintext availability.
type JailbreakEnvironment struct {
 Name string `json:"name,omitempty"`
 Rootless bool `json:"rootless"`
 Rootful bool `json:"rootful"`
}
type JailbreakAssessment struct {
 Detected string `json:"detected"`
 Layout string `json:"layout"`
 Notes []string `json:"notes"`
}
func AssessJailbreak(j JailbreakEnvironment) JailbreakAssessment {
 a:=JailbreakAssessment{Detected:"unknown",Layout:"unknown"}
 name:=strings.ToLower(strings.TrimSpace(j.Name))
 switch {
 case strings.Contains(name,"dopamine"):a.Detected="dopamine"
 case strings.Contains(name,"palera1n"):a.Detected="palera1n"
 }
 switch {
 case j.Rootful&&j.Rootless:a.Notes=append(a.Notes,"conflicting filesystem layout flags")
 case j.Rootless:a.Layout="rootless"
 case j.Rootful:a.Layout="rootful"
 default:a.Notes=append(a.Notes,"filesystem layout not confirmed")
 }
 a.Notes=append(a.Notes,"jailbreak detection does not establish FairPlay decryption capability")
 return a
}
