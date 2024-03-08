package types

import "strings"

var Severities = []string{
	"unknown",
	"negligible",
	"low",
	"medium",
	"high",
	"critical",
}

func GetJoinedSeverities() string {
	return strings.Join(Severities, ", ")
}

func IsValidSeverity(severity string) bool {
	for _, s := range Severities {
		if s == severity {
			return true
		}
	}
	return false
}
