package types

import "strings"

var Severities = []string{
	"critcal",
	"high",
	"medium",
	"low",
	"negligible",
	"unknown",
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
