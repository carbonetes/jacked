package analysis

func GetSeverity(baseScore float64) string {
	if baseScore >= 0.0 && baseScore <= 3.9 {
		return "LOW"
	}
	if baseScore >= 4.0 && baseScore <= 6.9 {
		return "MEDIUM"
	}
	if baseScore >= 7.0 && baseScore <= 10.0 {
		return "HIGH"
	}
	return "UNKNOWN"
}
