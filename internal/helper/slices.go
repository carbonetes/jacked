package helper

// unique removes duplicates from a slice of strings.
func Unique(s []string) []string {
	unique := make(map[string]struct{})
	for _, v := range s {
		unique[v] = struct{}{}
	}

	uniqueSlice := make([]string, 0, len(unique))
	for k := range unique {
		uniqueSlice = append(uniqueSlice, k)
	}

	return uniqueSlice
}
