package helper

import "regexp"

// MatchNamedCaptureGroups returns a map of named capture groups from the first match of the regex in the content.
// Only named groups with non-empty names are included.
func MatchNamedCaptureGroups(regEx *regexp.Regexp, content string) map[string]string {
	match := regEx.FindStringSubmatch(content)
	if match == nil {
		return nil
	}

	results := make(map[string]string)
	found := false
	for i, name := range regEx.SubexpNames() {
		if i == 0 || name == "" {
			continue // skip the full match and unnamed groups
		}
		results[name] = match[i]
		if match[i] != "" {
			found = true
		}
	}

	if !found {
		return nil
	}
	return results
}
