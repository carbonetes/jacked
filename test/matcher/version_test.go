package test

import (
	"testing"

	"github.com/carbonetes/jacked/internal/matcher"
)

func TestVersionMatcher(t *testing.T) {
	for _, test := range tests {
		t.Run(test.Condition, func(t *testing.T) {
			result, err := matcher.MatchVersion(test.Package.Version, &test.Vulnerability)
			if err != nil {
				t.Fatal(err)
			}
			if result != test.Version_test.Expected {
				t.Errorf("Expected %t, but got %t", test.Version_test.Expected, result)
			}
		})
	}
}
