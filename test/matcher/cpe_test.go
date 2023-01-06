package test

import (
	"testing"

	"github.com/carbonetes/jacked/internal/matcher"
)

func TestCpeMatcher(t *testing.T) {
	for _, test := range tests {
		t.Run(test.Condition, func(t *testing.T) {
			result, err := matcher.MatchCpe(test.Package.CPEs, test.Vulnerability.Cpe)
			if err != nil {
				t.Fatal(err)
			}
			if result != test.Cpe_test.Expected {
				t.Errorf("Expected %v, got %v", test.Cpe_test.Expected, result)
			}
		})
	}

}
