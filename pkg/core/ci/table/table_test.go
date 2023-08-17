package table

import (
	"testing"

	diggity "github.com/carbonetes/diggity/pkg/scanner"
	dm "github.com/carbonetes/diggity/pkg/model"
	jacked "github.com/carbonetes/jacked/pkg/core/analysis"
	// "github.com/carbonetes/jacked/pkg/core/model"
	"github.com/carbonetes/diggity/pkg/convert"
	"github.com/carbonetes/jacked/internal/config"
	"github.com/carbonetes/jacked/pkg/core/ci/assessment"
)

type Validator struct{
	image		string
	expected	int
}
var(
	cfg config.CIConfiguration
	d = dm.NewArguments()
	
	tests = []Validator{
		{"alpine", 1},
		{"busybox", 1},
	}
)

func TestCDXBomTable(t *testing.T) {
	
	for _, test := range tests {
		d.Image = &test.image
		sbom, _ := diggity.Scan(d)
		cdx := convert.ToCDX(sbom)
		if result := CDXBomTable(cdx); len(result) < test.expected{
			t.Error("Test Failed: CDXBom table is not working properly")
		}
	}
}

func TestCDXVexTable(t *testing.T) {
	
	for _, test := range tests {
		d.Image = &test.image
		sbom, _ := diggity.Scan(d)
		cdx := convert.ToCDX(sbom)
		jacked.AnalyzeCDX(cdx)
		if result := CDXVexTable(cdx); len(result) < test.expected{
			t.Error("Test Failed: CDXVextable is not working properly")
		}
	}
}

func TestIgnoreListTable(t *testing.T) {

	for _, test := range tests {
		if result := IgnoreListTable(&cfg.FailCriteria); len(result) < test.expected{
			t.Error("Test Failed: Ignore List table is not working properly")
		}
	}
}

func TestMatchTable(t *testing.T) {
	asses := &assessment.Assessment{
		Matches : &[]assessment.Match{},
	}

    matches := asses.Matches
	if result := len(MatchTable(matches)); result < 1 {
		t.Error("Test Failed: Match table is not working properly")
	}
}

func TestTallyTable(t *testing.T) {
	asses := &assessment.Assessment{
		Tally : &assessment.Tally{},
	}

    tally := asses.Tally
	if result := len(TallyTable(tally)); result < 1 {
		t.Error("Test Failed: Tally table is not working properly")
	}
}