package convert

import (
	"testing"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/pkg/core/model"
)

type validator struct {
  vulnerability  	model.Vulnerability
  component	    	cyclonedx.Component
  
}

func TestToVex(t *testing.T) {
	test := validator{
		vulnerability: model.Vulnerability{
			ID:          1,
			CVE:         "CVE-2023-1234",
			Package:     "example-package",
			Criteria: model.Criteria{
				CPES:          []string{"cpe:/o:example:package:1.0"},
				Constraint:    "less than 2.0",
				Source:        "example-source",
				VersionFormat: "Semantic Versioning",
				Scope:         "example-scope",
			},
			CVSS: model.CVSS{
				Method:   "CVSSv3",
				Severity: "Severe",
				Score:    9.8,
				Vector:   "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			},
			Remediation: &model.Remediation{
				Source: "example-source",
				State:  "Fixed",
				Fix:    "Update to the latest version",
				Scope:  "example-scope",
			},
			Reference: model.Reference{
				Source: "example-source",
				URL:    "https://example.com",
			},
			Description: model.Description{
				Content: "Example vulnerability description",
			},
		},
		component: cyclonedx.Component{
			Name : "busybox",
			BOMRef : "pkg:apk/alpine/busybox@1.35.0-r29?arch=x86_64&upstream=busybox&distro=alpine?package-id=262a8e56-1a4d-416a-afbe-706263fedacf",
		},
	}
    //call the toVex Function
	vex := ToVex(&test.component, &test.vulnerability)
	// set the source and ratings to a variable
	source := vex.Source
	ratings := *vex.Ratings
	//set the test vulnerability a  variable so it would be easier to access its fields
	vul := test.vulnerability
	//declare variables that holds the value from cyclonedx scoring method and severity
	ratingMethod := cyclonedx.ScoringMethod(vul.CVSS.Method)
	ratingSeverity := cyclonedx.Severity(vul.CVSS.Severity)
	//check if the returned value of vex BOMRef is correct
	bomRefIsCorrect := strings.EqualFold(test.component.BOMRef, vex.BOMRef)
	//check if the returned value of vex ID is correct
	idIsCorrect := strings.EqualFold(vex.ID, vul.CVE)
	//check if all the returned value of vex Source is correct
	sourceIsCorrect := (strings.EqualFold(source.Name,vul.Reference.Source)) && (strings.EqualFold(source.URL,vul.Reference.URL))
	//check if all the returned value of vex Rating is correct
	ratingIsCorrect := (ratings[0].Method == ratingMethod) && (vul.CVSS.Score == *ratings[0].Score) && (ratings[0].Severity == ratingSeverity) && (strings.EqualFold(ratings[0].Vector, vul.CVSS.Vector))
	//check if the returned value of vex Description content is correct
    descriptionIsCorrect := strings.EqualFold(vex.Description, vul.Description.Content)
	//check if the returned value of vex Description content is correct
    recommendationIsCorrect := (len(vul.Remediation.Fix) > 0) && (len(vex.Recommendation) > 0)
	
    //return an Error if one of the returned vex field is incorrect
	if !bomRefIsCorrect || !idIsCorrect || !sourceIsCorrect || !ratingIsCorrect ||!descriptionIsCorrect || !recommendationIsCorrect{
		t.Error(" Test Failed: An incorrect value of a vex field is detected");
	}
}
