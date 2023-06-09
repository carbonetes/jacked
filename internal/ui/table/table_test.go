package table

import (
	"testing"

	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/pkg/core/model"
)

type Validator struct{
    packages 	[]dm.Package
	expected    bool
}

type SecretValidator struct{
    secrets		dm.SecretResults
	expected    bool
}

type LicenseValidator struct{
    licenses	[]model.License
	expected    bool
}

//for table go
func TestDisplayScanResultTable(t *testing.T){

	tests := []Validator{
		{
			[]dm.Package{
			   {
				Name : " busybox1",
				Version : "1.35.0-r28",
				Type : "apk",
				Vulnerabilities : &[]model.Vulnerability{
				   {
					   CVE : "CVE-2022-28391",
					   CVSS : model.CVSS {
						   Severity: "High",
					   },
					   Criteria : model.Criteria{
						   Constraint : "1.35.0",
					   },
				   },
				},
			   },
		   },
		   true,
		},
		{
			[]dm.Package{
			   {
				Name : " busybox2",
				Version : "1.35.0-r28",
				Type : "apk",
				Vulnerabilities : nil,
			   },
		   },
		   false,
		},
		{
			[]dm.Package{
			   {
				Name : " busybox3",
				Version : "1.35.0-r28",
				Type : "apk",
				Vulnerabilities : &[]model.Vulnerability{
				   {
					   CVE : "CVE-2022-28391",
					   CVSS : model.CVSS {
						   Severity: "Medium",
					   },
					   Criteria : model.Criteria{
						   Constraint : "1.35.0",
					   },
				   },
				},
			   },
		   },
		   true,
		},
	}

	for _, test := range tests{
		if result := DisplayScanResultTable(&test.packages); len(result) > 0 != test.expected{
			t.Errorf(" Test Failed: There was an error on the display table");
		}
	}
}

// for secrects table
func TestPrintSecrets(t *testing.T) {
	tests := []SecretValidator{
		{
			dm.SecretResults{
				   Secrets : nil,
		   },false,
		},
		{
			dm.SecretResults{
					Secrets : []dm.Secret{
						{
							ContentRegexName : "Regex name",
							FileName : "File Name",
							FilePath : "../../File/Path",
							LineNumber : "10",
						},
				},
			}, true,
		},
		{
			dm.SecretResults{
				   Secrets : nil,
		   },false,
		},
	}

	for _, test := range tests{
		if result := PrintSecrets(&test.secrets); result > 0 != test.expected{
			t.Errorf(" Test Failed: There was an error on the display secret table");
		}
	}
}

// for license
func TestPrintLicense(t *testing.T) {
	tests := []LicenseValidator{
		{
			[]model.License{
			   {
				Package : "Package 1",
				License : "License 1",
			   },
		   },
		   true,
		},
		{
			[]model.License{
			   {
				Package : "Package 2",
				License : "License 2",
			   },
		   },
		   true,
		},
		{
		   nil,
		   false,
		},
	}
 
	for _, test := range tests{
		if result := PrintLicenses(test.licenses); result > 0 != test.expected{
			t.Errorf(" Test Failed: There was an error on the display license table");
		}
	}
}