package presenter

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/internal/tea/table"
	"github.com/carbonetes/jacked/pkg/types"
)

func Display(params types.Parameters, elapsed float64, bom *cyclonedx.BOM) {
	if len(params.File) > 0 {
		err := helper.SaveToFile(bom, params.File, params.Format.String())
		if err != nil {
			log.Errorf("Failed to save results to file : %s", err.Error())
		}
		return
	}

	// Display the results
	switch params.Format {
	case types.Table:
		// Display the results in a table format
		table.Show(table.Create(bom), elapsed)
	case types.JSON:
		// Display the results in a JSON format
		result, err := helper.ToJSON(*bom)
		if err != nil {
			log.Error(err)
		}
		log.Print(string(result))
	}

}
