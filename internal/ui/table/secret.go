package table

import (
	"fmt"

	"github.com/alexeyco/simpletable"
	dm "github.com/carbonetes/diggity/pkg/model"
)

var (
	secretTable = simpletable.New()
)

func secretHeader() {
	secretTable.Header = &simpletable.Header{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignCenter, Text: "#"},
			{Align: simpletable.AlignCenter, Text: "Content Regex"},
			{Align: simpletable.AlignCenter, Text: "File Name"},
			{Align: simpletable.AlignCenter, Text: "File Path"},
			{Align: simpletable.AlignCenter, Text: "Line Number"},
		},
	}
}

func secretRows(secrets *dm.SecretResults) int{
	var count int = 1
	for _, secret := range secrets.Secrets {
		r := []*simpletable.Cell{
			{Align: simpletable.AlignRight, Text: fmt.Sprintf("%v", count)},
			{Text: secret.ContentRegexName},
			{Text: secret.FileName},
			{Text: secret.FilePath},
			{Text: secret.LineNumber},
		}
		count++
		secretTable.Body.Cells = append(secretTable.Body.Cells, r)
	}
	secretFooter(count - 1)
	return count -1
}

func secretFooter(count int) {
	secretTable.Footer = &simpletable.Footer{
		Cells: []*simpletable.Cell{
			{
				Span:  5,
				Align: simpletable.AlignLeft,
				Text:  fmt.Sprintf("%s: %v", "Secrets Found: ", count),
			},
		},
	}
}

func PrintSecrets(secrets *dm.SecretResults) int{
	secretHeader()
	totalRows := secretRows(secrets)
	secretTable.SetStyle(simpletable.StyleCompactLite)
	log.Println("\nSecrets")
	log.Println(secretTable.String())
	return totalRows
}
