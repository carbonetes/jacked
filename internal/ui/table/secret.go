package table

import (
	"fmt"

	"github.com/carbonetes/jacked/internal/model"

	"github.com/alexeyco/simpletable"
)

var (
	secretTable = simpletable.New()
)

func secretHeader() {
	secretTable.Header = &simpletable.Header{
		Cells: []*simpletable.Cell{
			{Align: simpletable.AlignCenter, Text: Index},
			{Align: simpletable.AlignCenter, Text: "Content Regex"},
			{Align: simpletable.AlignCenter, Text: "File Name"},
			{Align: simpletable.AlignCenter, Text: "File Path"},
			{Align: simpletable.AlignCenter, Text: "Line Number"},
		},
	}
}

func secretRows(secrets model.SecretResults) {
	var index int = 1
	for _, secret := range secrets.Secrets {
		r := []*simpletable.Cell{
			{Align: simpletable.AlignRight, Text: fmt.Sprintf("%v", index)},
			{Text: secret.ContentRegexName},
			{Text: secret.FileName},
			{Text: secret.FilePath},
			{Text: secret.LineNumber},
		}
		index++
		secretTable.Body.Cells = append(secretTable.Body.Cells, r)
	}
	secretFooter(index - 1)
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

func PrintSecrets(secrets model.SecretResults) {
	secretHeader()
	secretRows(secrets)
	secretTable.SetStyle(simpletable.StyleCompactLite)
	log.Println("\nSecrets")
	log.Println(secretTable.String())
}
