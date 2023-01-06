package test

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/carbonetes/jacked/internal/model"
)

type test struct {
	Condition     string              `json:"condition"`
	Package       model.Package       `json:"package"`
	Vulnerability model.Vulnerability `json:"vulnerability"`
	Cpe_test      result              `json:"cpe_test"`
	Version_test  result              `json:"version_test"`
}

type result struct {
	Test_data string `json:"test_data"`
	Expected  bool   `json:"expected"`
}

var (
	tests []test
)

func init() {
	dataJson, err := os.Open("data/mock_data.json")

	if err != nil {
		panic(err.Error())
	}
	parser := json.NewDecoder(dataJson)
	err = parser.Decode(&tests)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("total test per module: %v\n", len(tests))
}
