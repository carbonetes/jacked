package test

import (
	"testing"

	"github.com/carbonetes/jacked/internal/model"

	"github.com/spf13/cobra"
)

var (
	t         *testing.T
	Arguments model.Arguments
)

var rootCmd = &cobra.Command{
	Use:    "jacked [image] [flags]",
	Short:  "Jacked Vulnerability Analyzer",
	Long:   `Description: Jacked Vulnerability Analyzer`,
	PreRun: preRun,
}

func TestCLi(t *testing.T) {
	Execute()
}

func Execute() {
	rootCmd.CompletionOptions.DisableDefaultCmd = false
	err := rootCmd.Execute()
	if err != nil {
		t.Fail()
	}
}

func preRun(_ *cobra.Command, args []string) {
	args = append(args, "nginx")
	if len(args) == 0 {
		t.Fail()
	}
}
