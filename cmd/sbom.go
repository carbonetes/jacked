package cmd

import (
	"os"

	"github.com/carbonetes/jacked/internal/engine"
	"github.com/spf13/cobra"
)

var (
	sbomCmd = &cobra.Command{
		Use:   "sbom [flags]",
		Short: "Use SBOM JSON format for vulnerability scanning.",
		Run:   sbomRun,
	}
	outputType string = "table"
)

func init() {
	rootCmd.AddCommand(sbomCmd)
	sbomCmd.Flags().StringVarP(&outputType, "output", "o", outputType, "Show scan results in \"table\", \"json\", \"cyclonedx-json\", \"cyclonedx-xml\", \"spdx-json\", \"spdx-xml\", \"spdx-tag-value\" format")
}

func sbomRun(c *cobra.Command, args []string) {

	*arguments.SbomJSONFile = args[0]
	cfg.Output = outputType
	if len(*arguments.SbomJSONFile) == 0 {
		err := c.Help()
		if err != nil {
			log.Errorln(err.Error())
		}
		os.Exit(0)
	}

	engine.Start(&arguments, &cfg)
}
