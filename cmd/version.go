package cmd

import (
	"encoding/json"
	"os"

	"github.com/carbonetes/jacked/internal/version"

	"github.com/spf13/cobra"
)

var (
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Display Build Version Information of Jacked",
		Run:   versionRun,
	}
	format string = "text"
)

func init() {
	rootCmd.AddCommand(versionCmd)

	versionCmd.Flags().StringVarP(&format, "format", "f", "text", "Print application version format (json, text)")
}

func versionRun(c *cobra.Command, _ []string) {
	info := version.GetBuild()
	if format == "json" {
		output, err := json.MarshalIndent(info, "", " ")
		if err != nil {
			log.Fatalf("Error marshalling version info: %v", err)
		}
		log.Infof("%v", string(output))
		os.Exit(0)
	} else if format == "text" {
		log.Infof("Application\t: %v", info.Application)
		log.Infof("Version\t\t: %v", info.Version)
		log.Infof("Build Date\t: %v", info.BuildDate)
		log.Infof("Git Commit\t: %v", info.GitCommit)
		log.Infof("Git Description\t: %v", info.GitDesc)
		log.Infof("Go Version\t: %v", info.GoVersion)
		log.Infof("Compiler\t: %v", info.Compiler)
		log.Infof("Platform\t: %v", info.Platform)
		os.Exit(0)
	} else {
		log.Fatal("Invalid output format")
	}
}
