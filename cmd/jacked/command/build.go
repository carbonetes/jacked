package command

import (
	"os"

	"github.com/carbonetes/jacked/cmd/jacked/build"
	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/internal/log"

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
	root.AddCommand(versionCmd)

	// Format flag to specify the output format of the version information
	versionCmd.Flags().StringVarP(&format, "format", "f", "text", "Print application version format (json, text)")
}

func versionRun(c *cobra.Command, _ []string) {
	info := build.GetBuild()
	switch format {
	case "json":
		output, err := helper.ToJSON(info)
		if err != nil {
			log.Fatalf("Error marshalling version info: %v", err)
		}
		log.Infof("%v", string(output))
	case "text":
		log.Infof("Application\t: %v", info.Application)
		log.Infof("Version\t\t: %v", info.Version)
		log.Infof("Build Date\t: %v", info.BuildDate)
		log.Infof("Git Commit\t: %v", info.GitCommit)
		log.Infof("Git Description\t: %v", info.GitDesc)
		log.Infof("Go Version\t: %v", info.GoVersion)
		log.Infof("Compiler\t: %v", info.Compiler)
		log.Infof("Platform\t: %v", info.Platform)
	default:
		log.Fatal("Invalid output format. Use 'json' or 'text'")
	}
	os.Exit(0)
}
