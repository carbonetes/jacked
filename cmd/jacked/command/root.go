package command

import (
	"os"

	"github.com/carbonetes/jacked/cmd/jacked/build"
	"github.com/carbonetes/jacked/cmd/jacked/ui/progress"
	"github.com/carbonetes/jacked/cmd/jacked/ui/spinner"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/ci"
	"github.com/carbonetes/jacked/pkg/config"
	"github.com/carbonetes/jacked/pkg/scan"
	"github.com/spf13/cobra"
)

var root = &cobra.Command{
	Use:   "jacked [image]",
	Args:  cobra.MaximumNArgs(1),
	Short: "Jacked Vulnerability Analyzer",
	Long:  `Jacked is an open-source vulnerability scanning tool designed to help you identify and mitigate security risks in your Container Images and File Systems.`,
	Run:   rootCmd,
}

// Main entry point
func rootCmd(c *cobra.Command, args []string) {
	// if version flag is set, print the version and exit
	versionArg, _ := c.Flags().GetBool("version")
	if versionArg {
		log.Print(build.GetBuild().Version)
		return
	}

	// Get the flags
	tarball, _ := c.Flags().GetString("tar")
	filesystem, _ := c.Flags().GetString("dir")
	quiet, _ := c.Flags().GetBool("quiet")
	format, _ := c.Flags().GetString("output")
	configFile, _ := c.Flags().GetString("config")
	file, _ := c.Flags().GetString("file")
	debug, _ := c.Flags().GetBool("debug")
	skip, _ := c.Flags().GetBool("skip-db-update")
	force, _ := c.Flags().GetBool("force-db-update")
	ciFlag, _ := c.Flags().GetBool("ci")
	failCriteria, _ := c.Flags().GetString("fail-criteria")

	// Initialize and configure the application
	config.InitializeConfig(configFile)
	log.SetupLogging(debug, quiet)
	ciMode := ci.SetupCIMode(ciFlag, quiet, failCriteria)

	// Apply configuration overrides
	quiet = ciMode.Quiet
	failCriteria = ciMode.FailCriteria

	if quiet {
		// If quiet mode is enabled, force the output format to JSON to avoid any issues
		format = string(scan.JSON)
	} else {
		// If quiet mode is not enabled, enable the spinner and progress bar
		spinner.Skip = false
		progress.Skip = false
	}

	// Create and validate parameters
	options := scan.ScanOptions{
		Quiet:        quiet,
		CI:           ciFlag,
		Format:       format,
		File:         file,
		Skip:         skip,
		Force:        force,
		FailCriteria: failCriteria,
	}
	params := scan.CreateScanParameters(c, args, options)
	if !scan.ValidateInputAndSetup(&params, tarball, filesystem, args) {
		_ = c.Help()
		os.Exit(0)
	}

	config.SetupFailCriteria(failCriteria)

	// Validate the output format type
	if !scan.ValidateFormat(params.Format) {
		log.Fatalf("Output type [%v] is not supported", params.Format)
	}

	// Run the analyzer with the parameters provided
	analyze(params)
}
