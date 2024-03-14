package cmd

import (
	"strings"

	diggity "github.com/carbonetes/diggity/pkg/types"
	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/internal/tea/progress"
	"github.com/carbonetes/jacked/internal/tea/spinner"
	"github.com/carbonetes/jacked/internal/version"
	"github.com/carbonetes/jacked/pkg/analyzer"
	"github.com/carbonetes/jacked/pkg/config"
	"github.com/carbonetes/jacked/pkg/types"
	"github.com/spf13/cobra"
)

var root = &cobra.Command{
	Use:   "jacked [image]",
	Args:  cobra.MaximumNArgs(1),
	Short: "Jacked Vulnerability Analyzer",
	Long:  `Jacked is an open-source vulnerability scanning tool designed to help you identify and mitigate security risks in your Container Images and File Systems.`,
	Run:   run,
}

// Main entry point
func run(c *cobra.Command, args []string) {
	// if version flag is set, print the version and exit
	versionArg, _ := c.Flags().GetBool("version")
	if versionArg {
		log.Print(version.GetBuild().Version)
		return
	}

	// Get the flags
	tarball, _ := c.Flags().GetString("tar")
	filesystem, _ := c.Flags().GetString("directory")
	quiet, _ := c.Flags().GetBool("quiet")
	format, _ := c.Flags().GetString("output-format")
	scanners, _ := c.Flags().GetStringArray("scanners")
	file, _ := c.Flags().GetString("file")
	skip, _ := c.Flags().GetBool("skip-db-update")
	force, _ := c.Flags().GetBool("force-db-update")
	ci, _ := c.Flags().GetBool("ci")
	failCriteria, _ := c.Flags().GetString("fail-criteria")

	// If CI mode is enabled, suppress all output except for errors
	if ci {
		quiet = true
		if len(failCriteria) == 0 || !types.IsValidSeverity(failCriteria) {
			log.Warn("CI mode is enabled, but no valid fail criteria is provided")
			log.Warn("Default fail criteria will be used: 'critical' severity vulnerabilities will fail the build")
			failCriteria = "critical"
		}
	} else {
		if len(failCriteria) > 0 {
			log.Warn("CI mode is not enabled, fail criteria will not be used")
		}
	}

	if quiet {
		// If quiet mode is enabled, suppress the spinner
		spinner.Skip = true
		progress.Skip = true

		// If quiet mode is enabled, force the output format to JSON to avoid any issues
		format = string(types.JSON)
	}
	params := types.Parameters{
		Format:        types.Format(format),
		Quiet:         quiet,
		File:          file,
		SkipDBUpdate:  skip,
		ForceDBUpdate: force,
		CI:            ci,
		Diggity: diggity.Parameters{
			Scanners:     scanners,
			OutputFormat: diggity.JSON,
		},
	}

	if len(args) > 0 {
		params.Diggity.Input = helper.FormatImage(args[0])
	} else if len(tarball) > 0 {
		params.Diggity.Input = tarball
	} else if len(filesystem) > 0 {
		params.Diggity.Input = filesystem
	} else {
		err := c.Help()
		if err != nil {
			log.Error(err)
		}
		return
	}

	// Set the scan type based on the input
	err := params.Diggity.GetScanType()
	if err != nil {
		log.Fatal(err)
		return
	}

	if len(failCriteria) > 0 {
		failCriteria = strings.ToLower(failCriteria)
		config.Config.CI.FailCriteria.Severity = failCriteria
	}

	// Validate the output format type
	valid := validatFormat(params.Format)
	if !valid {
		log.Fatalf("Output type [%v] is not supported", params.Format)
	}

	// Run the analyzer with the parameters provided
	analyzer.New(params)
}

// validatFormat validates the output format type provided by the user and returns true if it is valid else false
func validatFormat(format types.Format) bool {
	switch types.Format(format) {
	case types.JSON, types.Table, types.SPDXJSON, types.SPDXXML, types.SPDXTag, types.SnapshotJSON:
		return true
	default:
		return false
	}
}
