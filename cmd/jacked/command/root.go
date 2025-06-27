package command

import (
	"os"
	"strings"
	"time"

	diggity "github.com/carbonetes/diggity/pkg/types"
	"github.com/carbonetes/jacked/cmd/jacked/build"
	"github.com/carbonetes/jacked/internal/helper"
	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/internal/tea/progress"
	"github.com/carbonetes/jacked/internal/tea/spinner"
	"github.com/carbonetes/jacked/internal/tea/table"
	"github.com/carbonetes/jacked/pkg/config"
	"github.com/carbonetes/jacked/pkg/types"
	"github.com/sirupsen/logrus"
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
	performance, _ := c.Flags().GetString("performance")
	configFile, _ := c.Flags().GetString("config")
	nonInteractive, _ := c.Flags().GetBool("non-interactive")
	// scanners, _ := c.Flags().GetStringArray("scanners")
	file, _ := c.Flags().GetString("file")
	debug, _ := c.Flags().GetBool("debug")
	skip, _ := c.Flags().GetBool("skip-db-update")
	force, _ := c.Flags().GetBool("force-db-update")
	ci, _ := c.Flags().GetBool("ci")
	failCriteria, _ := c.Flags().GetString("fail-criteria")

	// New optimization flags
	maxConcurrency, _ := c.Flags().GetInt("max-concurrency")
	scanTimeout, _ := c.Flags().GetDuration("scan-timeout")
	enableCaching, _ := c.Flags().GetBool("enable-caching")
	enableMetrics, _ := c.Flags().GetBool("enable-metrics")
	showMetrics, _ := c.Flags().GetBool("show-metrics")
	enableProfiling, _ := c.Flags().GetBool("enable-profiling")

	// Handle custom config file path
	if configFile != "" {
		log.Debugf("Using custom config file: %s", configFile)
		config.SetConfigPath(configFile)
		// Reload config from the custom path
		config.ReloadConfig()
	}

	// Handle performance optimization level (only if explicitly set)
	if c.Flags().Changed("performance") {
		switch performance {
		case "basic":
			config.Config.Performance = config.GetConfigForOptimizationLevel(types.OptimizationBasic)
		case "balanced":
			config.Config.Performance = config.GetConfigForOptimizationLevel(types.OptimizationBalanced)
		case "aggressive":
			config.Config.Performance = config.GetConfigForOptimizationLevel(types.OptimizationAggressive)
		case "maximum":
			config.Config.Performance = config.GetConfigForOptimizationLevel(types.OptimizationMaximum)
		default:
			log.Warnf("Invalid performance level '%s', using balanced", performance)
			config.Config.Performance = config.GetConfigForOptimizationLevel(types.OptimizationBalanced)
		}
		log.Debugf("Performance optimization level set to: %s", performance)
	}

	// Apply command line overrides to performance configuration
	applyOptimizationOverrides(maxConcurrency, scanTimeout, enableCaching, enableMetrics, enableProfiling)

	// If CI mode is enabled, suppress all output except for errors
	if ci {
		quiet = true
		nonInteractive = true // Also enable non-interactive mode in CI
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

	if debug {
		log.SetLevel(logrus.DebugLevel)
	}

	if quiet {
		// If quiet mode is enabled, force the output format to JSON to avoid any issues
		format = string(types.JSON)
	} else {
		// If quiet mode is not enabled, enable the spinner and progress bar
		spinner.Skip = false
		progress.Skip = false
	}

	// Set non-interactive mode for table display
	if nonInteractive {
		table.NonInteractive = true
	}

	params := types.Parameters{
		Format:        types.Format(format),
		Quiet:         quiet,
		File:          file,
		SkipDBUpdate:  skip,
		ForceDBUpdate: force,
		CI:            ci,
		ShowMetrics:   showMetrics, // Add the show metrics flag
		Diggity: diggity.Parameters{
			OutputFormat: diggity.JSON,
		},
	}

	if filesystem != "" {
		if found, _ := helper.IsDirExists(filesystem); !found {
			log.Fatal("directory not found: " + filesystem)
			return
		}
		params.Diggity.ScanType = 3
		params.Diggity.Input = filesystem
	}

	if tarball != "" {
		if found, _ := helper.IsFileExists(tarball); !found {
			log.Fatal("tarball not found: " + tarball)
			return
		}
		params.Diggity.Input = tarball
		params.Diggity.ScanType = 2
	}

	if filesystem == "" && tarball == "" {
		if len(args) > 0 {
			params.Diggity.Input = helper.FormatImage(args[0])
			params.Diggity.ScanType = 1
		} else {
			_ = c.Help()
			os.Exit(0)
		}
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
	analyze(params)
}

// applyOptimizationOverrides applies command line optimization overrides to the global configuration
func applyOptimizationOverrides(maxConcurrency int, scanTimeout time.Duration, enableCaching, enableMetrics, enableProfiling bool) {
	// Apply overrides to the global performance config
	if maxConcurrency > 0 {
		config.Config.Performance.MaxConcurrentScanners = maxConcurrency
	}

	if scanTimeout > 0 {
		config.Config.Performance.ScanTimeout = scanTimeout
	}

	// Apply boolean settings
	config.Config.Performance.EnableCaching = enableCaching
	config.Config.Performance.EnableMetrics = enableMetrics

	if enableProfiling {
		config.Config.Performance.EnableMetrics = true // Profiling requires metrics
		log.Debug("Profiling enabled - performance data will be collected")
	}
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
