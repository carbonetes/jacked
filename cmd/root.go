package cmd

import (
	"os"
	"strings"

	"github.com/carbonetes/jacked/internal/engine"
	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/internal/ui/spinner"
	"github.com/carbonetes/jacked/internal/version"

	"github.com/spf13/cobra"
)

const (
	defaultTag   string = "latest"
	tagSeparator string = ":"
)

var rootCmd = &cobra.Command{
	Use:    "jacked [image]",
	Args:   cobra.MaximumNArgs(1),
	Short:  "Jacked Vulnerability Analyzer",
	Long:   `Description: Jacked Vulnerability Analyzer`,
	PreRun: preRun,
	Run:    run,
}

func preRun(c *cobra.Command, args []string) {
	if len(args) > 0 {
		Arguments.Image = &args[0]
		Arguments.Output = &outputFormat
		Arguments.Quiet = &quiet
		cfg.Settings.License = license
		cfg.Settings.Secret = secret
		if *Arguments.Quiet {
			logger.SetQuietMode()
			spinner.Disable()
		}
	}
}

func run(c *cobra.Command, args []string) {

	if c.Flags().Changed("version") {
		log.Infof("%v", version.GetBuild().Version)
		os.Exit(0)
	}
	if len(args) == 0 && Arguments.Image == nil {
		c.Help()
		os.Exit(0)
	}
	if !strings.Contains(*Arguments.Image, tagSeparator) {
		log.Print("Using default tag:", defaultTag)
		modifiedTag := *Arguments.Image + tagSeparator + defaultTag
		Arguments.Image = &modifiedTag
	}

	engine.Start(&Arguments, &cfg)
}
