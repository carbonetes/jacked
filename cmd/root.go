package cmd

import (
	"os"
	"strings"

	"github.com/carbonetes/jacked/internal/engine"
	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/internal/ui/spinner"
	"github.com/carbonetes/jacked/internal/version"
	"github.com/carbonetes/jacked/pkg/core/ci"

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
	Long:   `Description: Jacked provides organizations with a more comprehensive look at their application to take calculated actions and create a better security approach. Its primary purpose is to scan vulnerabilities to implement subsequent risk mitigation measures.`,
	PreRun: preRun,
	Run:    run,
}

func preRun(_ *cobra.Command, args []string) {
	if len(args) > 0 {
		arguments.Image = &args[0]
		arguments.Quiet = &quiet
		cfg.Output = *arguments.Output
		cfg.LicenseFinder = license

		if *arguments.Quiet {
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

	if c.Flags().Changed("secrets") {
		if secrets {
			*arguments.DisableSecretSearch = false
			cfg.SecretConfig.Disabled = false
		}
	}

	if len(args) == 0 && len(*arguments.Image) == 0 && len(*arguments.Dir) == 0 && len(*arguments.Tar) == 0 && len(*arguments.SbomFile) == 0 {
		err := c.Help()
		if err != nil {
			log.Errorln(err.Error())
		}
		os.Exit(0)
	}

	if c.Flags().Changed("fail-criteria") {
		if !ciMode {
			log.Warn("Fail Criteria : CI Mode is not enabled.")
		}
	}

	if ciMode {
		ci.Analyze(arguments)
	}

	if len(*arguments.Image) != 0 && !strings.Contains(*arguments.Image, tagSeparator) {
		log.Print("Using default tag:", defaultTag)
		modifiedTag := *arguments.Image + tagSeparator + defaultTag
		arguments.Image = &modifiedTag
	} else if len(*arguments.Tar) != 0 {
		log.Printf("Scanning Tar File: %v", *arguments.Tar)
	} else if len(*arguments.Dir) != 0 {
		log.Printf("Scanning Directory: %v", *arguments.Dir)
	} else if len(*arguments.SbomFile) != 0 {
		log.Printf("Scanning SBOM JSON: %v", *arguments.SbomFile)
	}

	engine.Start(arguments, &cfg)
}
