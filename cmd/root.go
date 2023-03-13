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

	// Check user output type is supported
	if arguments.Output != nil && *arguments.Output != "" {
		compareOutputToOutputTypes(*arguments.Output)
	}

	// Check user failcriteria is supported
	if arguments.FailCriteria != nil && *arguments.FailCriteria != "" {
		compareFailCriteriaToSeverities(arguments.FailCriteria)
	}

	if len(*arguments.Image) != 0 && !strings.Contains(*arguments.Image, tagSeparator) {
		log.Print("Using default tag:", defaultTag)
		modifiedTag := *arguments.Image + tagSeparator + defaultTag
		arguments.Image = &modifiedTag
		*arguments.Tar = ""
		*arguments.Dir = ""
		*arguments.SbomFile = ""
	} else if len(*arguments.Tar) != 0 {
		log.Printf("Scanning Tar File: %v", *arguments.Tar)
		arguments.Image = nil
		*arguments.Dir = ""
		*arguments.SbomFile = ""
	} else if len(*arguments.Dir) != 0 {
		log.Printf("Scanning Directory: %v", *arguments.Dir)
		arguments.Image = nil
		*arguments.Tar = ""
		*arguments.SbomFile = ""
	} else if len(*arguments.SbomFile) != 0 {
		log.Printf("Scanning SBOM JSON: %v", *arguments.SbomFile)
		arguments.Image = nil
		*arguments.Tar = ""
		*arguments.Dir = ""
	}

	engine.Start(&arguments, &cfg)
}

// ValidateOutputArg checks if output types specified are valid
func compareOutputToOutputTypes(outputs string) {
	var noMatch bool
	for _, output := range strings.Split(outputs, ",") {
		for _, outputType := range OutputTypes {
			if strings.EqualFold(output, outputType) {
				noMatch = true
				break
			}
			noMatch = false
		}
		if !noMatch {
			log.Errorf("[warning]: Invalid output type: %+v \nSupported output types: %v", output, OutputTypes)
			os.Exit(0)

		}
	}

}

func compareFailCriteriaToSeverities(failCriteria *string) {
	var noMatch bool
	for _, severity := range Severities {
		if strings.EqualFold(*failCriteria, severity) {
			noMatch = true
			break
		}
		noMatch = false
	}

	if !noMatch {
		log.Errorf("[warning]: Invalid output type: %+v \nSupported output types: %v", *failCriteria, Severities)
		os.Exit(0)

	}
}
