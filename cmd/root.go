package cmd

import (
	"os"
	"strings"

	"github.com/carbonetes/jacked/internal/engine"
	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/internal/ui/spinner"
	"github.com/carbonetes/jacked/internal/version"
	"github.com/carbonetes/jacked/pkg/core/ci"
	"github.com/carbonetes/jacked/pkg/core/model"
	"golang.org/x/exp/slices"

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
	Long:   `Jacked provides organizations with a more comprehensive look at their application to take calculated actions and create a better security approach. Its primary purpose is to scan vulnerabilities to implement subsequent risk mitigation measures.`,
	PreRun: preRun,
	Run:    run,
}

func preRun(_ *cobra.Command, args []string) {
	if len(args) > 0 {
		arguments.Image = &args[0]
		arguments.Quiet = &quiet
		cfg.Output = *arguments.Output
		cfg.LicenseFinder = license
		//arguments for CI Mode
		ciCfg.FailCriteria.Package.Name = appendIgnoreList(ciCfg.FailCriteria.Package.Name, *arguments.IgnorePackageNames)
		ciCfg.FailCriteria.Vulnerability.CVE = appendIgnoreList(ciCfg.FailCriteria.Vulnerability.CVE, *arguments.IgnoreCVEs)
		//arguments for normal scan
		cfg.Ignore.Package.Name = appendIgnoreList(cfg.Ignore.Package.Name, *arguments.IgnorePackageNames)
		cfg.Ignore.Vulnerability.CVE = appendIgnoreList(cfg.Ignore.Vulnerability.CVE, *arguments.IgnoreCVEs)

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
		*arguments.DisableSecretSearch = false
		cfg.SecretConfig.Disabled = false
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
		ci.Analyze(arguments, &ciCfg, false)
	}

	checkDefinedArguments(arguments)
	engine.Start(arguments, &cfg)
}

func checkDefinedArguments(arguments *model.Arguments) {
	// Check user output type is supported
	if arguments.Output != nil && *arguments.Output != "" {
		acceptedArgs := ValidateOutputArg(*arguments.Output)
		if len(acceptedArgs) > 0 {
			*arguments.Output = strings.Join(acceptedArgs, ",")
		} else {
			*arguments.Output = acceptedArgs[0]
		}
	}

	if len(*arguments.Image) != 0 && !strings.Contains(*arguments.Image, tagSeparator) {
		log.Print("Using default tag:", defaultTag)
		modifiedTag := *arguments.Image + tagSeparator + defaultTag
		arguments.Image = &modifiedTag
	}
}

// ValidateOutputArg checks if output types specified are valid
func ValidateOutputArg(outputArg string) []string {
	var acceptedArgs []string

	if strings.Contains(outputArg, ",") {
		for _, o := range strings.Split(outputArg, ",") {
			if slices.Contains(OutputTypes, strings.ToLower(o)) {
				acceptedArgs = append(acceptedArgs, strings.ToLower(o))
			}
		}
	} else {
		if slices.Contains(OutputTypes, strings.ToLower(outputArg)) {
			acceptedArgs = append(acceptedArgs, strings.ToLower(outputArg))
		}
	}
	return acceptedArgs
}

func appendIgnoreList(currentList []string, input string) []string {
	if len(input) == 0 {
		return removeDuplicates(currentList)
	}
	var newList []string
	if strings.Contains(input, ",") {
		newList = append(newList, strings.Split(input, ",")...)
	} else {
		newList = append(newList, input)
	}
	return removeDuplicates(newList)
}

func removeDuplicates(slice []string) []string {
	encountered := map[string]bool{}
	result := []string{}

	for _, str := range slice {
		strLowerCase := strings.ToLower(str)
		if !encountered[strLowerCase] {
			encountered[strLowerCase] = true
			result = append(result, strLowerCase)
		}
	}
	return result
}
