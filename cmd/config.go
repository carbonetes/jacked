package cmd

import (
	"os"

	"github.com/carbonetes/jacked/internal/config"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

var (
	cfgCmd = &cobra.Command{
		Use:   "config [flags]",
		Short: "Display the current configurations",
		Run:   cfgRun,
	}
)

func init() {
	rootCmd.AddCommand(cfgCmd)

	cfgCmd.Flags().BoolP("display", "d", false, "Display the content of the CI configuration file")
	cfgCmd.Flags().BoolP("ci-display", "", false, "Display the content of the configuration file")
	cfgCmd.Flags().BoolP("help", "h", false, "Help for configuration")
	cfgCmd.Flags().BoolP("path", "p", false, "Display the path of the configuration file")
	cfgCmd.Flags().BoolP("ci-path", "", false, "Display the path of the CI configuration file")
	cfgCmd.Flags().BoolP("reset", "r", false, "Restore default configuration file")
	cfgCmd.Flags().BoolP("ci-reset", "", false, "Restore default CI configuration file")
}

func cfgRun(c *cobra.Command, _ []string) {
	configuration, err := yaml.Marshal(&cfg)
	if err != nil {
		log.Fatalf("Error marshalling config: %v", err)
		os.Exit(0)
	}

	ciConfig, err := yaml.Marshal(&ciCfg)
	if err != nil {
		log.Fatalf("Error marshalling CI config: %v", err)
		os.Exit(0)
	}

	if c.Flags().Changed("display") {
		log.Info(config.File)
		log.Infof("%v", string(configuration))
		os.Exit(0)
	}
	if c.Flags().Changed("ci-display") {
		log.Info(config.CIFile)
		log.Infof("%v", string(ciConfig))
		os.Exit(0)
	}
	if c.Flags().Changed("path") {
		log.Info(config.File)
		os.Exit(0)
	}
	if c.Flags().Changed("ci-path") {
		log.Info(config.CIFile)
		os.Exit(0)
	}
	if c.Flags().Changed("reset") {
		var newCfg config.Configuration
		newCfg.ResetDefault()
	}
	if c.Flags().Changed("ci-reset") {
		var newCiCfg config.CIConfiguration
		newCiCfg.CIResetDefault()
	}else {
		err := c.Help()
		if err != nil {
			log.Errorln(err.Error())
		}
		os.Exit(0)
	}
}
