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

	cfgCmd.Flags().BoolP("display", "d", false, "Displays the content of the configuration file")
	cfgCmd.Flags().BoolP("help", "h", false, "Help for config")
	cfgCmd.Flags().BoolP("path", "p", false, "Display the path of the configuration file")
	cfgCmd.Flags().BoolP("reset", "r", false, "Restore default configuration file")
}

func cfgRun(c *cobra.Command, _ []string) {
	yamlcfg, err := yaml.Marshal(&cfg)
	if err != nil {
		log.Fatalf("Error marshalling config: %v", err)
		os.Exit(0)
	}

	if c.Flags().Changed("display") {
		log.Infof("%v", string(yamlcfg))
		os.Exit(0)
	}

	if c.Flags().Changed("path") {
		log.Info(config.File)
		os.Exit(0)
	}

	if c.Flags().Changed("reset") {
		var newCfg config.Configuration
		newCfg.ResetDefault()
	} else {
		c.Help()
		os.Exit(0)
	}
}
