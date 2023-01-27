package cmd

import (
	"github.com/carbonetes/jacked/internal/config"
	"github.com/carbonetes/jacked/internal/model"

	"github.com/spf13/cobra"
)

var (
	Arguments    model.Arguments
	cfg          config.Configuration
	outputFormat string
	quiet        bool
	license      bool
	secret       bool
)

func init() {
	cfg.Load()

	rootCmd.Flags().StringVarP(&outputFormat, "output", "o", cfg.Settings.Output, "Show scan results in \"json\" or \"table\" format")
	rootCmd.Flags().BoolVarP(&secret, "secrets", "s", cfg.Settings.Secret, "Enable scanning for secrets")
	rootCmd.Flags().BoolVarP(&license, "licenses", "l", cfg.Settings.License, "Enable scanning for package licenses")
	rootCmd.Flags().BoolVarP(&quiet, "quiet", "q", cfg.Settings.Quiet, "Disable all logging statements")
	rootCmd.Flags().BoolP("version", "v", false, "Print application version")

	rootCmd.PersistentFlags().BoolP("help", "h", false, "")
	rootCmd.PersistentFlags().Lookup("help").Hidden = true
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})

}
