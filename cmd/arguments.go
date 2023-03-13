package cmd

import (
	"fmt"

	"github.com/carbonetes/jacked/internal/config"
	"github.com/carbonetes/jacked/internal/model"

	"github.com/spf13/cobra"
)

var (
	arguments model.Arguments = model.Arguments{
		DisableFileListing:  new(bool),
		SecretContentRegex:  new(string),
		DisableSecretSearch: new(bool),
		Image:               new(string),
		SbomFile:            new(string),
		Dir:                 new(string),
		Tar:                 new(string),
		Quiet:               new(bool),
		OutputFile:          new(string),
		ExcludedFilenames:   &[]string{},
		EnabledParsers:      &[]string{},
		RegistryURI:         new(string),
		RegistryUsername:    new(string),
		RegistryPassword:    new(string),
		RegistryToken:       new(string),
		FailCriteria:        new(string),
	}
	cfg         config.Configuration
	quiet       bool
	license     bool
	secrets     bool
	parserNames = []string{
		"apk",
		"debian",
		"java",
		"npm",
		"composer",
		"python",
		"gem",
		"rpm",
		"dart",
		"nuget",
		"go",
	}
	OutputTypes = []string{
		"table",
		"json",
		"cyclonedx-json",
		"cyclonedx-xml",
		"cyclonedx-vex-json",
		"cyclonedx-vex-xml",
		"spdx-json",
		"spdx-xml",
		"spdx-tag-value",
	}
	Severities = []string{
		"unknown",
		"negligible",
		"low",
		"medium",
		"high",
		"critical",
	}
)

func init() {

	// Configuration set Flags Arguments
	cfg.Load()

	arguments.DisableSecretSearch = &cfg.SecretConfig.Disabled
	arguments.SecretContentRegex = &cfg.SecretConfig.SecretRegex
	arguments.ExcludedFilenames = cfg.SecretConfig.Excludes
	arguments.SecretMaxFileSize = cfg.SecretConfig.MaxFileSize
	arguments.EnabledParsers = &cfg.EnabledParsers
	arguments.DisableFileListing = &cfg.DisableFileListing
	arguments.RegistryURI = &cfg.Registry.URI
	arguments.RegistryToken = &cfg.Registry.Token
	arguments.RegistryUsername = &cfg.Registry.Username
	arguments.RegistryPassword = &cfg.Registry.Password
	arguments.Output = &cfg.Output

	rootCmd.Flags().StringVar(arguments.SbomFile, "sbom", "", "Input sbom file from diggity to scan (Only read from json file)")
	rootCmd.Flags().StringVarP(arguments.Output, "output", "o", cfg.Output, fmt.Sprintf("Show scan results in (%v) format", OutputTypes))
	rootCmd.Flags().BoolVarP(&secrets, "secrets", "s", !cfg.SecretConfig.Disabled, "Enable scanning for secrets")
	rootCmd.Flags().BoolVarP(&license, "licenses", "l", cfg.LicenseFinder, "Enable scanning for package licenses")
	rootCmd.Flags().BoolVarP(&quiet, "quiet", "q", cfg.Quiet, "Disable all logging statements")
	rootCmd.Flags().BoolP("version", "v", false, "Print application version")
	rootCmd.Flags().StringVar(arguments.FailCriteria, "fail-criteria", "", fmt.Sprintf("Input a severity that will be found at or above given severity then return code will be 1 (%v)", Severities))

	rootCmd.Flags().StringVarP(arguments.Dir, "dir", "d", "", "Read directly from a path on disk (any directory) (e.g. 'jacked path/to/dir)'")
	rootCmd.Flags().StringVarP(arguments.Tar, "tar", "t", "", "Read a tarball from a path on disk for archives created from docker save (e.g. 'jacked path/to/image.tar)'")
	rootCmd.Flags().BoolVar(arguments.DisableFileListing, "disable-file-listing", cfg.DisableFileListing, "Disables file listing from package metadata (default false)")
	rootCmd.Flags().Int64VarP(&arguments.SecretMaxFileSize, "secret-max-file-size", "", cfg.SecretConfig.MaxFileSize, "Maximum file size that the secret will search -- each file")

	rootCmd.Flags().StringArrayVarP(arguments.ExcludedFilenames, "secret-exclude-filenames", "", *cfg.SecretConfig.Excludes, "Exclude secret searching for each specified filenames")
	rootCmd.Flags().StringArrayVarP(arguments.EnabledParsers, "enabled-parsers", "", cfg.EnabledParsers, fmt.Sprintf("Specify enabled parsers (%+v) (default all)", parserNames))

	rootCmd.Flags().StringVarP(arguments.RegistryURI, "registry-uri", "", cfg.Registry.URI, "Registry uri endpoint")
	rootCmd.Flags().StringVarP(arguments.RegistryUsername, "registry-username", "", cfg.Registry.Username, "Username credential for private registry access")
	rootCmd.Flags().StringVarP(arguments.RegistryPassword, "registry-password", "", cfg.Registry.Password, "Password credential for private registry access")
	rootCmd.Flags().StringVarP(arguments.RegistryToken, "registry-token", "", cfg.Registry.Token, "Access token for private registry access")

	rootCmd.PersistentFlags().BoolP("help", "h", false, "")
	rootCmd.PersistentFlags().Lookup("help").Hidden = true
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})
}
