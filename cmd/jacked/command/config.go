package command

import (
	"fmt"
	"os"

	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/pkg/config"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage Jacked configuration",
	Long:  `Manage Jacked configuration file settings. Display, reset, or view the configuration path.`,
}

var configDisplayCmd = &cobra.Command{
	Use:     "display",
	Short:   "Display the content of the configuration file",
	Long:    `Display the current configuration file content with all settings.`,
	Aliases: []string{"show", "view"},
	Run: func(c *cobra.Command, args []string) {
		configPath := config.GetConfigPath()
		fmt.Printf("Configuration file path: %s\n\n", configPath)

		// Read and display the config file content
		content, err := os.ReadFile(configPath)
		if err != nil {
			log.Errorf("Failed to read config file: %v", err)
			return
		}

		fmt.Println("Configuration content:")
		fmt.Println(string(content))
	},
}

var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Display the path of the configuration file",
	Long:  `Display the current path where the configuration file is located.`,
	Run: func(c *cobra.Command, args []string) {
		configPath := config.GetConfigPath()
		fmt.Printf("Configuration file path: %s\n", configPath)
	},
}

var configResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Restore the default configuration file",
	Long:  `Reset the configuration file to default values with complete documentation and comments.`,
	Run: func(c *cobra.Command, args []string) {
		configPath := config.GetConfigPath()

		fmt.Printf("Resetting configuration file: %s\n", configPath)

		// Generate a new default config file
		err := config.GenerateDefaultConfigFile(configPath)
		if err != nil {
			log.Errorf("Failed to reset config file: %v", err)
			return
		}

		fmt.Println("Configuration file has been reset to defaults successfully!")
		fmt.Println("The file now includes comprehensive documentation and all available settings.")
	},
}

var configGenerateCmd = &cobra.Command{
	Use:   "generate [path]",
	Short: "Generate a default configuration file",
	Long:  `Generate a new default configuration file with documentation at the specified path or current directory.`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(c *cobra.Command, args []string) {
		var targetPath string

		if len(args) > 0 {
			targetPath = args[0]
		} else {
			targetPath = "./" + config.DefaultConfigFilename
		}

		fmt.Printf("Generating configuration file: %s\n", targetPath)

		// Generate a new default config file
		err := config.GenerateDefaultConfigFile(targetPath)
		if err != nil {
			log.Errorf("Failed to generate config file: %v", err)
			return
		}

		fmt.Println("Configuration file generated successfully!")
		fmt.Println("The file includes comprehensive documentation and all available settings.")
	},
}

func init() {
	// Add subcommands
	configCmd.AddCommand(configDisplayCmd)
	configCmd.AddCommand(configPathCmd)
	configCmd.AddCommand(configResetCmd)
	configCmd.AddCommand(configGenerateCmd)

	// Add flags to the display command
	configDisplayCmd.Flags().BoolP("debug", "d", false, "Show debug information about the configuration")

	// Add the config command to the root command
	root.AddCommand(configCmd)
}
