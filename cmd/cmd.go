package cmd

import "github.com/carbonetes/jacked/internal/logger"

var log = logger.GetLogger()

func Execute() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	err := rootCmd.Execute()
	if err != nil {
		log.Fatalf("Error executing root command: %v", err)
	}
}
