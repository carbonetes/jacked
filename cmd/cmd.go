package cmd

import "github.com/carbonetes/jacked/internal/log"

func Execute() {
	root.CompletionOptions.DisableDefaultCmd = true
	err := root.Execute()
	if err != nil {
		log.Fatalf("Error executing root command: %v", err)
	}
}
