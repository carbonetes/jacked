package cmd

import (
	"encoding/json"
	"os"

	"github.com/carbonetes/jacked/internal/db"

	"github.com/spf13/cobra"
)

var (
	dbCmd = &cobra.Command{
		Use:   "db [flags]",
		Short: "Display the database information",
		Run:   dbRun,
	}
)

func init() {
	rootCmd.AddCommand(dbCmd)

	dbCmd.Flags().BoolP("version", "v", false, "Print database current version")
	dbCmd.Flags().BoolP("info", "i", false, "Print database metadata information")
}

func dbRun(c *cobra.Command, _ []string) {
	if c.Flags().Changed("version") {
		log.Infof("%v", db.GetLocalMetadata().Version)
		os.Exit(0)
	}
	if c.Flags().Changed("info") {
		metadata, err := json.MarshalIndent(db.GetLocalMetadata(), "", "  ")
		if err != nil {
			log.Printf("Error marshalling: %v", err.Error())
		}
		log.Infof("%v", string(metadata))
		os.Exit(0)
	} else {
		err := c.Help()
		if err != nil {
			log.Errorln(err.Error())
		}
		os.Exit(0)

	}
}
