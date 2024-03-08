package cmd

import (
	"encoding/json"
	"os"

	"github.com/carbonetes/jacked/internal/db"
	"github.com/carbonetes/jacked/internal/log"

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
	root.AddCommand(dbCmd)

	// Build flag to print the database current build based on the local metadata
	dbCmd.Flags().BoolP("build", "b", false, "Print database current build")

	// Info flag to print the database metadata information based on the local metadata
	dbCmd.Flags().BoolP("info", "i", false, "Print database metadata information")

	// Update DB flag to do force update on vulnerability database without scanning 
	dbCmd.Flags().BoolP("update-db", "u", false, "Update the vulnerability database without scanning")
}

func dbRun(c *cobra.Command, _ []string) {
	if c.Flags().Changed("build") {
		log.Infof("%v", db.GetLocalMetadata().Build)
		os.Exit(0)
	}
	if c.Flags().Changed("info") {
		metadata, err := json.MarshalIndent(db.GetLocalMetadata(), "", "  ")
		if err != nil {
			log.Printf("Error marshalling: %v", err.Error())
		}
		log.Infof("%v", string(metadata))
		os.Exit(0)
	}
	if c.Flags().Changed("update-db") {
		db.DBCheck(false, true)
	} else {
		err := c.Help()
		if err != nil {
			log.Error(err)
		}
		os.Exit(0)
	}
}
