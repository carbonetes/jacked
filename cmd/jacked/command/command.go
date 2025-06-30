package command

import (
	"fmt"

	"github.com/carbonetes/jacked/pkg/ci"
	"github.com/carbonetes/jacked/pkg/scan"
	"github.com/spf13/cobra"
)

func init() {

	// Skip DB Update flag to skip the database update on scanning
	root.Flags().BoolP("skip-db-update", "", false, "Skip Database Update on Scanning")

	// Force DB Update flag to force the immediate implementation of database updates
	root.Flags().BoolP("force-db-update", "", false, "Enables immediate implementation of database updates")

	// Tarball flag to scan a tarball
	root.Flags().StringP("tar", "t", "", "Read a tarball from a path on disk for archives created from docker save (e.g. 'jacked -t path/to/image.tar)'")

	// Directory flag to scan a directory
	root.Flags().StringP("dir", "d", "", "Read directly from a path on disk (any directory) (e.g. 'jacked -d path/to/directory)'")

	// Quiet flag to allows the user to suppress all output except for errors
	root.Flags().BoolP("quiet", "q", false, "Suppress all output except for errors")

	// Output flag to specify the output format
	root.Flags().StringP("output", "o", string(scan.Table), "Supported output types are: "+scan.GetAllOutputFormat())

	// Performance optimization level flag
	root.Flags().String("performance", "balanced", "Set performance optimization level (basic, balanced, aggressive, maximum)")

	// Configuration file flag
	root.Flags().StringP("config", "c", "", "Path to configuration file (default: $HOME/.jacked.yaml)")

	// File flag to save the scan result to a file
	root.Flags().StringP("file", "f", "", "Save scan result to a file")

	// Version flag to print the version of jacked
	root.Flags().BoolP("version", "v", false, "Print the version of jacked")

	// Debug flag to enable debug mode
	root.Flags().Bool("debug", false, "Enable debug mode (e.g. --debug)")

	// CI flag to enable CI mode
	// CI mode is a mode that is used to run jacked in a CI/CD pipeline
	root.Flags().BoolP("ci", "", false, "Enable CI mode [experimental] (e.g. --ci)")

	root.Flags().StringP("fail-criteria", "", "", fmt.Sprintf("Input a severity that will be found at or above given severity then return code will be 1 (%v)", ci.GetJoinedSeverities()))

	root.PersistentFlags().BoolP("help", "h", false, "")
	root.PersistentFlags().Lookup("help").Hidden = true
	root.SetHelpCommand(&cobra.Command{Hidden: true})
}

func Run() error {
	if err := root.Execute(); err != nil {
		return err
	}
	return nil
}
