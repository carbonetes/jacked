package command

import (
	"os"
	"strings"

	diggity "github.com/carbonetes/diggity/pkg/types"
	"github.com/carbonetes/jacked/pkg/types"
	"github.com/spf13/cobra"
)

// legacyOptimizeCmd represents the legacy optimize command for backward compatibility
var legacyOptimizeCmd = &cobra.Command{
	Use:   "analyze-legacy",
	Short: "Run legacy vulnerability scanning (deprecated)",
	Long: `Run vulnerability scanning using the legacy analyzer.

This command is provided for backward compatibility. The default 'jacked' command 
now uses optimized scanning by default.

Examples:
  jacked analyze-legacy myimage:tag
  jacked analyze-legacy --config /path/to/config myimage:tag`,
	Args: cobra.MinimumNArgs(1),
	Run:  runLegacyAnalysis,
}

func init() {
	root.AddCommand(legacyOptimizeCmd)

	// Legacy command doesn't need all the optimization flags
	// It just uses the existing configuration system
}

func runLegacyAnalysis(cmd *cobra.Command, args []string) {
	target := args[0]

	// Set up parameters using the legacy system
	params := setupLegacyParameters(target)

	// Run the legacy analysis using the existing analyze function from analyze.go
	analyze(params)
}

func setupLegacyParameters(target string) types.Parameters {
	// Create basic parameter structure for legacy analysis
	params := types.Parameters{
		Format: types.Table, // Default to table output
		Diggity: diggity.Parameters{
			OutputFormat: diggity.JSON,
		},
	}

	// Configure diggity parameters based on target
	if isDockerImage(target) {
		params.Diggity.ScanType = 1 // Image
		params.Diggity.Input = target
	} else if isDirectory(target) {
		params.Diggity.ScanType = 3 // Filesystem
		params.Diggity.Input = target
	} else if isTarball(target) {
		params.Diggity.ScanType = 2 // Tarball
		params.Diggity.Input = target
	}

	return params
}

// Helper functions for target type detection
func isDockerImage(target string) bool {
	// Simple heuristic - could be improved
	return !isDirectory(target) && !isTarball(target)
}

func isDirectory(target string) bool {
	if stat, err := os.Stat(target); err == nil {
		return stat.IsDir()
	}
	return false
}

func isTarball(target string) bool {
	// Check for common tarball extensions
	return strings.HasSuffix(target, ".tar") ||
		strings.HasSuffix(target, ".tar.gz") ||
		strings.HasSuffix(target, ".tgz") ||
		strings.HasSuffix(target, ".tar.bz2")
}
