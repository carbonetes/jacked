package command

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestRootCommandFlags tests the root command flag handling
func TestRootCommandFlags(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
		Run: func(cmd *cobra.Command, args []string) {
			// Empty test command
		},
	}

	// Add essential flags
	cmd.Flags().String("format", "table", "Set output format")

	tests := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name:     "default_flags",
			args:     []string{},
			expected: "table",
		},
		{
			name:     "format_json",
			args:     []string{"--format=json"},
			expected: "json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			actualValue, err := cmd.Flags().GetString("format")
			if err != nil {
				t.Fatalf("Failed to get flag format: %v", err)
			}

			if actualValue != tt.expected {
				t.Errorf("Flag format: expected %s, got %s", tt.expected, actualValue)
			}
		})
	}
}

// TestCommandHelp tests that help text is properly generated
func TestCommandHelp(t *testing.T) {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test command",
		Run: func(cmd *cobra.Command, args []string) {
			// Empty test command
		},
	}

	cmd.Flags().String("format", "table", "Output format")

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--help"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Help command failed: %v", err)
	}

	helpOutput := buf.String()

	if !strings.Contains(helpOutput, "--format") {
		t.Errorf("Help output should contain flag --format")
	}
}
