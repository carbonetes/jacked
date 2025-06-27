package command

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/carbonetes/jacked/pkg/config"
	"github.com/carbonetes/jacked/pkg/types"
	"github.com/spf13/cobra"
)

// TestRootCommandFlags tests the root command flag handling
func TestRootCommandFlags(t *testing.T) {
	// Create a test command instance
	cmd := &cobra.Command{
		Use: "test",
		Run: func(cmd *cobra.Command, args []string) {},
	}

	// Add the flags similar to the root command
	cmd.Flags().String("performance", "balanced", "Set performance optimization level")
	cmd.Flags().Bool("non-interactive", false, "Disable interactive table display")
	cmd.Flags().StringP("config", "c", "", "Path to configuration file")

	tests := []struct {
		name     string
		args     []string
		expected map[string]string
	}{
		{
			name: "default_flags",
			args: []string{},
			expected: map[string]string{
				"performance":     "balanced",
				"non-interactive": "false",
				"config":          "",
			},
		},
		{
			name: "performance_basic",
			args: []string{"--performance=basic"},
			expected: map[string]string{
				"performance": "basic",
			},
		},
		{
			name: "non_interactive_enabled",
			args: []string{"--non-interactive"},
			expected: map[string]string{
				"non-interactive": "true",
			},
		},
		{
			name: "custom_config_path",
			args: []string{"--config=/custom/path/config.yaml"},
			expected: map[string]string{
				"config": "/custom/path/config.yaml",
			},
		},
		{
			name: "combined_flags",
			args: []string{"--performance=aggressive", "--non-interactive", "--config=test.yaml"},
			expected: map[string]string{
				"performance":     "aggressive",
				"non-interactive": "true",
				"config":          "test.yaml",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			for flagName, expectedValue := range tt.expected {
				actualValue, err := cmd.Flags().GetString(flagName)
				if flagName == "non-interactive" {
					actualBool, err := cmd.Flags().GetBool(flagName)
					if err != nil {
						t.Fatalf("Failed to get bool flag %s: %v", flagName, err)
					}
					actualValue = "false"
					if actualBool {
						actualValue = "true"
					}
				} else {
					if err != nil {
						t.Fatalf("Failed to get flag %s: %v", flagName, err)
					}
				}

				if actualValue != expectedValue {
					t.Errorf("Flag %s: expected %s, got %s", flagName, expectedValue, actualValue)
				}
			}
		})
	}
}

// TestPerformanceLevelValidation tests validation of performance levels
func TestPerformanceLevelValidation(t *testing.T) {
	tests := []struct {
		level       string
		expectValid bool
	}{
		{"basic", true},
		{"balanced", true},
		{"aggressive", true},
		{"maximum", true},
		{"BASIC", true},    // Case insensitive
		{"Balanced", true}, // Case insensitive
		{"invalid", false},
		{"", false},
		{"random", false},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			_, err := types.ParseOptimizationLevel(tt.level)

			if tt.expectValid && err != nil {
				t.Errorf("Expected level %s to be valid, got error: %v", tt.level, err)
			} else if !tt.expectValid && err == nil {
				t.Errorf("Expected level %s to be invalid, but got no error", tt.level)
			}
		})
	}
}

// TestConfigPathHandling tests configuration path handling
func TestConfigPathHandling(t *testing.T) {
	// Save original config path
	originalPath := config.GetConfigPath()
	defer config.SetConfigPath(originalPath)

	// Create a temporary config file
	tempDir := t.TempDir()
	testConfigPath := filepath.Join(tempDir, "test-config.yaml")

	configContent := `version: "1.0"
performance:
  max_concurrent_scanners: 16
  enable_caching: true
`

	err := os.WriteFile(testConfigPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Test setting and loading custom config path
	config.SetConfigPath(testConfigPath)
	err = config.ReloadConfig()
	if err != nil {
		t.Fatalf("Failed to reload config: %v", err)
	}

	// Verify the configuration was loaded
	if config.Config.Performance.MaxConcurrentScanners != 16 {
		t.Errorf("Expected MaxConcurrentScanners to be 16, got %d", config.Config.Performance.MaxConcurrentScanners)
	}

	if !config.Config.Performance.EnableCaching {
		t.Error("Expected caching to be enabled")
	}
}

// TestNonInteractiveMode tests non-interactive mode functionality
func TestNonInteractiveMode(t *testing.T) {
	// This test ensures that the non-interactive flag can be set and retrieved
	tests := []struct {
		name           string
		setFlag        bool
		expectedResult bool
	}{
		{
			name:           "non_interactive_enabled",
			setFlag:        true,
			expectedResult: true,
		},
		{
			name:           "non_interactive_disabled",
			setFlag:        false,
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{
				Use: "test",
				Run: func(cmd *cobra.Command, args []string) {},
			}
			cmd.Flags().Bool("non-interactive", false, "Disable interactive mode")

			if tt.setFlag {
				cmd.SetArgs([]string{"--non-interactive"})
			} else {
				cmd.SetArgs([]string{})
			}

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			result, err := cmd.Flags().GetBool("non-interactive")
			if err != nil {
				t.Fatalf("Failed to get non-interactive flag: %v", err)
			}

			if result != tt.expectedResult {
				t.Errorf("Expected non-interactive to be %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

// TestOptimizeCommandFlags tests the optimize command flags
func TestOptimizeCommandFlags(t *testing.T) {
	// Create a test command similar to optimizeCmd
	cmd := &cobra.Command{
		Use: "analyze-optimized",
		Run: func(cmd *cobra.Command, args []string) {},
	}

	// Add flags similar to optimizeCmd
	cmd.Flags().String("optimization", "balanced", "Optimization level")
	cmd.Flags().Bool("enable-metrics", true, "Enable performance metrics")
	cmd.Flags().Bool("show-metrics", false, "Show performance metrics")
	cmd.Flags().Bool("enable-profiling", false, "Enable profiling")
	cmd.Flags().Int("max-concurrency", 0, "Maximum concurrency")

	tests := []struct {
		name     string
		args     []string
		expected map[string]interface{}
	}{
		{
			name: "default_optimization",
			args: []string{},
			expected: map[string]interface{}{
				"optimization":     "balanced",
				"enable-metrics":   true,
				"show-metrics":     false,
				"enable-profiling": false,
				"max-concurrency":  0,
			},
		},
		{
			name: "aggressive_optimization",
			args: []string{"--optimization=aggressive", "--show-metrics", "--max-concurrency=16"},
			expected: map[string]interface{}{
				"optimization":    "aggressive",
				"show-metrics":    true,
				"max-concurrency": 16,
			},
		},
		{
			name: "profiling_enabled",
			args: []string{"--enable-profiling", "--optimization=maximum"},
			expected: map[string]interface{}{
				"enable-profiling": true,
				"optimization":     "maximum",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Command execution failed: %v", err)
			}

			for flagName, expectedValue := range tt.expected {
				switch v := expectedValue.(type) {
				case string:
					actualValue, err := cmd.Flags().GetString(flagName)
					if err != nil {
						t.Fatalf("Failed to get string flag %s: %v", flagName, err)
					}
					if actualValue != v {
						t.Errorf("Flag %s: expected %s, got %s", flagName, v, actualValue)
					}
				case bool:
					actualValue, err := cmd.Flags().GetBool(flagName)
					if err != nil {
						t.Fatalf("Failed to get bool flag %s: %v", flagName, err)
					}
					if actualValue != v {
						t.Errorf("Flag %s: expected %v, got %v", flagName, v, actualValue)
					}
				case int:
					actualValue, err := cmd.Flags().GetInt(flagName)
					if err != nil {
						t.Fatalf("Failed to get int flag %s: %v", flagName, err)
					}
					if actualValue != v {
						t.Errorf("Flag %s: expected %d, got %d", flagName, v, actualValue)
					}
				}
			}
		})
	}
}

// TestCommandHelp tests that help text is properly generated
func TestCommandHelp(t *testing.T) {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test command",
		Long:  "This is a test command for unit testing",
		Run:   func(cmd *cobra.Command, args []string) {},
	}

	cmd.Flags().String("performance", "balanced", "Performance optimization level")
	cmd.Flags().Bool("non-interactive", false, "Non-interactive mode")

	// Capture help output
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--help"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Help command failed: %v", err)
	}

	helpOutput := buf.String()

	// Check that help contains expected flags
	expectedFlags := []string{"--performance", "--non-interactive", "--help"}
	for _, flag := range expectedFlags {
		if !strings.Contains(helpOutput, flag) {
			t.Errorf("Help output should contain flag %s", flag)
		}
	}

	// Check that help contains command description (either short or long)
	if !strings.Contains(helpOutput, "test command") {
		t.Errorf("Help output should contain command description\nActual output:\n%s", helpOutput)
	}
}

// TestConfigurationIntegration tests integration between CLI flags and configuration
func TestConfigurationIntegration(t *testing.T) {
	// Save original config
	originalConfig := config.Config
	defer func() { config.Config = originalConfig }()

	// Test that different optimization levels produce different configurations
	levels := []types.OptimizationLevel{
		types.OptimizationBasic,
		types.OptimizationBalanced,
		types.OptimizationAggressive,
		types.OptimizationMaximum,
	}

	for _, level := range levels {
		t.Run(level.String(), func(t *testing.T) {
			cfg := config.GetConfigForOptimizationLevel(level)

			// Verify that each level has different characteristics
			switch level {
			case types.OptimizationBasic:
				// Basic should have conservative settings
				if cfg.MaxConcurrentScanners > 4 {
					t.Errorf("Basic optimization should have low concurrency, got %d", cfg.MaxConcurrentScanners)
				}
			case types.OptimizationMaximum:
				// Maximum should enable experimental features
				if !cfg.EnableExperimentalFeatures {
					t.Error("Maximum optimization should enable experimental features")
				}
			}

			// All levels should have positive values for basic settings
			if cfg.MaxConcurrentScanners <= 0 {
				t.Errorf("MaxConcurrentScanners should be positive, got %d", cfg.MaxConcurrentScanners)
			}

			if cfg.ScanTimeout <= 0 {
				t.Errorf("ScanTimeout should be positive, got %v", cfg.ScanTimeout)
			}
		})
	}
}

// BenchmarkCommandExecution benchmarks command execution performance
func BenchmarkCommandExecution(b *testing.B) {
	cmd := &cobra.Command{
		Use: "benchmark",
		Run: func(cmd *cobra.Command, args []string) {
			// Simulate configuration loading
			_ = config.GetConfigForOptimizationLevel(types.OptimizationBalanced)
		},
	}

	cmd.Flags().String("performance", "balanced", "Performance level")
	cmd.Flags().Bool("non-interactive", false, "Non-interactive mode")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd.SetArgs([]string{"--performance=balanced", "--non-interactive"})
		_ = cmd.Execute()
	}
}
