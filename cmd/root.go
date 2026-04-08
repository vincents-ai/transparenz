package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "transparenz",
	Short: "BSI TR-03183 compliant SBOM generator for Deutschland-Stack",
	Long: `Transparenz generates Software Bill of Materials (SBOM) compliant with 
BSI TR-03183-2 standard, with cryptographic hash enrichment and license detection
using native Syft libraries.

This Go-native implementation eliminates subprocess dependencies and provides
a single static binary for deployment in government and enterprise environments.`,
	Version: "0.1.0",
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file (default is $HOME/.transparenz.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}

// initConfig reads the configuration file and environment variables.
// If --config is provided, that file is used; otherwise the default
// $HOME/.transparenz.yaml is loaded when present.
// Environment variables prefixed with TRANSPARENZ_ override all file values.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not determine home directory:", err)
		} else {
			viper.AddConfigPath(home)
		}
		viper.AddConfigPath(".")
		viper.SetConfigName(".transparenz")
		viper.SetConfigType("yaml")
	}

	viper.SetEnvPrefix("TRANSPARENZ")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		// Config file not found is not an error — it's optional.
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Fprintln(os.Stderr, "warning: could not read config file:", err)
		}
	}
}
