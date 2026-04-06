package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
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
	// TODO: implement config file loading (e.g. using github.com/spf13/viper)
	// cfgFile is currently unused.
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file (default is $HOME/.transparenz.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}
