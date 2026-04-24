// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// CLICommand defines the interface for CLI commands.
// This allows for better testing and dependency injection.
type CLICommand interface {
	// Name returns the command name (use string)
	Name() string

	// Description returns the short description
	Description() string

	// Execute runs the command with the given arguments
	Execute(ctx context.Context, args []string) error

	// CobraCommand returns the underlying cobra.Command for registration
	CobraCommand() *cobra.Command
}

// baseCommand provides common functionality for CLI commands
type baseCommand struct {
	name        string
	description string
}

// Name returns the command name
func (c *baseCommand) Name() string {
	return c.name
}

// Description returns the command description
func (c *baseCommand) Description() string {
	return c.description
}

// GenerateCommand implements CLICommand for SBOM generation
type GenerateCommand struct {
	baseCommand
	format          string
	output          string
	save            bool
	bsiCompliant    bool
	manufacturer    string
	manufacturerURL string
	binary          string
	scope           string
	noFetch         bool
	submit          bool
	serverURL       string
	token           string
	insecure        bool
	timeout         int
}

// NewGenerateCommand creates a new GenerateCommand
func NewGenerateCommand() *GenerateCommand {
	return &GenerateCommand{
		baseCommand: baseCommand{
			name:        "generate",
			description: "Generate SBOM for a source directory or container image",
		},
	}
}

// Execute runs the generate command
func (c *GenerateCommand) Execute(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("source path is required")
	}
	// Implementation will delegate to existing generate logic
	fmt.Fprintln(os.Stderr, "GenerateCommand.Execute not yet fully implemented")
	return nil
}

// CobraCommand returns the cobra.Command for registration
func (c *GenerateCommand) CobraCommand() *cobra.Command {
	// Return the existing generateCmd for now
	return generateCmd
}

// BSICommand implements CLICommand for BSI enrichment
type BSICommand struct {
	baseCommand
	output string
	scope  string
}

// NewBSICommand creates a new BSICommand
func NewBSICommand() *BSICommand {
	return &BSICommand{
		baseCommand: baseCommand{
			name:        "bsi",
			description: "Enrich SBOM with BSI TR-03183-2 compliance data",
		},
	}
}

// Execute runs the BSI command
func (c *BSICommand) Execute(ctx context.Context, args []string) error {
	fmt.Fprintln(os.Stderr, "BSICommand.Execute not yet fully implemented")
	return nil
}

// CobraCommand returns the cobra.Command for registration
func (c *BSICommand) CobraCommand() *cobra.Command {
	return bsiCmd
}

// ValidateCommand implements CLICommand for SBOM validation
type ValidateCommand struct {
	baseCommand
	enrich bool
}

// NewValidateCommand creates a new ValidateCommand
func NewValidateCommand() *ValidateCommand {
	return &ValidateCommand{
		baseCommand: baseCommand{
			name:        "validate",
			description: "Validate SBOM against BSI TR-03183-2 requirements",
		},
	}
}

// Execute runs the validate command
func (c *ValidateCommand) Execute(ctx context.Context, args []string) error {
	fmt.Fprintln(os.Stderr, "ValidateCommand.Execute not yet fully implemented")
	return nil
}

// CobraCommand returns the cobra.Command for registration
func (c *ValidateCommand) CobraCommand() *cobra.Command {
	return validateCmd
}

// Commands returns a list of all CLI commands
func Commands() []CLICommand {
	return []CLICommand{
		NewGenerateCommand(),
		NewBSICommand(),
		NewValidateCommand(),
	}
}
