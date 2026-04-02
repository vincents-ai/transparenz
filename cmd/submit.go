package cmd

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	submitFile        string
	submitURL         string
	submitToken       string
	submitTimeout     int
	submitInsecure    bool
	submitContentType string
)

// detectContentType inspects the SBOM bytes and returns the appropriate
// IANA media type for CycloneDX JSON, SPDX JSON, or generic JSON.
func detectContentType(data []byte) string {
	s := string(data)
	if strings.Contains(s, `"bomFormat"`) && strings.Contains(s, `"CycloneDX"`) {
		return "application/vnd.cyclonedx+json"
	}
	if strings.Contains(s, `"spdxVersion"`) {
		return "application/spdx+json"
	}
	return "application/json"
}

// postSBOM sends data to url with the given bearer token and content type.
// It honours the insecure flag and uses the provided timeout.
// Returns an error for non-2xx responses.
func postSBOM(url, token, contentType string, data []byte, timeoutSecs int, insecure bool) error {
	transport := &http.Transport{}
	if insecure {
		fmt.Fprintln(os.Stderr, "WARNING: TLS verification disabled")
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // user opted in
	}

	client := &http.Client{
		Timeout:   time.Duration(timeoutSecs) * time.Second,
		Transport: transport,
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to build request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Printf("Successfully submitted SBOM (HTTP %d)\n", resp.StatusCode)
		if len(body) > 0 {
			fmt.Println(string(body))
		}
		return nil
	}

	errMsg := fmt.Sprintf("server returned HTTP %d", resp.StatusCode)
	if len(body) > 0 {
		errMsg += ": " + string(body)
	}
	return fmt.Errorf("%s", errMsg)
}

var submitCmd = &cobra.Command{
	Use:   "submit",
	Short: "Submit an SBOM file to a remote server with bearer token authentication",
	Long: `Submit a Software Bill of Materials (SBOM) to a configured server endpoint.

Reads the SBOM from --file or from stdin if --file is not provided.
Automatically detects the Content-Type from the SBOM content (CycloneDX / SPDX / generic JSON)
unless overridden with --content-type.

The server URL and bearer token may be provided via flags or environment variables:
  TRANSPARENZ_SERVER_URL  — remote endpoint URL
  TRANSPARENZ_TOKEN       — bearer token for Authorization header

Example usage:
  transparenz submit --file sbom.json --url https://sbom.example.com/api/sbom --token my-token
  cat sbom.json | transparenz submit --url https://sbom.example.com/api/sbom --token my-token`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Resolve URL from flag or env
		if submitURL == "" {
			submitURL = os.Getenv("TRANSPARENZ_SERVER_URL")
		}
		if submitURL == "" {
			return fmt.Errorf("server URL is required (use --url or TRANSPARENZ_SERVER_URL)")
		}

		// Resolve token from flag or env
		if submitToken == "" {
			submitToken = os.Getenv("TRANSPARENZ_TOKEN")
		}
		if submitToken == "" {
			return fmt.Errorf("bearer token is required (use --token or TRANSPARENZ_TOKEN)")
		}

		// Read SBOM bytes
		var data []byte
		var err error
		if submitFile != "" {
			data, err = os.ReadFile(submitFile)
			if err != nil {
				return fmt.Errorf("failed to read file %q: %w", submitFile, err)
			}
		} else {
			data, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read stdin: %w", err)
			}
		}

		// Determine content type
		ct := submitContentType
		if ct == "" {
			ct = detectContentType(data)
		}

		return postSBOM(submitURL, submitToken, ct, data, submitTimeout, submitInsecure)
	},
}

func init() {
	rootCmd.AddCommand(submitCmd)

	submitCmd.Flags().StringVarP(&submitFile, "file", "f", "", "Path to SBOM file to submit (reads stdin if not set)")
	submitCmd.Flags().StringVar(&submitURL, "url", "", "Server endpoint URL (or TRANSPARENZ_SERVER_URL env var)")
	submitCmd.Flags().StringVar(&submitToken, "token", "", "Bearer authentication token (or TRANSPARENZ_TOKEN env var)")
	submitCmd.Flags().IntVar(&submitTimeout, "timeout", 30, "HTTP timeout in seconds")
	submitCmd.Flags().BoolVar(&submitInsecure, "insecure", false, "Skip TLS certificate verification (prints a warning to stderr)")
	submitCmd.Flags().StringVar(&submitContentType, "content-type", "", "Override Content-Type header (default: auto-detect from SBOM content)")
}
