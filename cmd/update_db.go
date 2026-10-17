package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sudo-check/pkg/gtfobins"
	"time"

	"github.com/spf13/cobra"
)

const (
	gtfoBinsURL     = "https://gtfobins.org/api.json"
	maxDownloadMB   = 50
	downloadTimeout = 30 * time.Second
)

var (
	dbOutputPath        string
	gtfoBinsDownloadURL = gtfoBinsURL
)

var updateDbCmd = &cobra.Command{
	Use:   "update-db",
	Short: "Fetch and update the GTFObins database",
	Long:  `Downloads the latest database JSON from gtfobins.org/api.json and saves it to a file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Fetching latest GTFObins database from %s...\n", gtfoBinsDownloadURL)

		client := &http.Client{Timeout: downloadTimeout}
		resp, err := client.Get(gtfoBinsDownloadURL)
		if err != nil {
			return fmt.Errorf("failed to fetch database: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("server returned non-OK status: %s", resp.Status)
		}

		// Read response with size limit to prevent disk exhaustion
		limitedReader := io.LimitReader(resp.Body, maxDownloadMB*1024*1024)
		data, err := io.ReadAll(limitedReader)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}

		// Validate the downloaded data is a valid GTFObins database
		var db gtfobins.Database
		if err := json.Unmarshal(data, &db); err != nil {
			return fmt.Errorf("downloaded data is not valid GTFObins JSON: %w", err)
		}
		if len(db.Executables) == 0 {
			return fmt.Errorf("downloaded database contains no executables — aborting to prevent data loss")
		}

		// Write validated data to file
		if err := os.WriteFile(dbOutputPath, data, 0644); err != nil {
			return fmt.Errorf("failed to save database: %w", err)
		}

		fmt.Printf("GTFObins database updated successfully (%d executables) and saved to '%s'!\n", len(db.Executables), dbOutputPath)
		return nil
	},
}

func init() {
	updateDbCmd.Flags().StringVarP(&dbOutputPath, "output", "p", "gtfobins.json", "Output path for the updated gtfobins.json")
	rootCmd.AddCommand(updateDbCmd)
}
