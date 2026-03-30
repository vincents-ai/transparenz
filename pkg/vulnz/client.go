package vulnz

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Config struct {
	ProjectID  string
	APIURL     string
	Token      string
	OutputPath string
}

type Client struct {
	config Config
	client *http.Client
}

type Metadata struct {
	Version    string    `json:"version"`
	LastUpdate time.Time `json:"last_update"`
	Providers  []string  `json:"providers"`
	VulnCount  int       `json:"vuln_count"`
}

type Vulnerability struct {
	ID               int64   `json:"id"`
	Provider         string  `json:"provider"`
	VulnID           string  `json:"vuln_id"`
	CVE              string  `json:"cve,omitempty"`
	EuvdID           string  `json:"euvd_id,omitempty"`
	Title            string  `json:"title,omitempty"`
	Description      string  `json:"description,omitempty"`
	Severity         string  `json:"severity,omitempty"`
	CvssScore        float64 `json:"cvss_score,omitempty"`
	CvssVector       string  `json:"cvss_vector,omitempty"`
	PublishedDate    string  `json:"published_date,omitempty"`
	ModifiedDate     string  `json:"modified_date,omitempty"`
	IsKnownExploited bool    `json:"is_known_exploited"`
	RawData          string  `json:"raw_data,omitempty"`
}

func NewClient(config Config) *Client {
	return &Client{
		config: config,
		client: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

func (c *Client) DownloadURL() string {
	return fmt.Sprintf("%s/api/v4/projects/%s/packages/generic/vulnz/latest/vulnerabilities.db",
		c.config.APIURL, c.config.ProjectID)
}

func (c *Client) Download(ctx context.Context) (*os.File, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.DownloadURL(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("PRIVATE-TOKEN", c.config.Token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp("", "vulnz-*.db")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("failed to write file: %w", err)
	}

	return tmpFile, nil
}

func (c *Client) DownloadAndExtract(ctx context.Context, targetDir string) (*Metadata, error) {
	file, err := c.Download(ctx)
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	defer file.Close()

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create target dir: %w", err)
	}

	dbPath := filepath.Join(targetDir, "vulnerabilities.db")
	if err := os.Rename(file.Name(), dbPath); err != nil {
		return nil, fmt.Errorf("failed to move file: %w", err)
	}

	return c.GetMetadata(dbPath)
}

func (c *Client) GetMetadata(dbPath string) (*Metadata, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	meta := &Metadata{}

	row := db.QueryRow(`SELECT value FROM metadata WHERE key = 'last_updated'`)
	var lastUpdate string
	if err := row.Scan(&lastUpdate); err == nil && lastUpdate != "" {
		meta.LastUpdate, _ = time.Parse(time.RFC3339, lastUpdate)
	}

	row = db.QueryRow(`SELECT value FROM metadata WHERE key = 'providers'`)
	var providersJSON string
	if err := row.Scan(&providersJSON); err == nil && providersJSON != "" {
		json.Unmarshal([]byte(providersJSON), &meta.Providers)
	}

	row = db.QueryRow(`SELECT value FROM metadata WHERE key = 'version'`)
	row.Scan(&meta.Version)

	row = db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities`)
	if err := row.Scan(&meta.VulnCount); err != nil {
		return nil, fmt.Errorf("failed to count vulnerabilities: %w", err)
	}

	return meta, nil
}

func (c *Client) Query(dbPath string, query string) ([]map[string]interface{}, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns, _ := rows.Columns()
	var results []map[string]interface{}

	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}
		results = append(results, row)
	}

	return results, nil
}

func ExportToSQLite(srcPath, dstPath string) error {
	src, err := sql.Open("sqlite3", srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	srcDB, err := sql.Open("sqlite3", "?cache=shared&mode=ro")
	if err != nil {
		return err
	}

	Pragma(dstPath)

	dst, err := sql.Open("sqlite3", "file:"+dstPath+"?cache=shared")
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = dst.Exec("ATTACH DATABASE ? AS src", srcPath)
	if err != nil {
		return err
	}

	_, err = dst.Exec(`
		CREATE TABLE IF NOT EXISTS vulnerabilities (
			id INTEGER PRIMARY KEY,
			provider TEXT,
			vuln_id TEXT,
			cve TEXT,
			euvd_id TEXT,
			title TEXT,
			description TEXT,
			severity TEXT,
			cvss_score REAL,
			cvss_vector TEXT,
			published_date TEXT,
			modified_date TEXT,
			is_known_exploited INTEGER,
			raw_data TEXT,
			created_at TEXT,
			updated_at TEXT
		)
	`)
	if err != nil {
		return err
	}

	_, err = dst.Exec(`
		INSERT OR IGNORE INTO vulnerabilities 
		SELECT * FROM src.vulnerabilities
	`)
	if err != nil {
		return err
	}

	_ = srcDB

	return nil
}

func Pragma(path string) error {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return err
	}
	defer db.Close()

	pragma := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=-64000",
		"PRAGMA temp_store=MEMORY",
	}

	for _, p := range pragma {
		if _, err := db.Exec(p); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) Verify(dbPath string) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM vulnerabilities").Scan(&count)
	if err != nil {
		return fmt.Errorf("invalid database: %w", err)
	}

	if count == 0 {
		return fmt.Errorf("database is empty")
	}

	return nil
}

func DownloadFromURL(url, token, outputPath string) error {
	client := &http.Client{Timeout: 5 * time.Minute}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func IsSQLite(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	header := make([]byte, 16)
	if _, err := f.Read(header); err != nil {
		return false
	}

	return bytes.HasPrefix(header, []byte("SQLite format 3"))
}

func ExtractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	os.MkdirAll(destDir, 0755)

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}

		outPath := filepath.Join(destDir, f.Name)
		out, err := os.Create(outPath)
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			out.Close()
			return err
		}

		_, err = io.Copy(out, rc)
		out.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}

	return nil
}
