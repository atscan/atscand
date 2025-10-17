package plc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

type ExportOptions struct {
	Count int
	After string // ISO 8601 datetime string like "2023-04-26T06:19:25.508Z"
}

// Export fetches export data from PLC directory with pagination
func (c *Client) Export(ctx context.Context, opts ExportOptions) ([]PLCOperation, error) {
	url := fmt.Sprintf("%s/export", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Add query parameters
	q := req.URL.Query()
	if opts.Count > 0 {
		q.Add("count", fmt.Sprintf("%d", opts.Count))
	}
	// Only add 'after' if it's a valid datetime string
	if opts.After != "" {
		q.Add("after", opts.After)
	}
	req.URL.RawQuery = q.Encode()

	fmt.Printf("Requesting: %s\n", req.URL.String())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var operations []PLCOperation

	// PLC export returns newline-delimited JSON
	scanner := bufio.NewScanner(resp.Body)
	// Increase buffer size for large lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineCount := 0
	for scanner.Scan() {
		lineCount++
		line := scanner.Bytes()

		// Skip empty lines
		if len(line) == 0 {
			continue
		}

		var op PLCOperation
		if err := json.Unmarshal(line, &op); err != nil {
			fmt.Printf("Warning: failed to parse operation on line %d: %v\n", lineCount, err)
			continue
		}
		operations = append(operations, op)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	return operations, nil
}

// GetDID fetches a specific DID document from PLC
func (c *Client) GetDID(ctx context.Context, did string) (*DIDDocument, error) {
	url := fmt.Sprintf("%s/%s", c.baseURL, did)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var doc DIDDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}

	return &doc, nil
}
