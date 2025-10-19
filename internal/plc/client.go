package plc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/atscan/atscanner/internal/log"
)

type Client struct {
	baseURL     string
	httpClient  *http.Client
	rateLimiter *RateLimiter
}

func NewClient(baseURL string) *Client {
	// Rate limit: 90 requests per minute (leaving buffer below 100/min limit)
	rateLimiter := NewRateLimiter(90, time.Minute)

	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		rateLimiter: rateLimiter,
	}
}

func (c *Client) Close() {
	if c.rateLimiter != nil {
		c.rateLimiter.Stop()
	}
}

type ExportOptions struct {
	Count int
	After string // ISO 8601 datetime string
}

// Export fetches export data from PLC directory with rate limiting and retry
func (c *Client) Export(ctx context.Context, opts ExportOptions) ([]PLCOperation, error) {
	return c.exportWithRetry(ctx, opts, 5)
}

// exportWithRetry implements retry logic with exponential backoff for rate limits
func (c *Client) exportWithRetry(ctx context.Context, opts ExportOptions, maxRetries int) ([]PLCOperation, error) {
	var lastErr error
	backoff := 1 * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Wait for rate limiter token
		if err := c.rateLimiter.Wait(ctx); err != nil {
			return nil, err
		}

		operations, retryAfter, err := c.doExport(ctx, opts)

		if err == nil {
			return operations, nil
		}

		lastErr = err

		// Check if it's a rate limit error (429)
		if retryAfter > 0 {
			log.Info("⚠ Rate limited by PLC directory, waiting %v before retry %d/%d",
				retryAfter, attempt, maxRetries)

			select {
			case <-time.After(retryAfter):
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		// Other errors - exponential backoff
		if attempt < maxRetries {
			log.Verbose("Request failed (attempt %d/%d): %v, retrying in %v",
				attempt, maxRetries, err, backoff)

			select {
			case <-time.After(backoff):
				backoff *= 2 // Exponential backoff
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	return nil, fmt.Errorf("failed after %d attempts: %w", maxRetries, lastErr)
}

// doExport performs the actual HTTP request
func (c *Client) doExport(ctx context.Context, opts ExportOptions) ([]PLCOperation, time.Duration, error) {
	url := fmt.Sprintf("%s/export", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, 0, err
	}

	// Add query parameters
	q := req.URL.Query()
	if opts.Count > 0 {
		q.Add("count", fmt.Sprintf("%d", opts.Count))
	}
	if opts.After != "" {
		q.Add("after", opts.After)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle rate limiting (429)
	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := parseRetryAfter(resp)

		// Also check x-ratelimit headers for info
		if limit := resp.Header.Get("x-ratelimit-limit"); limit != "" {
			log.Verbose("Rate limit: %s", limit)
		}

		return nil, retryAfter, fmt.Errorf("rate limited (429)")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, 0, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var operations []PLCOperation

	// PLC export returns newline-delimited JSON
	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineCount := 0
	for scanner.Scan() {
		lineCount++
		line := scanner.Bytes()

		if len(line) == 0 {
			continue
		}

		var op PLCOperation
		if err := json.Unmarshal(line, &op); err != nil {
			log.Error("Warning: failed to parse operation on line %d: %v", lineCount, err)
			continue
		}

		// CRITICAL: Store the original raw JSON bytes
		op.rawJSON = make([]byte, len(line))
		copy(op.rawJSON, line)

		operations = append(operations, op)
	}

	if err := scanner.Err(); err != nil {
		return nil, 0, fmt.Errorf("error reading response: %w", err)
	}

	return operations, 0, nil

}

// parseRetryAfter parses the Retry-After header
func parseRetryAfter(resp *http.Response) time.Duration {
	retryAfter := resp.Header.Get("Retry-After")
	if retryAfter == "" {
		// Default to 5 minutes if no header
		return 5 * time.Minute
	}

	// Try parsing as seconds
	if seconds, err := strconv.Atoi(retryAfter); err == nil {
		return time.Duration(seconds) * time.Second
	}

	// Try parsing as HTTP date
	if t, err := http.ParseTime(retryAfter); err == nil {
		return time.Until(t)
	}

	// Default
	return 5 * time.Minute
}

// GetDID fetches a specific DID document from PLC
func (c *Client) GetDID(ctx context.Context, did string) (*DIDDocument, error) {
	// Wait for rate limiter
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}

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

	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := parseRetryAfter(resp)
		return nil, fmt.Errorf("rate limited, retry after %v", retryAfter)
	}

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
