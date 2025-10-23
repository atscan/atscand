package pds

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Client struct {
	httpClient *http.Client
}

func NewClient(timeout time.Duration) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// ListReposResponse represents the response from com.atproto.sync.listRepos
type ListReposResponse struct {
	Repos  []Repo  `json:"repos"`
	Cursor *string `json:"cursor,omitempty"`
}

// Repo represents a repository in the list
type Repo struct {
	DID  string `json:"did"`
	Head string `json:"head,omitempty"`
	Rev  string `json:"rev,omitempty"`
}

// ListRepos fetches all repositories from a PDS with pagination
func (c *Client) ListRepos(ctx context.Context, endpoint string) ([]string, error) {
	var allDIDs []string
	var cursor *string

	for {
		// Build URL
		url := fmt.Sprintf("%s/xrpc/com.atproto.sync.listRepos?limit=1000", endpoint)
		if cursor != nil {
			url += fmt.Sprintf("&cursor=%s", *cursor)
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}

		var result ListReposResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()

		// Collect DIDs
		for _, repo := range result.Repos {
			allDIDs = append(allDIDs, repo.DID)
		}

		// Check if there are more pages
		if result.Cursor == nil || *result.Cursor == "" {
			break
		}
		cursor = result.Cursor
	}

	return allDIDs, nil
}

// DescribeServer fetches com.atproto.server.describeServer
func (c *Client) DescribeServer(ctx context.Context, endpoint string) (*ServerDescription, error) {
	url := fmt.Sprintf("%s/xrpc/com.atproto.server.describeServer", endpoint)

	//fmt.Println(url)

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
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var desc ServerDescription
	if err := json.NewDecoder(resp.Body).Decode(&desc); err != nil {
		return nil, err
	}

	return &desc, nil
}

// CheckHealth performs a basic health check, ensuring the endpoint returns JSON with a "version"
func (c *Client) CheckHealth(ctx context.Context, endpoint string) (bool, time.Duration, string, error) {
	startTime := time.Now()

	url := fmt.Sprintf("%s/xrpc/_health", endpoint)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, 0, "", err
	}

	resp, err := c.httpClient.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		return false, duration, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, duration, "", fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	// Decode the JSON response and check for "version"
	var healthResponse struct {
		Version string `json:"version"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&healthResponse); err != nil {
		return false, duration, "", fmt.Errorf("failed to decode health JSON: %w", err)
	}

	if healthResponse.Version == "" {
		return false, duration, "", fmt.Errorf("health JSON response missing 'version' field")
	}

	// All checks passed
	return true, duration, healthResponse.Version, nil
}
