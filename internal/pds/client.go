package pds

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
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
	DID    string  `json:"did"`
	Head   string  `json:"head,omitempty"`
	Rev    string  `json:"rev,omitempty"`
	Active *bool   `json:"active,omitempty"`
	Status *string `json:"status,omitempty"`
}

// ListRepos fetches all repositories from a PDS with pagination
func (c *Client) ListRepos(ctx context.Context, endpoint string) ([]Repo, error) {
	var allRepos []Repo
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

		// Collect repos
		allRepos = append(allRepos, result.Repos...)

		// Check if there are more pages
		if result.Cursor == nil || *result.Cursor == "" {
			break
		}
		cursor = result.Cursor
	}

	return allRepos, nil
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
// Returns: available, responseTime, version, usedIP, error
func (c *Client) CheckHealth(ctx context.Context, endpoint string) (bool, time.Duration, string, string, error) {
	startTime := time.Now()

	url := fmt.Sprintf("%s/xrpc/_health", endpoint)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, 0, "", "", err
	}

	// Create a custom dialer to track which IP was actually used
	var usedIP string
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext(ctx, network, addr)

			if err == nil && conn != nil {
				if remoteAddr := conn.RemoteAddr(); remoteAddr != nil {
					// Extract IP from "ip:port" format
					if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
						usedIP = tcpAddr.IP.String()
					}
				}
			}

			return conn, err
		},
	}

	// Create a client with our custom transport
	client := &http.Client{
		Timeout:   c.httpClient.Timeout,
		Transport: transport,
	}

	resp, err := client.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		return false, duration, "", usedIP, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, duration, "", usedIP, fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	// Decode the JSON response and check for "version"
	var healthResponse struct {
		Version string `json:"version"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&healthResponse); err != nil {
		return false, duration, "", usedIP, fmt.Errorf("failed to decode health JSON: %w", err)
	}

	if healthResponse.Version == "" {
		return false, duration, "", usedIP, fmt.Errorf("health JSON response missing 'version' field")
	}

	// All checks passed
	return true, duration, healthResponse.Version, usedIP, nil
}
