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

// DescribeServer fetches com.atproto.server.describeServer
func (c *Client) DescribeServer(ctx context.Context, endpoint string) (*ServerDescription, error) {
	url := fmt.Sprintf("%s/xrpc/com.atproto.server.describeServer", endpoint)

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

// CheckHealth performs a basic health check
func (c *Client) CheckHealth(ctx context.Context, endpoint string) (bool, time.Duration, error) {
	startTime := time.Now()

	url := fmt.Sprintf("%s/xrpc/_health", endpoint)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, 0, err
	}

	resp, err := c.httpClient.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		return false, duration, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, duration, nil
}
