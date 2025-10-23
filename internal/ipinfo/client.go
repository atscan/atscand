package ipinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type Client struct {
	httpClient      *http.Client
	baseURL         string
	mu              sync.RWMutex
	backoffUntil    time.Time
	backoffDuration time.Duration
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		baseURL:         "https://api.ipapi.is",
		backoffDuration: 5 * time.Minute,
	}
}

// IsInBackoff checks if we're currently in backoff period
func (c *Client) IsInBackoff() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return time.Now().Before(c.backoffUntil)
}

// SetBackoff sets the backoff period
func (c *Client) SetBackoff() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.backoffUntil = time.Now().Add(c.backoffDuration)
}

// ClearBackoff clears the backoff (on successful request)
func (c *Client) ClearBackoff() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.backoffUntil = time.Time{}
}

// GetIPInfo fetches IP information from ipapi.is
func (c *Client) GetIPInfo(ctx context.Context, ip string) (map[string]interface{}, error) {
	// Check if we're in backoff period
	if c.IsInBackoff() {
		c.mu.RLock()
		remaining := time.Until(c.backoffUntil)
		c.mu.RUnlock()
		return nil, fmt.Errorf("in backoff period, retry in %v", remaining.Round(time.Second))
	}

	// Build URL with IP parameter
	reqURL := fmt.Sprintf("%s/?q=%s", c.baseURL, url.QueryEscape(ip))

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Set backoff on network errors (timeout, etc)
		c.SetBackoff()
		return nil, fmt.Errorf("failed to fetch IP info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		// Set backoff on rate limit
		c.SetBackoff()
		return nil, fmt.Errorf("rate limited (429), backing off for %v", c.backoffDuration)
	}

	if resp.StatusCode != http.StatusOK {
		// Set backoff on other errors too
		c.SetBackoff()
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var ipInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&ipInfo); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Clear backoff on successful request
	c.ClearBackoff()

	return ipInfo, nil
}

// ExtractIPFromEndpoint extracts IP from endpoint URL
func ExtractIPFromEndpoint(endpoint string) (string, error) {
	// Parse URL
	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("failed to parse endpoint URL: %w", err)
	}

	host := parsedURL.Hostname()
	if host == "" {
		return "", fmt.Errorf("no hostname in endpoint")
	}

	// Check if host is already an IP
	if net.ParseIP(host) != nil {
		return host, nil
	}

	// Resolve hostname to IP
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("failed to resolve hostname: %w", err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IPs found for hostname")
	}

	// Return first IPv4 address
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	// Fallback to first IP (might be IPv6)
	return ips[0].String(), nil
}
