package wayback

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/neonn0d/jsfinder/parser"
)

// Client queries the Wayback Machine CDX API
type Client struct {
	httpClient *http.Client
	timeout    time.Duration
}

// Result represents a JS URL found in Wayback Machine
type Result struct {
	URL    string
	Source string
}

// New creates a new Wayback Machine client
func New(timeout time.Duration) *Client {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     30 * time.Second,
		ForceAttemptHTTP2:   false,
	}

	return &Client{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
		timeout: timeout,
	}
}

// Query fetches JS URLs for a domain from Wayback Machine (single fast query)
func (c *Client) Query(ctx context.Context, domain string) ([]Result, error) {
	var results []Result
	seen := make(map[string]bool)

	// Single query - get ALL URLs, filter .js locally (like waybackurls)
	urls, err := c.fetchAllURLs(ctx, domain)
	if err != nil {
		return nil, err
	}

	for _, u := range urls {
		// Filter for JS files locally
		if !parser.IsJSFile(u) {
			continue
		}
		// Skip Cloudflare challenge URLs
		if strings.Contains(u, "cdn-cgi/challenge") {
			continue
		}
		normalized := parser.NormalizeURL(u)
		if !seen[normalized] {
			seen[normalized] = true
			results = append(results, Result{URL: u, Source: "wayback"})
		}
	}

	return results, nil
}

// fetchAllURLs gets all URLs for a domain with single CDX query
func (c *Client) fetchAllURLs(ctx context.Context, domain string) ([]string, error) {
	// Same approach as waybackurls - single query, get everything
	cdxURL := fmt.Sprintf(
		"http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&collapse=urlkey",
		domain,
	)

	req, err := http.NewRequestWithContext(ctx, "GET", cdxURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CDX API returned status %d", resp.StatusCode)
	}

	return c.parseResponse(resp.Body)
}

// parseResponse parses CDX JSON response
func (c *Client) parseResponse(body io.Reader) ([]string, error) {
	// Try JSON parsing first
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}

	var rows [][]interface{}
	if err := json.Unmarshal(data, &rows); err != nil {
		// Fallback to line-by-line
		return c.parseLineByLine(string(data)), nil
	}

	var urls []string
	for i, row := range rows {
		if i == 0 {
			continue // Skip header
		}
		// URL is typically at index 2 in CDX response
		if len(row) > 2 {
			if urlStr, ok := row[2].(string); ok {
				urls = append(urls, urlStr)
			}
		}
	}

	return urls, nil
}

// parseLineByLine handles non-JSON responses
func (c *Client) parseLineByLine(data string) []string {
	var urls []string
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			urls = append(urls, line)
		}
	}
	return urls
}

// QueryMultiple queries multiple domains concurrently
func (c *Client) QueryMultiple(ctx context.Context, domains []string, concurrency int) chan Result {
	results := make(chan Result, 10000)
	var wg sync.WaitGroup

	// Semaphore for concurrency control
	sem := make(chan struct{}, concurrency)

	go func() {
		for _, domain := range domains {
			select {
			case <-ctx.Done():
				break
			default:
			}

			wg.Add(1)
			sem <- struct{}{}

			go func(d string) {
				defer wg.Done()
				defer func() { <-sem }()

				domainResults, err := c.Query(ctx, d)
				if err != nil {
					return
				}

				for _, r := range domainResults {
					select {
					case results <- r:
					case <-ctx.Done():
						return
					}
				}
			}(domain)
		}

		wg.Wait()
		close(results)
	}()

	return results
}

// GetDomainFromURL extracts the domain from a URL
func GetDomainFromURL(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
