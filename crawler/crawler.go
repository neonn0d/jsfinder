package crawler

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/neonn0d/jsfinder/parser"
)

// Config holds crawler configuration
type Config struct {
	Concurrency int
	Timeout     time.Duration
	Headers     map[string]string
	Proxy       string
	Verbose     bool
}

// Result represents a discovered JS file
type Result struct {
	URL    string
	Source string // "crawl", "wayback", "bruteforce"
}

// Crawler performs recursive web crawling
type Crawler struct {
	config     Config
	client     *http.Client
	visited    sync.Map
	jsFiles    sync.Map
	queue      chan string
	results    chan Result
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	baseHost   string
	allowedDomains map[string]bool
}

// New creates a new Crawler instance
func New(config Config) *Crawler {

	// Configure HTTP client - disable HTTP/2 to avoid "unsolicited response" warnings
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   false,
		DisableKeepAlives:   false,
	}

	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow up to 10 redirects
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return &Crawler{
		config:         config,
		client:         client,
		queue:          make(chan string, 10000),
		results:        make(chan Result, 1000),
		allowedDomains: make(map[string]bool),
	}
}

// Crawl starts crawling from the given URLs
func (c *Crawler) Crawl(ctx context.Context, startURLs []string) chan Result {
	c.ctx, c.cancel = context.WithCancel(ctx)
	// Set allowed domains from start URLs
	for _, u := range startURLs {
		parsed, err := url.Parse(u)
		if err == nil {
			c.allowedDomains[parsed.Hostname()] = true
			// Also allow parent domain for subdomain crawling
			parts := strings.Split(parsed.Hostname(), ".")
			if len(parts) >= 2 {
				parentDomain := strings.Join(parts[len(parts)-2:], ".")
				c.allowedDomains[parentDomain] = true
			}
		}
	}

	// Start workers
	for i := 0; i < c.config.Concurrency; i++ {
		c.wg.Add(1)
		go c.worker()
	}

	// Seed the queue
	go func() {
		for _, u := range startURLs {
			normalized := parser.NormalizeURL(u)
			if _, loaded := c.visited.LoadOrStore(normalized, true); !loaded {
				c.queue <- u
			}
		}
	}()

	// Close results when done
	go func() {
		c.wg.Wait()
		close(c.results)
	}()

	return c.results
}

// worker processes URLs from the queue
func (c *Crawler) worker() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		case urlStr, ok := <-c.queue:
			if !ok {
				return
			}
			c.processURL(urlStr)
		case <-time.After(5 * time.Second):
			// No new URLs for 5 seconds, worker exits
			return
		}
	}
}

// processURL fetches and processes a single URL
func (c *Crawler) processURL(urlStr string) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return
	}

	// Check if domain is allowed
	if !c.isAllowedDomain(parsed.Hostname()) {
		return
	}

	// Fetch the URL
	body, contentType, err := c.fetch(urlStr)
	if err != nil {
		return
	}

	// If it's a JS file, add to results
	if parser.IsJSFile(urlStr) || parser.IsJSContentType(contentType) {
		c.addJSResult(urlStr)
		// Also extract imports from JS files
		jsURLs := parser.ExtractJSImports(body, parsed)
		for _, jsURL := range jsURLs {
			c.addJSResult(jsURL)
			c.maybeEnqueue(jsURL)
		}
		return
	}

	// If HTML, extract scripts and links
	if strings.Contains(contentType, "text/html") {
		// Extract JS files
		scripts := parser.ExtractScriptSrcs(body, parsed)
		for _, script := range scripts {
			c.addJSResult(script)
			// Also try to fetch JS files to find more imports
			c.maybeEnqueue(script)
		}

		// Extract all JS references
		allJS := parser.ExtractAllJSReferences(body, parsed)
		for _, js := range allJS {
			c.addJSResult(js)
		}

		// Extract links for further crawling
		links := parser.ExtractLinks(body, parsed)
		for _, link := range links {
			c.maybeEnqueue(link)
		}
	}
}

// fetch retrieves a URL and returns its body and content-type
func (c *Crawler) fetch(urlStr string) (string, string, error) {
	req, err := http.NewRequestWithContext(c.ctx, "GET", urlStr, nil)
	if err != nil {
		return "", "", err
	}

	// Set default headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	// Set custom headers
	for key, value := range c.config.Headers {
		req.Header.Set(key, value)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", nil
	}

	// Limit body size to 10MB
	limitedReader := io.LimitReader(resp.Body, 10*1024*1024)
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", "", err
	}

	contentType := resp.Header.Get("Content-Type")
	return string(bodyBytes), contentType, nil
}

// addJSResult adds a JS URL to results if not already seen
func (c *Crawler) addJSResult(urlStr string) {
	normalized := parser.NormalizeURL(urlStr)
	if _, loaded := c.jsFiles.LoadOrStore(normalized, true); !loaded {
		select {
		case c.results <- Result{URL: urlStr, Source: "crawl"}:
		default:
		}
	}
}

// maybeEnqueue adds a URL to the queue if not already visited
func (c *Crawler) maybeEnqueue(urlStr string) {
	normalized := parser.NormalizeURL(urlStr)

	// Parse to check domain
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return
	}

	// Only enqueue HTTP URLs
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return
	}

	// Check domain allowlist
	if !c.isAllowedDomain(parsed.Hostname()) {
		return
	}

	// Skip common non-crawlable extensions
	if shouldSkipURL(parsed.Path) {
		return
	}

	if _, loaded := c.visited.LoadOrStore(normalized, true); !loaded {
		select {
		case c.queue <- urlStr:
		default:
			// Queue full, skip
		}
	}
}

// isAllowedDomain checks if a domain should be crawled
func (c *Crawler) isAllowedDomain(domain string) bool {
	if c.allowedDomains[domain] {
		return true
	}

	// Check if it's a subdomain of an allowed domain
	for allowed := range c.allowedDomains {
		if strings.HasSuffix(domain, "."+allowed) {
			return true
		}
	}

	return false
}

// Stop cancels the crawler
func (c *Crawler) Stop() {
	c.cancel()
	close(c.queue)
}

// shouldSkipURL returns true for URLs that shouldn't be crawled
func shouldSkipURL(path string) bool {
	path = strings.ToLower(path)
	skipExtensions := []string{
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
		".css", ".woff", ".woff2", ".ttf", ".eot",
		".pdf", ".doc", ".docx", ".xls", ".xlsx",
		".zip", ".tar", ".gz", ".rar",
		".mp3", ".mp4", ".avi", ".mov", ".webm",
		".xml", ".rss", ".atom",
	}

	for _, ext := range skipExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}

	return false
}
