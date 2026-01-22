package bruteforce

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/neonn0d/jsfinder/parser"
)

// Common JS paths to check
var commonPaths = []string{
	// Generic JS paths
	"/js/app.js",
	"/js/main.js",
	"/js/bundle.js",
	"/js/vendor.js",
	"/js/script.js",
	"/js/scripts.js",
	"/js/common.js",
	"/js/core.js",
	"/js/index.js",

	// Assets folder
	"/assets/js/app.js",
	"/assets/js/main.js",
	"/assets/js/bundle.js",
	"/assets/js/vendor.js",
	"/assets/js/script.js",
	"/assets/js/scripts.js",
	"/assets/app.js",
	"/assets/main.js",
	"/assets/bundle.js",

	// Static folder
	"/static/js/main.js",
	"/static/js/bundle.js",
	"/static/js/app.js",
	"/static/js/vendor.js",
	"/static/main.js",
	"/static/bundle.js",
	"/static/app.js",

	// Dist/Build folders
	"/dist/bundle.js",
	"/dist/main.js",
	"/dist/app.js",
	"/dist/vendor.js",
	"/dist/index.js",
	"/build/bundle.js",
	"/build/main.js",
	"/build/app.js",
	"/build/static/js/main.js",
	"/build/static/js/bundle.js",

	// Webpack/Module bundlers
	"/vendor.js",
	"/runtime.js",
	"/polyfills.js",
	"/polyfill.js",
	"/webpack-runtime.js",
	"/manifest.js",
	"/commons.js",
	"/chunk.js",

	// Next.js
	"/_next/static/chunks/main.js",
	"/_next/static/chunks/webpack.js",
	"/_next/static/chunks/framework.js",
	"/_next/static/chunks/commons.js",
	"/_next/static/chunks/pages/_app.js",
	"/_next/static/chunks/pages/index.js",

	// Nuxt.js
	"/_nuxt/app.js",
	"/_nuxt/runtime.js",
	"/_nuxt/commons.js",
	"/_nuxt/vendors.js",

	// React
	"/static/js/main.chunk.js",
	"/static/js/runtime-main.js",
	"/static/js/vendors-main.chunk.js",
	"/static/js/2.chunk.js",

	// Angular
	"/main.js",
	"/polyfills.js",
	"/runtime.js",
	"/vendor.js",
	"/scripts.js",
	"/styles.js",

	// Vue.js
	"/app.js",
	"/chunk-vendors.js",
	"/chunk-common.js",

	// jQuery and common libraries
	"/jquery.js",
	"/jquery.min.js",
	"/js/jquery.js",
	"/js/jquery.min.js",

	// Public folder
	"/public/js/app.js",
	"/public/js/main.js",
	"/public/bundle.js",

	// CDN-style paths
	"/cdn/js/app.js",
	"/cdn/bundle.js",

	// Minified versions
	"/app.min.js",
	"/main.min.js",
	"/bundle.min.js",
	"/vendor.min.js",
	"/js/app.min.js",
	"/js/main.min.js",

	// Common API/Config files
	"/config.js",
	"/settings.js",
	"/env.js",
	"/constants.js",

	// Admin/Dashboard
	"/admin/js/app.js",
	"/admin/js/admin.js",
	"/dashboard/js/app.js",

	// API related
	"/api.js",
	"/api/v1/swagger.js",
}

// Result represents a found JS file
type Result struct {
	URL    string
	Source string
}

// Checker performs bruteforce checking of common JS paths
type Checker struct {
	client      *http.Client
	timeout     time.Duration
	headers     map[string]string
	concurrency int
}

// Config holds checker configuration
type Config struct {
	Timeout     time.Duration
	Headers     map[string]string
	Proxy       string
	Concurrency int
}

// New creates a new bruteforce checker
func New(config Config) *Checker {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
	}

	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return &Checker{
		client: &http.Client{
			Transport: transport,
			Timeout:   config.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Don't follow redirects for bruteforce
				return http.ErrUseLastResponse
			},
		},
		timeout:     config.Timeout,
		headers:     config.Headers,
		concurrency: config.Concurrency,
	}
}

// Check tests all common JS paths against the given base URL
func (c *Checker) Check(ctx context.Context, baseURL string) chan Result {
	results := make(chan Result, 100)

	// Normalize base URL
	parsed, err := url.Parse(baseURL)
	if err != nil {
		close(results)
		return results
	}

	base := parsed.Scheme + "://" + parsed.Host

	go func() {
		defer close(results)

		var wg sync.WaitGroup
		sem := make(chan struct{}, c.concurrency)

		for _, path := range commonPaths {
			select {
			case <-ctx.Done():
				return
			default:
			}

			wg.Add(1)
			sem <- struct{}{}

			go func(p string) {
				defer wg.Done()
				defer func() { <-sem }()

				fullURL := base + p
				if c.checkPath(ctx, fullURL) {
					select {
					case results <- Result{URL: fullURL, Source: "bruteforce"}:
					case <-ctx.Done():
					}
				}
			}(path)
		}

		wg.Wait()
	}()

	return results
}

// CheckMultiple checks common paths for multiple base URLs
func (c *Checker) CheckMultiple(ctx context.Context, baseURLs []string) chan Result {
	results := make(chan Result, 1000)

	go func() {
		defer close(results)

		var wg sync.WaitGroup
		seen := sync.Map{}

		for _, baseURL := range baseURLs {
			select {
			case <-ctx.Done():
				return
			default:
			}

			wg.Add(1)
			go func(base string) {
				defer wg.Done()

				for r := range c.Check(ctx, base) {
					normalized := parser.NormalizeURL(r.URL)
					if _, loaded := seen.LoadOrStore(normalized, true); !loaded {
						select {
						case results <- r:
						case <-ctx.Done():
							return
						}
					}
				}
			}(baseURL)
		}

		wg.Wait()
	}()

	return results
}

// checkPath tests if a JS file exists at the given URL
func (c *Checker) checkPath(ctx context.Context, urlStr string) bool {
	// Use HEAD request first for efficiency
	req, err := http.NewRequestWithContext(ctx, "HEAD", urlStr, nil)
	if err != nil {
		return false
	}

	c.setHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Check if it's a successful response
	if resp.StatusCode != http.StatusOK {
		return false
	}

	// Verify content-type if available
	contentType := resp.Header.Get("Content-Type")
	if contentType != "" {
		// Must be JavaScript or at least not HTML
		if strings.Contains(contentType, "text/html") {
			return false
		}
		if parser.IsJSContentType(contentType) {
			return true
		}
	}

	// If no content-type or uncertain, do a GET and check
	return c.verifyWithGet(ctx, urlStr)
}

// verifyWithGet does a full GET request to verify the file
func (c *Checker) verifyWithGet(ctx context.Context, urlStr string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return false
	}

	c.setHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	contentType := resp.Header.Get("Content-Type")
	if parser.IsJSContentType(contentType) {
		return true
	}

	// Reject HTML responses (soft 404s)
	if strings.Contains(contentType, "text/html") {
		return false
	}

	// Accept if no content-type and URL looks like JS
	if contentType == "" && parser.IsJSFile(urlStr) {
		return true
	}

	return false
}

// setHeaders sets common headers on a request
func (c *Checker) setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	for key, value := range c.headers {
		req.Header.Set(key, value)
	}
}

// GetCommonPaths returns the list of common paths being checked
func GetCommonPaths() []string {
	return commonPaths
}
