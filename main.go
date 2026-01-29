package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/neonn0d/jsfinder/bruteforce"
	"github.com/neonn0d/jsfinder/crawler"
	"github.com/neonn0d/jsfinder/output"
	"github.com/neonn0d/jsfinder/wayback"
)

// headerFlags allows multiple -H flags
type headerFlags []string

func (h *headerFlags) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

func main() {
	// Suppress noisy HTTP library warnings
	log.SetOutput(io.Discard)

	// Define flags
	targetURL := flag.String("u", "", "Single target URL")
	urlList := flag.String("l", "", "File containing list of URLs")
	outputFile := flag.String("o", "", "Output file for JS URLs (required)")
	concurrency := flag.Int("c", 50, "Concurrency level")
	timeout := flag.Int("t", 10, "Request timeout in seconds")
	proxyURL := flag.String("proxy", "", "Proxy URL (e.g., http://127.0.0.1:8080)")
	verbose := flag.Bool("v", false, "Verbose output")
	silent := flag.Bool("silent", false, "Only output JS URLs (no banner/stats)")
	noCrawl := flag.Bool("no-crawl", false, "Disable crawling")
	noWayback := flag.Bool("no-wayback", false, "Disable Wayback Machine queries")
	noBruteforce := flag.Bool("no-bruteforce", false, "Disable bruteforce checking")

	var headers headerFlags
	flag.Var(&headers, "H", "Custom header (can be used multiple times)")

	flag.Parse()

	// Print banner unless silent
	if !*silent {
		output.PrintBanner()
	}

	// Validate required flags
	if *targetURL == "" && *urlList == "" {
		fmt.Println("Error: Either -u (single URL) or -l (URL list file) is required")
		flag.Usage()
		os.Exit(1)
	}

	if *outputFile == "" {
		fmt.Println("Error: -o (output file) is required")
		flag.Usage()
		os.Exit(1)
	}

	// Parse custom headers
	customHeaders := make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			customHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Load target URLs
	var targetURLs []string
	if *targetURL != "" {
		targetURLs = append(targetURLs, normalizeInputURL(*targetURL))
	}
	if *urlList != "" {
		urls, err := loadURLsFromFile(*urlList)
		if err != nil {
			output.PrintError("Failed to load URLs from file: %v", err)
			os.Exit(1)
		}
		targetURLs = append(targetURLs, urls...)
	}

	if len(targetURLs) == 0 {
		output.PrintError("No valid URLs provided")
		os.Exit(1)
	}

	// Extract unique domains for Wayback queries
	domains := extractUniqueDomains(targetURLs)

	// Create result collector (writes to file immediately)
	collector := output.New(*verbose, *silent, *outputFile)

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		if !*silent {
			fmt.Println("\n[*] Interrupt received, saving results...")
		}
		cancel()
	}()

	// WaitGroup for all discovery methods
	var wg sync.WaitGroup
	timeoutDuration := time.Duration(*timeout) * time.Second

	// Progress ticker
	done := make(chan struct{})
	if !*silent {
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					fmt.Printf("\r[*] Found: %d JS files...", collector.Count())
				}
			}
		}()
	}

	// Start crawler
	if !*noCrawl {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !*silent {
				output.PrintInfo("Starting crawler on %d URL(s)...", len(targetURLs))
			}

			c := crawler.New(crawler.Config{
				Concurrency: *concurrency,
				Timeout:     timeoutDuration,
				Headers:     customHeaders,
				Proxy:       *proxyURL,
				Verbose:     *verbose,
			})

			for result := range c.Crawl(ctx, targetURLs) {
				collector.Add(result.URL, result.Source)
			}
		}()
	}

	// Start Wayback Machine queries
	if !*noWayback {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !*silent {
				output.PrintInfo("Querying Wayback Machine for %d domain(s)...", len(domains))
			}

			wb := wayback.New(timeoutDuration * 2)

			// Use same concurrency as crawler for Wayback
			for result := range wb.QueryMultiple(ctx, domains, *concurrency) {
				collector.Add(result.URL, result.Source)
			}
		}()
	}

	// Start bruteforce checking
	if !*noBruteforce {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !*silent {
				output.PrintInfo("Bruteforcing common JS paths...")
			}

			// Extract base URLs
			baseURLs := extractBaseURLs(targetURLs)

			bf := bruteforce.New(bruteforce.Config{
				Timeout:     timeoutDuration,
				Headers:     customHeaders,
				Proxy:       *proxyURL,
				Concurrency: *concurrency / 2, // Use half concurrency for bruteforce
			})

			for result := range bf.CheckMultiple(ctx, baseURLs) {
				collector.Add(result.URL, result.Source)
			}
		}()
	}

	// Wait for all methods to complete
	wg.Wait()
	close(done)

	// Clear progress line
	if !*silent {
		fmt.Print("\r                                        \r")
	}

	// Write results to file
	if err := collector.WriteToFile(*outputFile); err != nil {
		output.PrintError("Failed to write output file: %v", err)
		os.Exit(1)
	}

	// Print summary
	collector.PrintSummary(*outputFile)
}

// normalizeInputURL ensures URL has a scheme
func normalizeInputURL(urlStr string) string {
	urlStr = strings.TrimSpace(urlStr)
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr
	}
	return urlStr
}

// loadURLsFromFile reads URLs from a file
func loadURLsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, normalizeInputURL(line))
		}
	}

	return urls, scanner.Err()
}

// extractUniqueDomains extracts unique domains from URLs
func extractUniqueDomains(urls []string) []string {
	seen := make(map[string]bool)
	var domains []string

	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		domain := parsed.Hostname()
		if !seen[domain] {
			seen[domain] = true
			domains = append(domains, domain)
		}
	}

	return domains
}

// extractBaseURLs extracts unique base URLs (scheme + host)
func extractBaseURLs(urls []string) []string {
	seen := make(map[string]bool)
	var baseURLs []string

	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		base := parsed.Scheme + "://" + parsed.Host
		if !seen[base] {
			seen[base] = true
			baseURLs = append(baseURLs, base)
		}
	}

	return baseURLs
}
