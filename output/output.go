package output

import (
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/neonn0d/jsfinder/parser"
)

// Stats holds discovery statistics
type Stats struct {
	Crawl      int
	Wayback    int
	Bruteforce int
	Total      int
}

// Collector collects and deduplicates JS URLs
type Collector struct {
	mu       sync.RWMutex
	urls     map[string]string // normalized URL -> source
	order    []string          // preserve order of discovery
	verbose  bool
	silent   bool
	file     *os.File
	filePath string
}

// New creates a new result collector
func New(verbose, silent bool, outputFile string) *Collector {
	c := &Collector{
		urls:     make(map[string]string),
		order:    make([]string, 0),
		verbose:  verbose,
		silent:   silent,
		filePath: outputFile,
	}

	// Open file for immediate writing
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err == nil {
			c.file = f
		}
	}

	return c
}

// Add adds a JS URL to the collection and writes to file immediately
func (c *Collector) Add(url, source string) bool {
	// Skip URLs that are too long (crawler trap)
	if len(url) > 500 {
		return false
	}

	normalized := parser.NormalizeURL(url)

	// Skip if normalization failed or too long
	if normalized == "" || len(normalized) > 500 {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.urls[normalized]; exists {
		return false // Already seen
	}

	c.urls[normalized] = source
	c.order = append(c.order, normalized)

	// Write to file immediately (saves on crash/interrupt)
	if c.file != nil {
		c.file.WriteString(normalized + "\n")
		c.file.Sync()
	}

	// Print if verbose and not silent
	if c.verbose && !c.silent {
		sourceLabel := ""
		switch source {
		case "crawl":
			sourceLabel = ""
		case "wayback":
			sourceLabel = " (wayback)"
		case "bruteforce":
			sourceLabel = " (bruteforce)"
		}
		fmt.Printf("[INF] Found: %s%s\n", url, sourceLabel)
	}

	return true
}

// GetAll returns all collected URLs
func (c *Collector) GetAll() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]string, len(c.order))
	copy(result, c.order)
	return result
}

// GetSorted returns all URLs sorted alphabetically
func (c *Collector) GetSorted() []string {
	urls := c.GetAll()
	sort.Strings(urls)
	return urls
}

// GetStats returns statistics about discovered URLs
func (c *Collector) GetStats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := Stats{}
	for _, source := range c.urls {
		switch source {
		case "crawl":
			stats.Crawl++
		case "wayback":
			stats.Wayback++
		case "bruteforce":
			stats.Bruteforce++
		}
	}
	stats.Total = len(c.urls)
	return stats
}

// Count returns the total number of unique URLs
func (c *Collector) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.urls)
}

// WriteToFile closes the file (already written incrementally)
func (c *Collector) WriteToFile(filename string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.file != nil {
		c.file.Close()
		c.file = nil
	}
	return nil
}

// Close closes the output file
func (c *Collector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.file != nil {
		c.file.Close()
		c.file = nil
	}
}

// PrintSummary prints a summary of results
func (c *Collector) PrintSummary(outputFile string) {
	if c.silent {
		// In silent mode, just print the URLs
		for _, url := range c.GetSorted() {
			fmt.Println(url)
		}
		return
	}

	stats := c.GetStats()

	fmt.Println()
	fmt.Println("[*] Scan complete")
	fmt.Printf("[*] Total JS files found: %d\n", stats.Total)

	if stats.Crawl > 0 {
		fmt.Printf("    - From crawling: %d\n", stats.Crawl)
	}
	if stats.Wayback > 0 {
		fmt.Printf("    - From Wayback Machine: %d\n", stats.Wayback)
	}
	if stats.Bruteforce > 0 {
		fmt.Printf("    - From bruteforce: %d\n", stats.Bruteforce)
	}

	if outputFile != "" {
		fmt.Printf("[*] Results saved to %s\n", outputFile)
	}
}

// PrintBanner prints the tool banner
func PrintBanner() {
	banner := `
     ╦╔═╗╔═╗┬┌┐┌┌┬┐┌─┐┬─┐
     ║╚═╗╠╣ ││││ ││├┤ ├┬┘
    ╚╝╚═╝╚  ┴┘└┘─┴┘└─┘┴└─  v1.0

    JavaScript File Discovery Tool
`
	fmt.Println(banner)
}

// PrintInfo prints an info message
func PrintInfo(format string, args ...interface{}) {
	fmt.Printf("[INF] "+format+"\n", args...)
}

// PrintError prints an error message
func PrintError(format string, args ...interface{}) {
	fmt.Printf("[ERR] "+format+"\n", args...)
}

// PrintWarning prints a warning message
func PrintWarning(format string, args ...interface{}) {
	fmt.Printf("[WRN] "+format+"\n", args...)
}
