package parser

import (
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

var (
	// Regex patterns for JS extraction
	importRegex    = regexp.MustCompile(`import\s+(?:.*?\s+from\s+)?['"]([^'"]+\.js)['"]`)
	dynamicImport  = regexp.MustCompile(`import\s*\(\s*['"]([^'"]+\.js)['"]\s*\)`)
	requireRegex   = regexp.MustCompile(`require\s*\(\s*['"]([^'"]+\.js)['"]\s*\)`)
	srcRegex       = regexp.MustCompile(`(?i)['"]([^'"]*\.js(?:\?[^'"]*)?)['""]`)
	jsExtRegex     = regexp.MustCompile(`(?i)\.js(\?.*)?$`)
	jsContentTypes = []string{
		"application/javascript",
		"application/x-javascript",
		"text/javascript",
		"application/ecmascript",
		"text/ecmascript",
	}
)

// ExtractScriptSrcs finds all <script src="..."> tags in HTML
func ExtractScriptSrcs(htmlContent string, baseURL *url.URL) []string {
	var results []string
	seen := make(map[string]bool)

	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		// Fallback to regex if HTML parsing fails
		return extractScriptSrcsRegex(htmlContent, baseURL)
	}

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			for _, attr := range n.Attr {
				if attr.Key == "src" && attr.Val != "" {
					resolved := ResolveURL(baseURL, attr.Val)
					if resolved != "" && !seen[resolved] {
						seen[resolved] = true
						results = append(results, resolved)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}
	extract(doc)

	return results
}

// extractScriptSrcsRegex is a fallback regex-based extractor
func extractScriptSrcsRegex(htmlContent string, baseURL *url.URL) []string {
	var results []string
	seen := make(map[string]bool)

	scriptTagRegex := regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*['"]([^'"]+)['"]`)
	matches := scriptTagRegex.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range matches {
		if len(match) > 1 {
			resolved := ResolveURL(baseURL, match[1])
			if resolved != "" && !seen[resolved] {
				seen[resolved] = true
				results = append(results, resolved)
			}
		}
	}

	return results
}

// ExtractLinks finds all <a href="..."> links for crawling
func ExtractLinks(htmlContent string, baseURL *url.URL) []string {
	var results []string
	seen := make(map[string]bool)

	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return extractLinksRegex(htmlContent, baseURL)
	}

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key == "href" && attr.Val != "" {
					resolved := ResolveURL(baseURL, attr.Val)
					if resolved != "" && !seen[resolved] && isHTTPURL(resolved) {
						seen[resolved] = true
						results = append(results, resolved)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}
	extract(doc)

	return results
}

// extractLinksRegex is a fallback regex-based link extractor
func extractLinksRegex(htmlContent string, baseURL *url.URL) []string {
	var results []string
	seen := make(map[string]bool)

	linkRegex := regexp.MustCompile(`(?i)<a[^>]+href\s*=\s*['"]([^'"]+)['"]`)
	matches := linkRegex.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range matches {
		if len(match) > 1 {
			resolved := ResolveURL(baseURL, match[1])
			if resolved != "" && !seen[resolved] && isHTTPURL(resolved) {
				seen[resolved] = true
				results = append(results, resolved)
			}
		}
	}

	return results
}

// ExtractJSImports finds import/require statements pointing to other JS files
func ExtractJSImports(jsContent string, baseURL *url.URL) []string {
	var results []string
	seen := make(map[string]bool)

	patterns := []*regexp.Regexp{importRegex, dynamicImport, requireRegex, srcRegex}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(jsContent, -1)
		for _, match := range matches {
			if len(match) > 1 {
				path := match[1]
				// Skip data URLs, blob URLs, etc.
				if strings.HasPrefix(path, "data:") || strings.HasPrefix(path, "blob:") {
					continue
				}
				resolved := ResolveURL(baseURL, path)
				if resolved != "" && !seen[resolved] && IsJSFile(resolved) {
					seen[resolved] = true
					results = append(results, resolved)
				}
			}
		}
	}

	return results
}

// ExtractAllJSReferences extracts JS URLs from any content type
func ExtractAllJSReferences(content string, baseURL *url.URL) []string {
	var results []string
	seen := make(map[string]bool)

	// Script tags
	for _, js := range ExtractScriptSrcs(content, baseURL) {
		if !seen[js] {
			seen[js] = true
			results = append(results, js)
		}
	}

	// JS imports
	for _, js := range ExtractJSImports(content, baseURL) {
		if !seen[js] {
			seen[js] = true
			results = append(results, js)
		}
	}

	return results
}

// ResolveURL converts a relative URL to absolute using the base URL
func ResolveURL(base *url.URL, relative string) string {
	if relative == "" {
		return ""
	}

	// Skip non-HTTP schemes
	relative = strings.TrimSpace(relative)
	if strings.HasPrefix(relative, "javascript:") ||
		strings.HasPrefix(relative, "data:") ||
		strings.HasPrefix(relative, "blob:") ||
		strings.HasPrefix(relative, "mailto:") ||
		strings.HasPrefix(relative, "tel:") ||
		strings.HasPrefix(relative, "#") {
		return ""
	}

	// Parse relative URL
	ref, err := url.Parse(relative)
	if err != nil {
		return ""
	}

	// Resolve against base
	resolved := base.ResolveReference(ref)

	// Normalize the URL
	resolved.Fragment = "" // Remove fragment

	result := resolved.String()

	// Skip URLs that are too long (crawler trap detection)
	if len(result) > 500 {
		return ""
	}

	// Skip URLs with repeated path segments (loop detection)
	if hasRepeatedSegments(resolved.Path) {
		return ""
	}

	return result
}

// hasRepeatedSegments detects crawler traps with repeated path patterns
func hasRepeatedSegments(path string) bool {
	segments := strings.Split(path, "/")
	if len(segments) < 6 {
		return false
	}

	// Count occurrences of each segment
	counts := make(map[string]int)
	for _, seg := range segments {
		if seg == "" || seg == "-" {
			continue
		}
		counts[seg]++
		// If any segment appears more than 3 times, it's likely a trap
		if counts[seg] > 3 {
			return true
		}
	}

	return false
}

// IsJSFile checks if a URL likely points to a JavaScript file
func IsJSFile(urlStr string) bool {
	// Parse URL to check path
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	path := strings.ToLower(parsed.Path)

	// Check common JS extensions
	if jsExtRegex.MatchString(path) {
		return true
	}

	// Check for common JS paths without extension
	jsIndicators := []string{
		"/webpack",
		"/bundle",
		"/chunk",
		"/vendor",
		"/runtime",
		"/polyfill",
	}

	for _, indicator := range jsIndicators {
		if strings.Contains(path, indicator) {
			return true
		}
	}

	return false
}

// IsJSContentType checks if the content-type header indicates JavaScript
func IsJSContentType(contentType string) bool {
	contentType = strings.ToLower(contentType)
	for _, jsType := range jsContentTypes {
		if strings.Contains(contentType, jsType) {
			return true
		}
	}
	return false
}

// NormalizeURL normalizes a URL for deduplication
func NormalizeURL(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}

	// Lowercase scheme and host
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)

	// Remove fragment
	parsed.Fragment = ""

	// Remove trailing slash from path (unless it's just "/")
	if len(parsed.Path) > 1 {
		parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	}

	// Remove default ports
	if (parsed.Scheme == "http" && parsed.Port() == "80") ||
		(parsed.Scheme == "https" && parsed.Port() == "443") {
		parsed.Host = parsed.Hostname()
	}

	return parsed.String()
}

// GetDomain extracts the domain from a URL
func GetDomain(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// GetBaseURL extracts scheme + host from a URL
func GetBaseURL(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

// IsSameOrigin checks if two URLs have the same origin
func IsSameOrigin(url1, url2 string) bool {
	return GetBaseURL(url1) == GetBaseURL(url2)
}

// IsSameDomain checks if two URLs belong to the same domain (including subdomains)
func IsSameDomain(url1, url2 string) bool {
	d1 := GetDomain(url1)
	d2 := GetDomain(url2)

	if d1 == d2 {
		return true
	}

	// Check if one is a subdomain of the other
	return strings.HasSuffix(d1, "."+d2) || strings.HasSuffix(d2, "."+d1)
}

// isHTTPURL checks if a URL uses HTTP or HTTPS scheme
func isHTTPURL(urlStr string) bool {
	return strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://")
}

// ParseURL parses a URL string
func ParseURL(urlStr string) (*url.URL, error) {
	return url.Parse(urlStr)
}
