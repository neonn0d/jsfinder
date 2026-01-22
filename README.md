# JSFinder

Fast JavaScript file discovery tool for bug bounty and security research.

## Features

- **Crawler** - Recursively crawls websites to find JS files
- **Wayback Machine** - Queries archive.org for historical JS files
- **Bruteforce** - Checks common JS paths (/js/app.js, /static/bundle.js, etc.)
- **Concurrent** - All methods run in parallel for speed
- **Deduplication** - Automatically removes duplicate URLs

## Installation

```bash
go install github.com/neonn0d/jsfinder@latest
```

Or build from source:

```bash
git clone https://github.com/neonn0d/jsfinder.git
cd jsfinder
go build -o jsfinder .
```

## Usage

```bash
# Single target
jsfinder -u https://example.com -o output.txt

# Multiple targets from file
jsfinder -l urls.txt -o output.txt

# With custom headers
jsfinder -u https://example.com -o output.txt -H "Authorization: Bearer token" -H "Cookie: session=abc"

# High concurrency
jsfinder -u https://example.com -o output.txt -c 100

# Disable specific methods
jsfinder -u https://example.com -o output.txt --no-wayback --no-bruteforce

# Silent mode (only output JS URLs)
jsfinder -u https://example.com -o output.txt --silent

# With proxy (for Burp)
jsfinder -u https://example.com -o output.txt --proxy http://127.0.0.1:8080
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-u` | Single target URL | - |
| `-l` | File containing list of URLs | - |
| `-o` | Output file (required) | - |
| `-c` | Concurrency level | 50 |
| `-t` | Request timeout in seconds | 10 |
| `-H` | Custom header (can be used multiple times) | - |
| `--proxy` | Proxy URL | - |
| `-v` | Verbose output | false |
| `--silent` | Only output JS URLs | false |
| `--no-crawl` | Disable crawling | false |
| `--no-wayback` | Disable Wayback Machine | false |
| `--no-bruteforce` | Disable bruteforce | false |

## Pipeline Examples

```bash
# With subfinder + httpx
subfinder -d example.com | httpx -silent | jsfinder -l - -o js_files.txt

# Feed to nuclei
jsfinder -u https://example.com -o js.txt && nuclei -l js.txt -t exposures/

# Feed to ghost (secret scanner)
jsfinder -u https://example.com -o js.txt && cat js.txt | ghost -l -
```

## How It Works

1. **Crawler**: Fetches the target page, extracts `<script src>` tags, and recursively follows same-domain links
2. **Wayback Machine**: Queries the CDX API for `*.js` files archived for the domain
3. **Bruteforce**: Checks ~100 common JS paths like `/js/app.js`, `/static/bundle.js`, `/dist/main.js`

All three methods run concurrently and results are deduplicated in real-time.

## License

MIT
