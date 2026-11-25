# Hakrawler

Fast golang web crawler for gathering URLs and JavaScript file locations. This is basically a simple implementation of the awesome Gocolly library.

## Example usages

Single URL:

```
echo https://google.com | hakrawler
```

Multiple URLs:

```
cat urls.txt | hakrawler
```

Timeout for each line of stdin after 5 seconds:

```
cat urls.txt | hakrawler -timeout 5
```

Send all requests through a proxy:

```
cat urls.txt | hakrawler -proxy http://localhost:8080
```

Include subdomains:

```
echo https://google.com | hakrawler -subs
```

## Noise reduction and triage

Use `-smart` to normalize URLs, deduplicate equivalent parameter fingerprints,
and print the most sensitive endpoints first:

```
echo https://target.example | hakrawler -smart -hide-static -s
```

For machine-readable output and complete raw-URL traceability:

```
echo https://target.example | hakrawler -smart -hide-static -json -aliases \
  -trace-file hakrawler-trace.jsonl
```

You can also re-process an already-crawled URL list without sending requests:

```
cat urls.txt | hakrawler -filter -smart -hide-static -sensitivity
```

`-filter` accepts bare URL lists, legacy `[source] URL` / `[where] [source] URL`
text output, and hakrawler JSON lines.

Normalization lowercases the scheme/host, removes fragments and default ports,
resolves dot segments, sorts query parameters, and removes common tracking
parameters. The parameter fingerprint additionally ignores parameter values and
generalizes numeric, UUID, hash, and common resource-identifier path segments.
SPA-style `#/route?param=...` fragments are included in the fingerprint; plain
in-page anchors are not.
The original crawled URL remains in the historical `URL` JSON field; opt-in
`normalized_url`, `fingerprint`, `sensitivity`, `static`, `reasons`, `aliases`,
and `-trace-file` records provide the reversible mapping back to every raw URL.

Without the new flags, the original streaming text/JSON formats and exact `-u`
behavior remain unchanged. The three-site manual-screening regression suite lives
under `testdata/acceptance/` and runs with `go test ./...`.

> Note: a common issue is that the tool returns no URLs. This usually happens when a domain is specified (https://example.com), but it redirects to a subdomain (https://www.example.com). The subdomain is not included in the scope, so the no URLs are printed. In order to overcome this, either specify the final URL in the redirect chain or use the `-subs` option to include subdomains.

## Example tool chain

Get all subdomains of google, find the ones that respond to http(s), crawl them all.

```
echo google.com | haktrails subdomains | httpx | hakrawler
```

## Installation

### Normal Install

First, you'll need to [install go](https://golang.org/doc/install).

Then run this command to download + compile hakrawler:
```
go install github.com/hakluke/hakrawler@latest
```

You can now run `~/go/bin/hakrawler`. If you'd like to just run `hakrawler` without the full path, you'll need to `export PATH="~/go/bin/:$PATH"`. You can also add this line to your `~/.bashrc` file if you'd like this to persist.

### Docker Install (from dockerhub)

```
echo https://www.google.com | docker run --rm -i hakluke/hakrawler:v2 -subs
```

### Local Docker Install

It's much easier to use the dockerhub method above, but if you'd prefer to run it locally:

```
git clone https://github.com/hakluke/hakrawler
cd hakrawler
sudo docker build -t hakluke/hakrawler .
sudo docker run --rm -i hakluke/hakrawler --help
```
### Kali Linux: Using apt

Note: This will install an older version of hakrawler without all the features, and it may be buggy. I recommend using one of the other methods.

```sh
sudo apt install hakrawler
```

Then, to run hakrawler:

```
echo https://www.google.com | docker run --rm -i hakluke/hakrawler -subs
```

## Command-line options
```
Usage of hakrawler:
  -aliases
    	Include all distinct raw URLs in each deduplicated JSON record.
  -d int
    	Depth to crawl. (default 2)
  -dedupe
    	Alias for -dedupe-params.
  -dedupe-params
    	Normalize URLs and deduplicate equivalent host/path/parameter fingerprints.
  -dr
    	Disable following HTTP redirects.
  -exclude-static
    	Alias for -hide-static.
  -filter
    	Treat stdin as an already-crawled URL list and do not perform network requests.
  -fingerprint
    	Alias for -dedupe-params.
  -h string
    	Custom headers separated by two semi-colons. E.g. -h "Cookie: foo=bar;;Referer: http://example.com/"
  -hide-static
    	Suppress classified static assets such as CSS, images, fonts, media, and scripts.
  -i	Only crawl inside path
  -insecure
    	Disable TLS verification.
  -json
    	Output as JSON.
  -normalize
    	Include normalization and fingerprint metadata in JSON or trace output.
  -normalize-url
    	Alias for -normalize.
  -proxy string
    	Proxy URL. E.g. -proxy http://127.0.0.1:8080
  -s	Show the source of URL based on where it was found. E.g. href, form, script, etc.
  -sensitivity
    	Prefix plain-text output with sensitivity label and score.
  -size int
    	Page size limit, in KB. (default -1)
  -smart
    	Shorthand for -dedupe-params and -sort=sensitivity.
  -sort string
    	Sort output; supported value: "sensitivity".
  -sort-by string
    	Alias for -sort; supported value: "sensitivity".
  -sort-sensitive
    	Alias for -sort=sensitivity.
  -subs
    	Include subdomains for crawling.
  -t int
    	Number of threads to utilise. (default 8)
  -timeout int
    	Maximum time to crawl each URL from stdin, in seconds. (default -1)
  -trace-file string
    	Write one JSON trace record per crawled URL to the specified file.
  -u	Show only unique urls.
  -w	Show at which link the URL is found.
```

---

Built by [hakluke](https://hakluke.com) (Luke Stephens), founder and CEO of [Haksec](https://haksec.io), a group of cybersecurity companies:

- [HackerContent](https://hackercontent.com) — content marketing and social media for cybersecurity companies
- [Ironbark Cyber](https://ironbarkcyber.com) — cybersecurity consultancy for penetration testing, social engineering and OSINT
- [TRIAGERS™](https://triagers.com) — outsourced bug bounty and vulnerability disclosure (VDP) triage

I write about hacking and the security industry at [hakluke.com](https://hakluke.com).
