package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"
)

type Result struct {
	Source string
	URL    string
	Where  string
}

var headers map[string]string

// Thread safe map
var sm sync.Map

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func runCLI(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("hakrawler", flag.ContinueOnError)
	flags.SetOutput(stderr)

	inside := flags.Bool("i", false, "Only crawl inside path")
	threads := flags.Int("t", 8, "Number of threads to utilise.")
	depth := flags.Int("d", 2, "Depth to crawl.")
	maxSize := flags.Int("size", -1, "Page size limit, in KB.")
	insecure := flags.Bool("insecure", false, "Disable TLS verification.")
	subsInScope := flags.Bool("subs", false, "Include subdomains for crawling.")
	showJson := flags.Bool("json", false, "Output as JSON.")
	showSource := flags.Bool("s", false, "Show the source of URL based on where it was found. E.g. href, form, script, etc.")
	showWhere := flags.Bool("w", false, "Show at which link the URL is found.")
	rawHeaders := flags.String("h", "", "Custom headers separated by two semi-colons. E.g. -h \"Cookie: foo=bar;;Referer: http://example.com/\" ")
	unique := flags.Bool("u", false, "Show only unique urls.")
	proxy := flags.String("proxy", "", "Proxy URL. E.g. -proxy http://127.0.0.1:8080")
	timeout := flags.Int("timeout", -1, "Maximum time to crawl each URL from stdin, in seconds.")
	disableRedirects := flags.Bool("dr", false, "Disable following HTTP redirects.")
	dedupeParams := flags.Bool("dedupe-params", false, "Normalize URLs and deduplicate equivalent host/path/parameter fingerprints.")
	dedupeAlias := flags.Bool("dedupe", false, "Alias for -dedupe-params.")
	fingerprintAlias := flags.Bool("fingerprint", false, "Alias for -dedupe-params.")
	normalizeURL := flags.Bool("normalize", false, "Include normalization and fingerprint metadata in JSON or trace output.")
	normalizeURLAlias := flags.Bool("normalize-url", false, "Alias for -normalize.")
	sortMode := flags.String("sort", "", `Sort output; supported value: "sensitivity".`)
	sortBy := flags.String("sort-by", "", `Alias for -sort; supported value: "sensitivity".`)
	sortSensitiveFlag := flags.Bool("sort-sensitive", false, "Alias for -sort=sensitivity.")
	hideStatic := flags.Bool("hide-static", false, "Suppress classified static assets such as CSS, images, fonts, media, and scripts.")
	excludeStaticAlias := flags.Bool("exclude-static", false, "Alias for -hide-static.")
	traceFile := flags.String("trace-file", "", "Write one JSON trace record per crawled URL to the specified file.")
	includeAliases := flags.Bool("aliases", false, "Include all distinct raw URLs in each deduplicated JSON record.")
	showSensitivity := flags.Bool("sensitivity", false, "Prefix plain-text output with sensitivity label and score.")
	smart := flags.Bool("smart", false, "Shorthand for -dedupe-params and -sort=sensitivity.")
	filterURLs := flags.Bool("filter", false, "Treat stdin as an already-crawled URL list and do not perform network requests.")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *dedupeAlias || *fingerprintAlias {
		*dedupeParams = true
	}
	if *normalizeURLAlias {
		*normalizeURL = true
	}
	if *excludeStaticAlias {
		*hideStatic = true
	}
	if *sortSensitiveFlag && *sortMode == "" && *sortBy == "" {
		*sortMode = "sensitivity"
	}

	if *smart {
		*dedupeParams = true
		if *sortMode == "" && *sortBy == "" {
			*sortMode = "sensitivity"
		}
	}
	if *sortMode == "" && *sortBy != "" {
		*sortMode = *sortBy
	}
	sortSensitive := *sortMode == "sensitivity"
	if *sortMode != "" && !sortSensitive {
		fmt.Fprintln(stderr, `Error: unsupported -sort value; only "sensitivity" is supported.`)
		return 2
	}

	sm = sync.Map{}

	if *proxy != "" {
		os.Setenv("PROXY", *proxy)
	}
	proxyURL, _ := url.Parse(os.Getenv("PROXY"))

	// Convert the headers input to a usable map (or die trying)
	err := parseHeaders(*rawHeaders)
	if err != nil {
		fmt.Fprintln(stderr, "Error parsing headers:", err)
		return 1
	}

	// Check for stdin input
	if file, ok := stdin.(*os.File); ok {
		stat, _ := file.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			fmt.Fprintln(stderr, "No urls detected. Hint: cat urls.txt | hakrawler")
			return 1
		}
	}

	var traceEncoder *json.Encoder
	if *traceFile != "" {
		traceHandle, traceErr := os.Create(*traceFile)
		if traceErr != nil {
			fmt.Fprintln(stderr, "Error creating trace file:", traceErr)
			return 1
		}
		defer traceHandle.Close()
		traceEncoder = json.NewEncoder(traceHandle)
	}

	results := make(chan Result, *threads)
	if *filterURLs {
		go func() {
			scanner := bufio.NewScanner(stdin)
			for scanner.Scan() {
				rawLine := strings.TrimSpace(scanner.Text())
				if rawLine == "" {
					continue
				}
				result := parseFilterLine(rawLine)
				if !*showWhere {
					result.Where = ""
				}
				if result.Source == "" {
					result.Source = "stdin"
				}
				results <- result
			}
			if err := scanner.Err(); err != nil {
				fmt.Fprintln(stderr, "reading standard input:", err)
			}
			close(results)
		}()
	} else {
		go func() {
			// get each line of stdin, push it to the work channel
			s := bufio.NewScanner(stdin)
			for s.Scan() {
				seedURL := s.Text()
				hostname, err := extractHostname(seedURL)
				if err != nil {
					log.Println("Error parsing URL:", err)
					continue
				}

				allowed_domains := []string{hostname}
				// if "Host" header is set, append it to allowed domains
				if headers != nil {
					if val, ok := headers["Host"]; ok {
						allowed_domains = append(allowed_domains, val)
					}
				}

				// Instantiate default collector
				c := colly.NewCollector(
					// default user agent header
					colly.UserAgent("Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"),
					// set custom headers
					colly.Headers(headers),
					// limit crawling to the domain of the specified URL
					colly.AllowedDomains(allowed_domains...),
					// set MaxDepth to the specified depth
					colly.MaxDepth(*depth),
					// specify Async for threading
					colly.Async(true),
				)

				// set a page size limit
				if *maxSize != -1 {
					c.MaxBodySize = *maxSize * 1024
				}

				// if -subs is present, use regex to filter out subdomains in scope.
				if *subsInScope {
					c.AllowedDomains = nil
					c.URLFilters = []*regexp.Regexp{regexp.MustCompile(".*(\\.|\\/\\/)" + strings.ReplaceAll(hostname, ".", "\\.") + "((#|\\/|\\?).*)?")}
				}

				// If `-dr` flag provided, do not follow HTTP redirects.
				if *disableRedirects {
					c.SetRedirectHandler(func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					})
				}
				// Set parallelism
				c.Limit(&colly.LimitRule{DomainGlob: "*", Parallelism: *threads})

				// Print every href found, and visit it
				c.OnHTML("a[href]", func(e *colly.HTMLElement) {
					link := e.Attr("href")
					abs_link := e.Request.AbsoluteURL(link)
					if strings.Contains(abs_link, seedURL) || !*inside {

						printResultEvent(link, "href", *showSource, *showWhere, *showJson, results, e)
						e.Request.Visit(link)
					}
				})

				// find and print all the JavaScript files
				c.OnHTML("script[src]", func(e *colly.HTMLElement) {
					printResultEvent(e.Attr("src"), "script", *showSource, *showWhere, *showJson, results, e)
				})

				// find and print all the form action URLs
				c.OnHTML("form[action]", func(e *colly.HTMLElement) {
					printResultEvent(e.Attr("action"), "form", *showSource, *showWhere, *showJson, results, e)
				})

				// add the custom headers
				if headers != nil {
					c.OnRequest(func(r *colly.Request) {
						for header, value := range headers {
							r.Headers.Set(header, value)
						}
					})
				}

				if *proxy != "" {
					// Skip TLS verification for proxy, if -insecure specified
					c.WithTransport(&http.Transport{
						Proxy:           http.ProxyURL(proxyURL),
						TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure},
					})
				} else {
					// Skip TLS verification if -insecure flag is present
					c.WithTransport(&http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure},
					})
				}

				if *timeout == -1 {
					// Start scraping
					c.Visit(seedURL)
					// Wait until threads are finished
					c.Wait()
				} else {
					finished := make(chan int, 1)

					go func() {
						// Start scraping
						c.Visit(seedURL)
						// Wait until threads are finished
						c.Wait()
						finished <- 0
					}()

					select {
					case _ = <-finished: // the crawling finished before the timeout
						close(finished)
						continue
					case <-time.After(time.Duration(*timeout) * time.Second): // timeout reached
						log.Println("[timeout] " + seedURL)
						continue

					}
				}

			}
			if err := s.Err(); err != nil {
				fmt.Fprintln(stderr, "reading standard input:", err)
			}
			close(results)
		}()
	}

	w := bufio.NewWriter(stdout)
	defer w.Flush()

	enhanced := *dedupeParams || *normalizeURL || sortSensitive || *hideStatic ||
		traceEncoder != nil || *includeAliases || *showSensitivity

	if !enhanced {
		urlsFound := false
		if *unique {
			for res := range results {
				line := renderResult(res, *showSource, *showWhere, *showJson)
				if isUnique(line) {
					fmt.Fprintln(w, line)
					urlsFound = true
				}
			}
		} else {
			for res := range results {
				fmt.Fprintln(w, renderResult(res, *showSource, *showWhere, *showJson))
				urlsFound = true
			}
		}

		if !urlsFound {
			printNoURLsWarning(stderr)
		}
		return 0
	}

	catalog := NewCatalog(*dedupeParams)
	receivedResults := false
	printedResults := false

	for res := range results {
		receivedResults = true
		enriched := Enrich(res)
		analysis := enriched.URLAnalysis
		if traceEncoder != nil {
			_ = traceEncoder.Encode(TraceRecord{
				RawURL:      res.URL,
				Source:      res.Source,
				Where:       res.Where,
				URLAnalysis: analysis,
			})
		}

		if *hideStatic && analysis.Static {
			continue
		}

		if !*dedupeParams && *unique {
			legacyLine := renderResult(res, *showSource, *showWhere, *showJson)
			if !isUnique(legacyLine) {
				continue
			}
		}

		catalog.Add(res)
	}

	items := catalog.Items(sortSensitive, *includeAliases)
	for _, item := range items {
		if *showJson {
			encoded, _ := json.Marshal(item)
			fmt.Fprintln(w, string(encoded))
		} else {
			line := renderResult(item.Result, *showSource, *showWhere, false)
			if *normalizeURL && item.NormalizedURL != "" {
				line += " => " + item.NormalizedURL
				if item.Fingerprint != "" {
					line += " (" + item.Fingerprint + ")"
				}
			}
			if *showSensitivity {
				label := item.Sensitivity
				if label == "" {
					label = sensitivityLabel(item.SensitivityScore)
				}
				line = fmt.Sprintf("[%s:%d] %s", label, item.SensitivityScore, line)
			}
			fmt.Fprintln(w, line)
		}
		printedResults = true
	}

	if !receivedResults {
		printNoURLsWarning(stderr)
	} else if !printedResults {
		fmt.Fprintln(stderr, "URLs were crawled, but all results were filtered or deduplicated out.")
	}
	return 0
}

// parseHeaders does validation of headers input and saves it to a formatted map.
func parseHeaders(rawHeaders string) error {
	headers = nil
	if rawHeaders != "" {
		if !strings.Contains(rawHeaders, ":") {
			return errors.New("headers flag not formatted properly (no colon to separate header and value)")
		}

		headers = make(map[string]string)
		rawHeaders := strings.Split(rawHeaders, ";;")
		for _, header := range rawHeaders {
			var parts []string
			if strings.Contains(header, ": ") {
				parts = strings.SplitN(header, ": ", 2)
			} else if strings.Contains(header, ":") {
				parts = strings.SplitN(header, ":", 2)
			} else {
				continue
			}
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return nil
}

// extractHostname() extracts the hostname from a URL and returns it
func extractHostname(urlString string) (string, error) {
	u, err := url.Parse(urlString)
	if err != nil || !u.IsAbs() {
		return "", errors.New("Input must be a valid absolute URL")
	}

	return u.Hostname(), nil
}

// printResult preserves the historical string-channel helper for compatibility.
// The normal CLI path uses printResultEvent so rendering stays in one place.
func printResult(link string, sourceName string, showSource bool, showWhere bool, showJson bool, results chan string, e *colly.HTMLElement) {
	result := e.Request.AbsoluteURL(link)
	whereURL := e.Request.URL.String()
	if result != "" {
		if showJson {
			where := ""
			if showWhere {
				where = whereURL
			}
			bytes, _ := json.Marshal(Result{Source: sourceName, URL: result, Where: where})
			result = string(bytes)
		} else if showSource {
			result = "[" + sourceName + "] " + result
		}

		if showWhere && !showJson {
			result = "[" + whereURL + "] " + result
		}

		defer func() {
			if err := recover(); err != nil {
				return
			}
		}()
		results <- result
	}
}

// printResultEvent constructs a structured result and sends it to the results chan.
// The boolean parameters remain part of the call shape used by HTML handlers;
// rendering is handled by renderResult so legacy and enhanced output stay in sync.
func printResultEvent(link string, sourceName string, showSource bool, showWhere bool, showJson bool, results chan Result, e *colly.HTMLElement) {
	foundURL := e.Request.AbsoluteURL(link)
	whereURL := e.Request.URL.String()
	if foundURL != "" {
		result := Result{Source: sourceName, URL: foundURL}
		if showWhere {
			result.Where = whereURL
		}
		// If timeout occurs before goroutines are finished, recover from panic that may occur when attempting writing to results to closed results channel
		defer func() {
			if err := recover(); err != nil {
				return
			}
		}()
		results <- result
	}
}

// renderResult preserves hakrawler's historical plain-text and JSON formats.
func renderResult(result Result, showSource bool, showWhere bool, showJSON bool) string {
	if showJSON {
		encoded, _ := json.Marshal(result)
		return string(encoded)
	}

	line := result.URL
	if showSource {
		line = "[" + result.Source + "] " + line
	}
	if showWhere {
		line = "[" + result.Where + "] " + line
	}
	return line
}

// parseFilterLine accepts raw URL lists as well as hakrawler's JSON and
// bracket-prefixed text output.
func parseFilterLine(line string) Result {
	if strings.HasPrefix(line, "{") {
		var result Result
		if err := json.Unmarshal([]byte(line), &result); err == nil && result.URL != "" {
			return result
		}
	}

	rest := line
	prefixes := make([]string, 0, 2)
	for strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "] ")
		if end <= 1 {
			break
		}
		prefixes = append(prefixes, rest[1:end])
		rest = rest[end+2:]
	}

	result := Result{URL: strings.TrimSpace(rest)}
	switch len(prefixes) {
	case 1:
		if parsed, err := url.Parse(prefixes[0]); err == nil && parsed.IsAbs() {
			result.Where = prefixes[0]
		} else {
			result.Source = prefixes[0]
		}
	case 2:
		result.Where = prefixes[0]
		result.Source = prefixes[1]
	}
	if result.URL == "" {
		result.URL = line
	}
	return result
}

func printNoURLsWarning(writer io.Writer) {
	fmt.Fprintln(writer, "No URLs were found. This usually happens when a domain is specified (https://example.com), but it redirects to a subdomain (https://www.example.com). The subdomain is not included in the scope, so the no URLs are printed. In order to overcome this, either specify the final URL in the redirect chain or use the -subs option to include subdomains.")
}

// returns whether the supplied url is unique or not
func isUnique(url string) bool {
	_, present := sm.Load(url)
	if present {
		return false
	}
	sm.Store(url, true)
	return true
}
