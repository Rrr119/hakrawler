package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

// URLAnalysis contains reversible normalization and prioritization metadata.
// The original crawled URL remains in Result.URL; these fields never replace it.
type URLAnalysis struct {
	NormalizedURL        string   `json:"normalized_url,omitempty"`
	Fingerprint          string   `json:"fingerprint,omitempty"`
	FingerprintSignature string   `json:"fingerprint_signature,omitempty"`
	SensitivityScore     int      `json:"sensitivity_score,omitempty"`
	Sensitivity          string   `json:"sensitivity,omitempty"`
	Static               bool     `json:"static,omitempty"`
	Reasons              []string `json:"reasons,omitempty"`
}

// EnrichedResult is the additive JSON representation used by opt-in processing.
// Result's historical JSON fields are intentionally left unchanged.
type EnrichedResult struct {
	Result
	URLAnalysis
	OccurrenceCount int      `json:"occurrence_count,omitempty"`
	Aliases         []string `json:"aliases,omitempty"`
}

// TraceRecord preserves every crawled raw URL together with its reversible
// normalization and fingerprint metadata.
type TraceRecord struct {
	RawURL string `json:"raw_url"`
	Source string `json:"source,omitempty"`
	Where  string `json:"where,omitempty"`
	URLAnalysis
}

// NormalizeOptions controls conservative URL canonicalization.
type NormalizeOptions struct {
	RemoveFragment bool
	RemoveTracking bool
	CleanPath      bool
	SortQuery      bool
}

// DefaultNormalizeOptions returns the canonicalization rules used by hakrawler.
func DefaultNormalizeOptions() NormalizeOptions {
	return NormalizeOptions{
		RemoveFragment: true,
		RemoveTracking: true,
		CleanPath:      true,
		SortQuery:      true,
	}
}

var trackingParamNames = map[string]bool{
	"fbclid":       true,
	"gclid":        true,
	"msclkid":      true,
	"yclid":        true,
	"ttclid":       true,
	"twclid":       true,
	"igshid":       true,
	"mc_cid":       true,
	"mc_eid":       true,
	"mkt_tok":      true,
	"spm":          true,
	"ref":          true,
	"referer":      true,
	"referrer":     true,
	"_ga":          true,
	"_gl":          true,
	"cachebuster":  true,
	"cache_buster": true,
	"cb":           true,
	"nocache":      true,
	"_":            true,
}

var staticExtensions = map[string]bool{
	".css":   true,
	".eot":   true,
	".otf":   true,
	".ttf":   true,
	".woff":  true,
	".woff2": true,
	".avif":  true,
	".bmp":   true,
	".gif":   true,
	".ico":   true,
	".jpeg":  true,
	".jpg":   true,
	".png":   true,
	".svg":   true,
	".tif":   true,
	".tiff":  true,
	".webp":  true,
	".mp3":   true,
	".mp4":   true,
	".ogg":   true,
	".wav":   true,
	".webm":  true,
	".avi":   true,
	".mov":   true,
	".mkv":   true,
}

var scriptExtensions = map[string]bool{
	".js":   true,
	".mjs":  true,
	".cjs":  true,
	".map":  true,
	".wasm": true,
}

var sensitiveSuffixScores = []struct {
	suffix string
	score  int
	reason string
}{
	{".env", 95, "environment/secrets file"},
	{".pem", 95, "private key/certificate material"},
	{".key", 95, "private key file"},
	{".p12", 90, "PKCS#12 key store"},
	{".pfx", 90, "PFX key store"},
	{".jks", 90, "Java key store"},
	{".keystore", 90, "key store"},
	{".htpasswd", 90, "HTTP password file"},
	{"id_rsa", 95, "SSH private key"},
	{".sql", 90, "SQL database dump"},
	{".sqlite", 80, "SQLite database"},
	{".sqlite3", 80, "SQLite database"},
	{".mdb", 80, "database file"},
	{".bak", 80, "backup file"},
	{".backup", 80, "backup file"},
	{".old", 70, "old/backup file"},
	{".orig", 70, "original/backup file"},
	{".save", 70, "saved backup file"},
	{".swp", 75, "editor swap file"},
	{".swo", 75, "editor swap file"},
	{"~", 65, "editor backup file"},
	{".log", 70, "log file"},
	{".git/config", 90, "Git configuration exposed"},
	{".git/index", 85, "Git index exposed"},
	{".svn/entries", 85, "SVN metadata exposed"},
	{"/.git/", 85, "Git metadata exposed"},
	{"/.svn/", 80, "SVN metadata exposed"},
}

var uuidSegmentPattern = mustPattern(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var hexSegmentPattern = mustPattern(`^[0-9a-fA-F]{16,}$`)
var trailingNumericIDPattern = mustPattern(`[-_.][0-9]+$`)
var trailingHashIDPattern = mustPattern(`[-_.][0-9a-fA-F]{8,}$`)

var dynamicValuePrefixes = map[string]bool{
	"author": true, "authors": true,
	"user": true, "users": true,
	"account": true, "accounts": true,
	"profile": true, "profiles": true,
	"product": true, "products": true,
	"item": true, "items": true,
	"post": true, "posts": true,
	"blog": true, "article": true, "articles": true,
	"book": true, "books": true, "catalogue": true, "catalog": true,
	"tag": true, "tags": true,
	"category": true, "categories": true,
	"order": true, "orders": true,
}

func mustPattern(pattern string) (re *regexp.Regexp) {
	return regexp.MustCompile(pattern)
}

// NormalizeURL returns a canonical equivalent of raw without touching the raw
// string retained by callers.
func NormalizeURL(raw string) (string, error) {
	u, err := canonicalURL(raw, DefaultNormalizeOptions())
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// FingerprintURL is a convenience alias for ParameterFingerprint.
func FingerprintURL(raw string) string {
	fingerprint, _ := ParameterFingerprint(raw)
	return fingerprint
}

// ParameterFingerprint returns a stable hash for host, generalized path shape,
// and sorted query parameter names. Parameter values are intentionally ignored.
func ParameterFingerprint(raw string) (string, error) {
	signature, err := FingerprintSignature(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(signature))
	return "fp1_" + hex.EncodeToString(sum[:])[:20], nil
}

// FingerprintSignature returns the human-readable string that is hashed into
// ParameterFingerprint.
func FingerprintSignature(raw string) (string, error) {
	parsedRaw, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	u, err := canonicalURL(raw, DefaultNormalizeOptions())
	if err != nil {
		return "", err
	}

	static := hasStaticExtension(u.Path)
	values, _ := url.ParseQuery(u.RawQuery)
	parameters := make([]string, 0, len(values))
	for name := range values {
		if isFingerprintIgnoredParam(name, static) {
			continue
		}
		parameters = append(parameters, name)
	}
	sort.Strings(parameters)

	signaturePath := fingerprintPath(u.Path)
	fragmentPath, fragmentParameters := fragmentRoute(parsedRaw, static)
	return strings.Join([]string{
		u.Scheme,
		u.Host,
		signaturePath,
		strings.Join(parameters, ","),
		fragmentPath,
		strings.Join(fragmentParameters, ","),
	}, "|"), nil
}

// fragmentRoute extracts SPA-style hash routes such as #/users/1?tab=a. Plain
// in-page anchors are ignored because they do not identify a route or parameters.
func fragmentRoute(u *url.URL, static bool) (string, []string) {
	if u == nil || u.Fragment == "" {
		return "", nil
	}
	fragment := strings.TrimPrefix(u.Fragment, "!")
	if !strings.HasPrefix(fragment, "/") && !strings.HasPrefix(fragment, "?") {
		return "", nil
	}

	fragmentURL, err := url.Parse(fragment)
	if err != nil {
		return "", nil
	}
	values, _ := url.ParseQuery(fragmentURL.RawQuery)
	parameters := make([]string, 0, len(values))
	for name := range values {
		if isFingerprintIgnoredParam(name, static) {
			continue
		}
		parameters = append(parameters, name)
	}
	sort.Strings(parameters)
	return fingerprintPath(fragmentURL.Path), parameters
}

// AnalyzeURL computes normalization, fingerprint, static classification, and
// sensitivity metadata. It never discards raw; parse failures get a raw-based
// fingerprint so the caller can still preserve the URL.
func AnalyzeURL(raw string) URLAnalysis {
	normalized, normErr := NormalizeURL(raw)
	fingerprint, fpErr := ParameterFingerprint(raw)
	signature, _ := FingerprintSignature(raw)
	if normErr != nil || fpErr != nil {
		sum := sha256.Sum256([]byte(raw))
		return URLAnalysis{
			NormalizedURL:        "",
			Fingerprint:          "raw1_" + hex.EncodeToString(sum[:])[:20],
			FingerprintSignature: "raw|" + raw,
			SensitivityScore:     0,
			Sensitivity:          SensitivityInfo,
			Static:               false,
			Reasons:              []string{"unparseable-url-preserved-raw"},
		}
	}

	u, _ := url.Parse(raw)
	score, static, reasons := scoreSensitivity(u)
	return URLAnalysis{
		NormalizedURL:        normalized,
		Fingerprint:          fingerprint,
		FingerprintSignature: signature,
		SensitivityScore:     score,
		Sensitivity:          sensitivityLabel(score),
		Static:               static,
		Reasons:              reasons,
	}
}

// Enrich attaches analysis to an existing crawled result.
func Enrich(result Result) EnrichedResult {
	analysis := AnalyzeURL(result.URL)
	if strings.EqualFold(result.Source, "script") {
		analysis.Static = true
		if analysis.SensitivityScore < 15 {
			analysis.SensitivityScore = 15
			analysis.Sensitivity = SensitivityLow
			analysis.Reasons = append(analysis.Reasons, "script source asset")
		}
	}
	return EnrichedResult{
		Result:      result,
		URLAnalysis: analysis,
	}
}

const (
	SensitivityCritical = "critical"
	SensitivityHigh     = "high"
	SensitivityMedium   = "medium"
	SensitivityLow      = "low"
	SensitivityInfo     = "info"
)

func sensitivityLabel(score int) string {
	switch {
	case score >= 85:
		return SensitivityCritical
	case score >= 65:
		return SensitivityHigh
	case score >= 45:
		return SensitivityMedium
	case score >= 20:
		return SensitivityLow
	default:
		return SensitivityInfo
	}
}

// SortBySensitivity sorts enriched results from most to least sensitive. Ties
// are ordered by raw URL to keep output deterministic.
func SortBySensitivity(items []EnrichedResult) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].SensitivityScore != items[j].SensitivityScore {
			return items[i].SensitivityScore > items[j].SensitivityScore
		}
		return items[i].URL < items[j].URL
	})
}

// Catalog groups crawled results by parameter fingerprint.
type Catalog struct {
	mu     sync.Mutex
	dedupe bool
	groups map[string]*catalogGroup
	order  []string
}

type catalogGroup struct {
	item    EnrichedResult
	aliases map[string]struct{}
}

// NewCatalog creates a catalog. When dedupe is false every Add gets a unique
// internal key and order is still useful for collecting/sorting output.
func NewCatalog(dedupe bool) *Catalog {
	return &Catalog{
		dedupe: dedupe,
		groups: make(map[string]*catalogGroup),
	}
}

// Add records one result and returns its current enriched representative.
func (c *Catalog) Add(result Result) EnrichedResult {
	enriched := Enrich(result)
	c.mu.Lock()
	defer c.mu.Unlock()

	key := enriched.Fingerprint
	if !c.dedupe {
		key = key + "|" + strconv.Itoa(len(c.order)) + "|" + result.URL
	}

	if group, ok := c.groups[key]; ok {
		group.item.OccurrenceCount++
		group.aliases[result.URL] = struct{}{}
		return group.item
	}

	enriched.OccurrenceCount = 1
	group := &catalogGroup{item: enriched, aliases: map[string]struct{}{result.URL: {}}}
	group.item.Aliases = []string{result.URL}
	c.groups[key] = group
	c.order = append(c.order, key)
	return enriched
}

// Items returns representatives in first-seen order, optionally sorted by
// sensitivity. Aliases are populated only when includeAliases is true.
func (c *Catalog) Items(sortSensitive bool, includeAliases bool) []EnrichedResult {
	c.mu.Lock()
	defer c.mu.Unlock()

	items := make([]EnrichedResult, 0, len(c.order))
	for _, key := range c.order {
		group := c.groups[key]
		item := group.item
		if includeAliases {
			aliases := make([]string, 0, len(group.aliases))
			for alias := range group.aliases {
				aliases = append(aliases, alias)
			}
			sort.Strings(aliases)
			item.Aliases = aliases
		} else {
			item.Aliases = nil
		}
		items = append(items, item)
	}
	if sortSensitive {
		SortBySensitivity(items)
	}
	return items
}

func canonicalURL(raw string, options NormalizeOptions) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if !u.IsAbs() || u.Host == "" {
		return nil, &url.Error{Op: "normalize", URL: raw, Err: errAbsoluteURLRequired}
	}

	u.Scheme = strings.ToLower(u.Scheme)
	canonicalHost(u)

	if options.CleanPath {
		cleanPath(u)
	}

	if options.RemoveFragment {
		u.Fragment = ""
		u.RawFragment = ""
	}

	if options.SortQuery {
		values, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return nil, err
		}
		if options.RemoveTracking {
			static := hasStaticExtension(u.Path)
			for name := range values {
				if isTrackingParam(name) || isCacheParam(name, static) {
					delete(values, name)
				}
			}
		}
		u.RawQuery = values.Encode()
	}

	return u, nil
}

var errAbsoluteURLRequired = stringError("absolute URL required")

type stringError string

func (e stringError) Error() string { return string(e) }

func canonicalHost(u *url.URL) {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	if port == "" {
		if strings.Contains(host, ":") {
			u.Host = "[" + host + "]"
		} else {
			u.Host = host
		}
		return
	}
	u.Host = net.JoinHostPort(host, port)
}

func cleanPath(u *url.URL) {
	rawPath := u.Path
	if rawPath == "" {
		u.Path = "/"
		u.RawPath = ""
		return
	}

	trailingSlash := strings.HasSuffix(rawPath, "/") && rawPath != "/"
	cleaned := path.Clean(rawPath)
	if cleaned == "." || cleaned == "" {
		cleaned = "/"
	}
	if trailingSlash && cleaned != "/" {
		cleaned += "/"
	}
	u.Path = cleaned
	u.RawPath = ""
}

func isTrackingParam(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "utm_") {
		return true
	}
	return trackingParamNames[lower]
}

func isCacheParam(name string, static bool) bool {
	lower := strings.ToLower(name)
	if trackingParamNames[lower] {
		return true
	}
	if lower == "_" || lower == "cb" || lower == "cachebuster" || lower == "cache_buster" || lower == "nocache" {
		return true
	}
	return static && (lower == "v" || lower == "ver" || lower == "version")
}

func isFingerprintIgnoredParam(name string, static bool) bool {
	return isTrackingParam(name) || isCacheParam(name, static)
}

func hasStaticExtension(urlPath string) bool {
	ext := strings.ToLower(path.Ext(urlPath))
	return staticExtensions[ext] || scriptExtensions[ext]
}

func fingerprintPath(urlPath string) string {
	if urlPath == "" {
		return "/"
	}
	segments := strings.Split(urlPath, "/")
	previous := ""
	for index, segment := range segments {
		if segment == "" {
			continue
		}
		extension := path.Ext(segment)
		stem := strings.TrimSuffix(segment, extension)
		lowerSegment := strings.ToLower(segment)
		generalized := false
		switch {
		case isGenericPathValue(stem):
			segments[index] = ":id" + extension
			generalized = true
		case dynamicValuePrefixes[previous]:
			segments[index] = ":value" + extension
			generalized = true
		}
		if generalized {
			previous = ""
		} else {
			previous = lowerSegment
		}
	}
	return strings.Join(segments, "/")
}

func isGenericPathValue(value string) bool {
	if value == "" {
		return false
	}
	if _, err := strconv.ParseInt(value, 10, 64); err == nil {
		return true
	}
	if uuidSegmentPattern.MatchString(value) {
		return true
	}
	if hexSegmentPattern.MatchString(value) {
		return true
	}
	if trailingNumericIDPattern.MatchString(value) || trailingHashIDPattern.MatchString(value) {
		return true
	}
	return false
}

func scoreSensitivity(u *url.URL) (int, bool, []string) {
	if u == nil {
		return 0, false, nil
	}

	best := 0
	reasonSet := make(map[string]bool)
	reasons := make([]string, 0)
	raise := func(score int, reason string) {
		if !reasonSet[reason] {
			reasonSet[reason] = true
			reasons = append(reasons, reason)
		}
		if score > best {
			best = score
		}
	}

	lowerPath := strings.ToLower(u.Path)
	lowerBase := strings.ToLower(path.Base(lowerPath))
	if lowerBase == ".env" || strings.HasPrefix(lowerBase, ".env.") {
		raise(95, "environment/secrets file")
	}
	if strings.Contains(lowerPath, "/.git/") {
		raise(85, "Git metadata exposed")
	}
	if strings.Contains(lowerPath, "/.svn/") {
		raise(80, "SVN metadata exposed")
	}
	for _, rule := range sensitiveSuffixScores {
		if strings.HasSuffix(lowerPath, rule.suffix) {
			raise(rule.score, rule.reason)
		}
	}

	ext := strings.ToLower(path.Ext(lowerPath))
	static := false
	if staticExtensions[ext] {
		static = true
		raise(5, "static asset")
	}
	if scriptExtensions[ext] {
		static = true
		raise(15, "script/source asset")
	}

	host := strings.ToLower(u.Hostname())
	hostLabels := strings.Split(host, ".")
	for index, label := range hostLabels {
		// The final label is normally a TLD. In particular, do not treat the
		// public .dev TLD as a development environment.
		if index == len(hostLabels)-1 {
			continue
		}
		switch {
		case label == "admin" || strings.HasPrefix(label, "admin-"):
			raise(75, "administrative host")
		case label == "api" || strings.HasPrefix(label, "api-"):
			raise(25, "API host")
		case label == "dev" || label == "development" || label == "test" || label == "testing" ||
			label == "stage" || label == "staging" || label == "debug" || label == "demo" ||
			label == "sandbox" || label == "internal" || label == "private":
			raise(35, "non-production/internal host")
		}
	}

	pathTokens := tokenize(lowerPath)
	fragmentPath, fragmentParameterNames := fragmentRoute(u, static)
	if fragmentPath != "" {
		pathTokens = append(pathTokens, tokenize(fragmentPath)...)
	}
	for _, rule := range pathTermRules {
		if matchedPathTerm(pathTokens, rule.terms) {
			raise(rule.score, rule.reason)
		}
	}

	queryValues, _ := url.ParseQuery(u.RawQuery)
	parameterNames := make([]string, 0, len(queryValues))
	for name := range queryValues {
		parameterNames = append(parameterNames, name)
	}
	sort.Strings(parameterNames)
	for _, name := range parameterNames {
		score, reason := scoreParameter(name)
		if score > 0 {
			raise(score, reason)
		}
	}
	for _, name := range fragmentParameterNames {
		score, reason := scoreParameter(name)
		if score > 0 {
			raise(score, reason)
		}
	}

	if len(reasons) > 2 {
		best += 2 * (len(reasons) - 2)
	}
	if best > 100 {
		best = 100
	}
	return best, static, reasons
}

type termRule struct {
	score  int
	terms  []string
	reason string
}

var pathTermRules = []termRule{
	{95, []string{"shell", "phpinfo", "eval", "exec", "execute", "passthru", "popen"}, "command/evaluation surface"},
	{90, []string{"password", "passwd", "credential", "credentials", "secret", "secrets", "private-key"}, "secrets/authentication material"},
	{85, []string{"backup", "backups", "dump", "dumps", "sql", "database", "db", "phpmyadmin", "adminer"}, "database/backup surface"},
	{80, []string{"admin", "administrator", "manage", "management", "manager", "console", "panel", "actuator", "debug", "pprof", "server-status", "server-info"}, "administrative/debug surface"},
	{75, []string{"login", "logon", "signin", "auth", "oauth", "sso", "saml", "cas", "logout", "reset", "forgot", "jwt", "session", "register", "signup"}, "authentication surface"},
	{75, []string{"xmlrpc"}, "XML-RPC attack surface"},
	{70, []string{"upload", "uploads", "download", "downloads", "attachment", "attachments", "file", "files", "browser", "explorer", "include", "includes"}, "file access/upload surface"},
	{65, []string{"swagger", "openapi", "graphiql", "graphql", "apidocs", "playground", "altair", "redoc", "voyager"}, "API schema/query surface"},
	{60, []string{"account", "accounts", "profile", "profiles", "user", "users", "order", "orders", "payment", "payments", "billing", "invoice", "invoices", "checkout", "cart", "wallet", "transaction", "transactions", "refund", "role", "roles", "permission", "permissions"}, "account/business data surface"},
	{50, []string{"config", "configuration", "setting", "settings", "preferences", "env", "environment", "properties"}, "configuration surface"},
	{40, []string{"template", "templates", "theme", "themes", "render", "preview", "proxy", "fetch", "request"}, "template/proxy surface"},
	{35, []string{"search", "query", "find", "filter", "export", "import", "report", "reports"}, "data query/export surface"},
	{30, []string{"test", "tests", "testing", "demo", "dev", "develop", "development", "stage", "staging", "beta", "sandbox", "tmp", "temp", "internal", "private"}, "non-production/internal path"},
	{20, []string{"api", "rest", "rpc", "service", "services"}, "API endpoint"},
	{15, []string{"page"}, "pagination path"},
}

func tokenize(value string) []string {
	return strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

func matchedPathTerm(tokens []string, terms []string) bool {
	tokenSet := make(map[string]bool, len(tokens))
	for _, token := range tokens {
		tokenSet[token] = true
	}
	for _, term := range terms {
		normalizedTerm := strings.ToLower(term)
		if tokenSet[normalizedTerm] {
			return true
		}
		for _, token := range tokens {
			if len(normalizedTerm) >= 5 && strings.HasPrefix(token, normalizedTerm) {
				return true
			}
		}
	}
	return false
}

func normalizeParamName(name string) string {
	name = strings.TrimSuffix(name, "[]")
	var builder strings.Builder
	for index, r := range name {
		if unicode.IsUpper(r) {
			if index > 0 {
				builder.WriteByte('_')
			}
			builder.WriteRune(unicode.ToLower(r))
			continue
		}
		if r == '-' || r == '.' {
			builder.WriteByte('_')
			continue
		}
		builder.WriteRune(r)
	}
	return builder.String()
}

func scoreParameter(rawName string) (int, string) {
	name := normalizeParamName(rawName)
	compact := strings.ReplaceAll(name, "_", "")
	contains := func(fragment string) bool {
		normalizedFragment := strings.ReplaceAll(strings.ToLower(fragment), "_", "")
		return strings.Contains(compact, normalizedFragment)
	}
	equalsAny := func(values ...string) bool {
		for _, value := range values {
			if name == value || compact == strings.ReplaceAll(value, "_", "") {
				return true
			}
		}
		return false
	}

	switch {
	case contains("password"), contains("passwd"), equalsAny("pwd"),
		contains("secret"), contains("token"), contains("api_key"),
		contains("apikey"), contains("private_key"), contains("credential"),
		contains("access_key"), contains("client_secret"), contains("cvv"),
		contains("ssn"):
		return 90, "sensitive parameter: " + rawName
	case equalsAny("cmd", "exec", "execute", "command", "eval"):
		return 90, "command/evaluation parameter: " + rawName
	case equalsAny("code") || contains("auth_code") || contains("oauth_code"):
		return 65, "authentication/OAuth parameter: " + rawName
	case contains("card_number"), contains("credit_card"):
		return 90, "payment parameter: " + rawName
	case equalsAny("url", "uri", "next", "callback", "continue", "dest", "destination",
		"target", "goto", "return", "return_url", "redirect", "redirect_uri",
		"redirect_url", "return_to", "returnurl", "domain", "host", "site") ||
		strings.HasSuffix(name, "_url") || strings.HasSuffix(name, "_uri") ||
		strings.HasPrefix(name, "url_"):
		return 70, "redirect/SSRF-like parameter: " + rawName
	case equalsAny("file", "filename", "filepath", "path", "dir", "folder",
		"document", "template", "include", "require") ||
		strings.HasSuffix(name, "_file") || strings.HasSuffix(name, "_path") ||
		strings.HasSuffix(name, "_template"):
		return 65, "file/path/template parameter: " + rawName
	case equalsAny("sql", "query_sql") || contains("sql_query"):
		return 75, "SQL parameter: " + rawName
	case equalsAny("email", "mail", "phone", "mobile", "user", "username",
		"account", "role", "permission", "group") || strings.HasSuffix(name, "_email") ||
		strings.HasSuffix(name, "_user"):
		return 55, "identity/access parameter: " + rawName
	case name == "id" || strings.HasSuffix(name, "_id") || equalsAny("uuid", "guid"):
		return 35, "object identifier parameter: " + rawName
	case equalsAny("page", "p", "limit", "offset", "cursor", "sort", "order",
		"q", "query", "search", "keyword", "keywords", "term"):
		return 15, "pagination/search parameter: " + rawName
	default:
		return 0, ""
	}
}
