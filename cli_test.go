package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIFilterJSONRemainsCompatibleAndAddsTraceability(t *testing.T) {
	tracePath := filepath.Join(t.TempDir(), "trace.jsonl")
	input := strings.NewReader(strings.Join([]string{
		"https://example.test/items/1?b=2&a=1",
		"https://example.test/items/2?a=9&b=8",
	}, "\n") + "\n")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runCLI([]string{
		"-filter",
		"-dedupe-params",
		"-json",
		"-aliases",
		"-trace-file", tracePath,
	}, input, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected one deduplicated JSON line, got %d: %s", len(lines), stdout.String())
	}

	var record EnrichedResult
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatal(err)
	}
	if record.Source != "stdin" {
		t.Fatalf("Source = %q, want stdin", record.Source)
	}
	if record.URL != "https://example.test/items/1?b=2&a=1" {
		t.Fatalf("raw representative URL changed: %q", record.URL)
	}
	if record.NormalizedURL == "" || record.Fingerprint == "" {
		t.Fatalf("missing normalization metadata: %+v", record.URLAnalysis)
	}
	if len(record.Aliases) != 2 {
		t.Fatalf("expected two aliases, got %v", record.Aliases)
	}

	traceBytes, err := os.ReadFile(tracePath)
	if err != nil {
		t.Fatal(err)
	}
	traceLines := strings.Split(strings.TrimSpace(string(traceBytes)), "\n")
	if len(traceLines) != 2 {
		t.Fatalf("expected two raw trace records, got %d: %s", len(traceLines), string(traceBytes))
	}
	for _, line := range traceLines {
		var trace TraceRecord
		if err := json.Unmarshal([]byte(line), &trace); err != nil {
			t.Fatal(err)
		}
		if trace.RawURL == "" || trace.Fingerprint == "" {
			t.Fatalf("trace record missing raw URL/fingerprint: %+v", trace)
		}
	}
}

func TestCLILegacyJSONAndUniqueOutputAreCompatible(t *testing.T) {
	var stdout bytes.Buffer
	code := runCLI(
		[]string{"-filter", "-json"},
		strings.NewReader("https://legacy.example.test/path\n"),
		&stdout,
		&bytes.Buffer{},
	)
	if code != 0 {
		t.Fatalf("unexpected exit code %d", code)
	}
	want := `{"Source":"stdin","URL":"https://legacy.example.test/path","Where":""}` + "\n"
	if stdout.String() != want {
		t.Fatalf("legacy JSON changed:\ngot:  %q\nwant: %q", stdout.String(), want)
	}

	uniqueURL := "https://unique-legacy.example.test/path?x=1"
	stdout.Reset()
	code = runCLI(
		[]string{"-filter", "-u"},
		strings.NewReader(uniqueURL+"\n"+uniqueURL+"\n"),
		&stdout,
		&bytes.Buffer{},
	)
	if code != 0 {
		t.Fatalf("unique exit code %d", code)
	}
	if got := stdout.String(); got != uniqueURL+"\n" {
		t.Fatalf("legacy -u output changed: %q", got)
	}
}

func TestCLIRejectsUnsupportedSort(t *testing.T) {
	var stderr bytes.Buffer
	code := runCLI([]string{"-filter", "-sort", "unknown"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), `unsupported -sort value`) {
		t.Fatalf("expected sort error, got %q", stderr.String())
	}
}

func TestParseFilterLineUnderstandsLegacyOutput(t *testing.T) {
	cases := []struct {
		line       string
		wantURL    string
		wantSource string
		wantWhere  string
	}{
		{"https://example.test/a", "https://example.test/a", "", ""},
		{"[href] https://example.test/b", "https://example.test/b", "href", ""},
		{"[https://found.test/page] https://example.test/c", "https://example.test/c", "", "https://found.test/page"},
		{"[https://found.test/page] [script] https://example.test/d.js", "https://example.test/d.js", "script", "https://found.test/page"},
		{`{"Source":"form","URL":"https://example.test/e","Where":"https://found.test/form"}`, "https://example.test/e", "form", "https://found.test/form"},
	}

	for _, tc := range cases {
		got := parseFilterLine(tc.line)
		if got.URL != tc.wantURL || got.Source != tc.wantSource || got.Where != tc.wantWhere {
			t.Fatalf("parseFilterLine(%q) = %+v, want URL=%q Source=%q Where=%q", tc.line, got, tc.wantURL, tc.wantSource, tc.wantWhere)
		}
	}
}
