package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeURLIsCanonicalButDoesNotMutateInput(t *testing.T) {
	raw := "HTTPS://Example.COM:443/a/../b/?b=2&a=1&utm_source=newsletter#section"
	want := "https://example.com/b/?a=1&b=2"

	got, err := NormalizeURL(raw)
	if err != nil {
		t.Fatalf("NormalizeURL returned error: %v", err)
	}
	if got != want {
		t.Fatalf("normalized URL mismatch:\ngot:  %s\nwant: %s", got, want)
	}
	if raw != "HTTPS://Example.COM:443/a/../b/?b=2&a=1&utm_source=newsletter#section" {
		t.Fatalf("input was mutated: %s", raw)
	}
}

func TestNormalizeURLRemovesDefaultHTTPPort(t *testing.T) {
	got, err := NormalizeURL("http://Example.ORG:80/path?z=9&a=1")
	if err != nil {
		t.Fatal(err)
	}
	if want := "http://example.org/path?a=1&z=9"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParameterFingerprintMatchesEquivalentShapes(t *testing.T) {
	equivalentGroups := [][]string{
		{
			"https://example.test/search?q=shoes&page=1",
			"https://example.test/search?page=2&q=boots",
			"https://example.test/search?page=3&q=hats&utm_source=news",
		},
		{
			"https://example.test/users/1001/profile",
			"https://example.test/users/2002/profile?ref=footer",
		},
		{
			"https://example.test/assets/app.js?v=1.0.0",
			"https://example.test/assets/app.js?ver=2.0.0",
		},
		{
			"https://quotes.example/author/Jane-Austen",
			"https://quotes.example/author/John_Doe?ref=footer",
		},
		{
			"https://books.example/catalogue/first-book_1000/index.html",
			"https://books.example/catalogue/second-book_2000/index.html",
		},
		{
			"https://app.example/#/users/1?tab=profile",
			"https://app.example/#/users/2?tab=security&utm_source=news",
		},
	}

	for groupIndex, group := range equivalentGroups {
		var first string
		for i, raw := range group {
			fp := FingerprintURL(raw)
			if fp == "" || strings.HasPrefix(fp, "raw1_") {
				t.Fatalf("group %d URL %q did not produce a normal fingerprint: %q", groupIndex, raw, fp)
			}
			if i == 0 {
				first = fp
				continue
			}
			if fp != first {
				t.Fatalf("group %d fingerprints differ:\n%s => %s\n%s => %s", groupIndex, group[0], first, raw, fp)
			}
		}
	}
}

func TestParameterFingerprintSeparatesDifferentShapes(t *testing.T) {
	different := []struct {
		a string
		b string
	}{
		{"https://example.test/path?a=1", "https://example.test/path?b=1"},
		{"https://example.test/users/1/profile", "https://example.test/accounts/1/profile"},
		{"https://example.test/path?a=1", "http://example.test/path?a=1"},
		{"https://app.example/#/settings", "https://app.example/#/admin"},
	}

	for _, pair := range different {
		if FingerprintURL(pair.a) == FingerprintURL(pair.b) {
			t.Fatalf("fingerprints should differ: %q and %q", pair.a, pair.b)
		}
	}
}

func TestEnrichmentKeepsRawURLTraceable(t *testing.T) {
	raw := "HTTPS://Example.COM/admin?b=2&a=1#fragment"
	result := Result{Source: "href", URL: raw, Where: "https://example.com/start"}
	enriched := Enrich(result)

	if enriched.URL != raw {
		t.Fatalf("original URL changed: got %q want %q", enriched.URL, raw)
	}
	if enriched.NormalizedURL == "" || enriched.Fingerprint == "" {
		t.Fatalf("normalization metadata missing: %+v", enriched.URLAnalysis)
	}

	encoded, err := json.Marshal(enriched)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["URL"] != raw {
		t.Fatalf("JSON URL = %v, want raw %q; payload: %s", decoded["URL"], raw, string(encoded))
	}
	if decoded["normalized_url"] != "https://example.com/admin?a=1&b=2" {
		t.Fatalf("normalized_url = %v; payload: %s", decoded["normalized_url"], string(encoded))
	}
}

func TestCatalogDeduplicatesAndPreservesAliases(t *testing.T) {
	catalog := NewCatalog(true)
	rawURLs := []string{
		"https://example.test/items/1?utm_source=a",
		"https://example.test/items/2?ref=b",
		"https://example.test/items/3?utm_campaign=c",
	}
	for _, raw := range rawURLs {
		catalog.Add(Result{Source: "href", URL: raw})
	}

	items := catalog.Items(false, true)
	if len(items) != 1 {
		t.Fatalf("expected one fingerprint group, got %d: %+v", len(items), items)
	}
	if items[0].OccurrenceCount != 3 {
		t.Fatalf("expected three occurrences, got %d", items[0].OccurrenceCount)
	}
	if len(items[0].Aliases) != 3 {
		t.Fatalf("expected three raw aliases, got %v", items[0].Aliases)
	}
	if items[0].URL != rawURLs[0] {
		t.Fatalf("representative should be first seen: got %q want %q", items[0].URL, rawURLs[0])
	}
}

func TestSensitivityClassificationAndOrder(t *testing.T) {
	cases := []struct {
		raw        string
		wantLabel  string
		wantStatic bool
	}{
		{"https://example.test/.env", SensitivityCritical, false},
		{"https://example.test/admin/users", SensitivityHigh, false},
		{"https://example.test/login?next=/admin", SensitivityHigh, false},
		{"https://app.example/#/login?redirect=/account", SensitivityHigh, false},
		{"https://example.test/assets/app.css", SensitivityInfo, true},
	}

	items := make([]EnrichedResult, 0, len(cases))
	for _, tc := range cases {
		analysis := AnalyzeURL(tc.raw)
		if analysis.Sensitivity != tc.wantLabel {
			t.Fatalf("%s label: got %q want %q (score %d, reasons %v)", tc.raw, analysis.Sensitivity, tc.wantLabel, analysis.SensitivityScore, analysis.Reasons)
		}
		if analysis.Static != tc.wantStatic {
			t.Fatalf("%s static: got %v want %v", tc.raw, analysis.Static, tc.wantStatic)
		}
		items = append(items, EnrichedResult{Result: Result{URL: tc.raw}, URLAnalysis: analysis})
	}

	SortBySensitivity(items)
	if items[0].Sensitivity != SensitivityCritical {
		t.Fatalf("critical result should sort first, got %s (%d)", items[0].URL, items[0].SensitivityScore)
	}
	if items[len(items)-1].Static != true {
		t.Fatalf("static result should sort last, got %s (%d)", items[len(items)-1].URL, items[len(items)-1].SensitivityScore)
	}
}

func TestRenderResultPreservesLegacyOutput(t *testing.T) {
	result := Result{Source: "href", URL: "https://example.test/path", Where: "https://example.test/from"}

	if got := renderResult(result, false, false, false); got != "https://example.test/path" {
		t.Fatalf("plain URL format changed: %q", got)
	}
	if got := renderResult(result, true, false, false); got != "[href] https://example.test/path" {
		t.Fatalf("source format changed: %q", got)
	}
	if got := renderResult(result, false, true, false); got != "[https://example.test/from] https://example.test/path" {
		t.Fatalf("where format changed: %q", got)
	}
	if got := renderResult(result, true, true, false); got != "[https://example.test/from] [href] https://example.test/path" {
		t.Fatalf("combined format changed: %q", got)
	}

	result.Where = ""
	wantJSON := `{"Source":"href","URL":"https://example.test/path","Where":""}`
	if got := renderResult(result, false, false, true); got != wantJSON {
		t.Fatalf("JSON format changed:\ngot:  %s\nwant: %s", got, wantJSON)
	}
}
