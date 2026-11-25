package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestThreeSiteManualAcceptance(t *testing.T) {
	sites := []string{"shop", "api", "cms"}

	for _, site := range sites {
		t.Run(site, func(t *testing.T) {
			dir := filepath.Join("testdata", "acceptance", site)
			raw, err := os.ReadFile(filepath.Join(dir, "raw-urls.txt"))
			if err != nil {
				t.Fatalf("read raw URLs: %v", err)
			}
			want, err := os.ReadFile(filepath.Join(dir, "expected-dedup.txt"))
			if err != nil {
				t.Fatalf("read manual expectation: %v", err)
			}

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := runCLI(
				[]string{"-filter", "-dedupe-params", "-sort", "sensitivity", "-hide-static"},
				bytes.NewReader(raw),
				&stdout,
				&stderr,
			)
			if code != 0 {
				t.Fatalf("runCLI exited %d, stderr: %s", code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("unexpected stderr: %s", stderr.String())
			}
			if got := stdout.String(); got != string(want) {
				t.Fatalf("deduplicated output does not match manual screening\n--- got ---\n%s\n--- want ---\n%s", got, string(want))
			}
		})
	}
}
