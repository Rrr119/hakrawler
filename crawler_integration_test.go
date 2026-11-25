package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCrawlerSmartOutputOnThreeLocalSites(t *testing.T) {
	sites := []struct {
		name string
		html string
		want []string
	}{
		{
			name: "shop",
			html: `<!doctype html><html><body>
				<a href="/">Home</a>
				<a href="/.git/config">git</a>
				<a href="/admin/orders?status=paid">orders</a>
				<a href="/products/1?utm_source=ad">p1</a>
				<a href="/products/2?utm_campaign=week">p2</a>
				<script src="/static/app.js?v=1"></script>
				<link rel="stylesheet" href="/static/app.css?ver=2">
			</body></html>`,
			want: []string{"/.git/config", "/admin/orders", "/products/1?"},
		},
		{
			name: "api",
			html: `<!doctype html><html><body>
				<a href="/.env.production">env</a>
				<a href="/v1/proxy?url=https://example.com">proxy</a>
				<a href="/v1/users?limit=50&offset=0">users1</a>
				<a href="/v1/users?offset=50&limit=50">users2</a>
				<script src="/static/vendor.js?ver=1"></script>
			</body></html>`,
			want: []string{"/.env.production", "/v1/proxy?url=", "/v1/users?limit=50"},
		},
		{
			name: "cms",
			html: `<!doctype html><html><body>
				<a href="/.git/HEAD">git head</a>
				<a href="/wp-admin/">admin</a>
				<a href="/wp-login.php?redirect_to=/wp-admin/">login</a>
				<a href="/?p=101">post1</a>
				<a href="/?p=202">post2</a>
				<link rel="stylesheet" href="/wp-content/theme/style.css?ver=1">
			</body></html>`,
			want: []string{"/.git/HEAD", "/wp-admin/", "/wp-login.php?redirect_to=", "/?p=101"},
		},
	}

	for _, site := range sites {
		t.Run(site.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "text/html")
				fmt.Fprint(writer, site.html)
			}))
			defer server.Close()

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := runCLI(
				[]string{"-t", "1", "-d", "1", "-smart", "-hide-static"},
				strings.NewReader(server.URL+"\n"),
				&stdout,
				&stderr,
			)
			if code != 0 {
				t.Fatalf("runCLI code=%d stderr=%s", code, stderr.String())
			}

			output := stdout.String()
			if output == "" {
				t.Fatalf("expected crawled output, stderr=%s", stderr.String())
			}
			for _, wanted := range site.want {
				if !strings.Contains(output, wanted) {
					t.Fatalf("output missing %q\noutput:\n%s\nstderr:\n%s", wanted, output, stderr.String())
				}
			}
			if strings.Contains(output, ".css") || strings.Contains(output, ".js?") {
				t.Fatalf("static asset was not hidden:\n%s", output)
			}

			productGroups := strings.Count(output, "/products/")
			if site.name == "shop" && productGroups != 1 {
				t.Fatalf("expected one product fingerprint group, got %d:\n%s", productGroups, output)
			}
			userGroups := strings.Count(output, "/v1/users?")
			if site.name == "api" && userGroups != 1 {
				t.Fatalf("expected one users fingerprint group, got %d:\n%s", userGroups, output)
			}
			postGroups := strings.Count(output, "/?p=")
			if site.name == "cms" && postGroups != 1 {
				t.Fatalf("expected one post fingerprint group, got %d:\n%s", postGroups, output)
			}

			lines := strings.Split(strings.TrimSpace(output), "\n")
			if !strings.Contains(lines[0], ".env") && !strings.Contains(lines[0], ".git") {
				t.Fatalf("expected a critical secret-control URL first, got %q", lines[0])
			}
		})
	}
}
