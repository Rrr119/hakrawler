# Three-site acceptance baseline

These deterministic fixtures stand in for three crawled site types:

- `shop/`: ecommerce pages, product identifiers, tracking parameters, and static bundles.
- `api/`: API endpoints, OAuth callbacks, object identifiers, secrets, debug endpoints, and file/SSRF parameters.
- `cms/`: CMS/admin endpoints, backup files, pagination, tag/category routes, uploads, and theme assets.

For each site, `raw-urls.txt` is a crawled URL superset and `expected-dedup.txt`
is the manually reviewed shortlist after:

1. collapsing reordered parameters and equivalent parameter values;
2. collapsing tracking/cache parameters, fragments, default ports, numeric/UUID/hash path IDs, and common resource slugs;
3. hiding classified static assets with `-hide-static`;
4. sorting critical/high/medium/low/info endpoints by sensitivity;
5. retaining the first seen **raw** URL as the representative.

The Go regression in `acceptance_test.go` runs the real CLI pipeline and compares
the complete output for all three sites:

```sh
go test -run TestThreeSiteManualAcceptance -v
```

Raw counts to reviewed counts are:

| Site type | Raw URLs | Reviewed output |
| --- | ---: | ---: |
| Shop | 26 | 11 |
| API/SaaS | 22 | 14 |
| CMS/docs | 23 | 13 |

The raw representative URL is never rewritten. JSON output adds
`normalized_url`, `fingerprint`, score/classification, and optional aliases;
`-trace-file` additionally records every raw crawled URL.
