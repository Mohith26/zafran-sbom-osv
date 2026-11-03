# zafran-sbom-osv

A [Zafran custom integration](https://github.com/ZafranSecurity/zafran-custom-integrations-public) that turns a CycloneDX SBOM into Zafran data: the SBOM becomes one instance with its components attached as SBOM components, and every component's purl is looked up in [OSV.dev](https://osv.dev) (free, no key) to produce vulnerabilities with CVE, severity, CVSS vector, CWEs and the fixed version to upgrade to.

I wrote it to learn Zafran's Starlark integration format and tested it with the public `starlark-runner-mac` binary.

## Usage

```
./starlark-runner-mac -script sbom_osv.star \
  -params "api_url=https://raw.githubusercontent.com/CycloneDX/bom-examples/master/SBOM/juice-shop/v11.1.2/bom.json" \
  -output out.json
```

- `api_url`: URL of a CycloneDX JSON SBOM
- `api_key`: optional bearer token if the SBOM URL needs auth

## Results

On two public SBOMs from [CycloneDX/bom-examples](https://github.com/CycloneDX/bom-examples):

| SBOM | components | unique advisories | findings | critical / high / medium / low | runtime |
|---|---|---|---|---|---|
| OWASP Juice Shop 11.1.2 (npm) | 840 | 177 | 205 | 25 / 92 / 73 / 15 | ~16 s |
| Keycloak 10.0.2 (maven) | 903 | 500 | 924 | 94 / 359 / 372 / 99 | ~50 s |

Outputs are in `results/` (OSV data as of Nov 3, 2026). 191 of the 205 Juice Shop findings get a concrete `fixed_in_version`: the smallest fixed version above the installed one, so `bl@4.0.2` gets "upgrade to 4.0.3", not the 1.x/2.x/3.x fixes from the same advisory. When versions can't be ordered (pre-release tags), it lists the fixed versions instead of guessing.

`crosscheck.py` re-queries OSV straight from Python and compares the (package, version, advisory) sets with the runner output. Both SBOMs match exactly (205/205 and 924/924, no orphan vulnerabilities):

```
python3 crosscheck.py <sbom url> results/juice-shop-11.1.2.json
```

## Things I ran into

The shipped runner and the README in the integrations repo disagree in a few places:

- `zafran.collect_vulnerability()` and `zafran.flush()` are documented but not in the module (`dir(zafran)` lists `collect_instance`, `collect_instances`, `collect_control`, and a few others). Vulnerabilities go in as the second argument: `zafran.collect_instance(instance, vulns)`.
- `http.get()` returns a dict (`status_code`, `body`, `headers`), so the README's `response.json()` fails; `example.star` uses `json.decode(response["body"])`, which works.

## Limitations

- OSV paginates very large result sets per package; I only read the first page and log a warning if there's more.
- Advisory details are fetched one by one (cached per run), which is most of the runtime on big SBOMs.
- Only CycloneDX JSON for now, no SPDX.
