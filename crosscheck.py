"""Independent check of sbom_osv.star output: query OSV directly from Python
and compare the set of (package, version, advisory id) findings."""
import json
import sys
import urllib.request

SBOM_URL = sys.argv[1]
OUT = sys.argv[2]


def get(url, data=None):
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def walk(comps):
    for c in comps:
        yield c
        yield from walk(c.get("components", []))


sbom = get(SBOM_URL)
purls = sorted({c["purl"].split("#")[0].split("?")[0] for c in walk(sbom.get("components", [])) if c.get("purl")})
expected = set()
for i in range(0, len(purls), 500):
    chunk = purls[i:i + 500]
    res = get("https://api.osv.dev/v1/querybatch", json.dumps({"queries": [{"package": {"purl": p}} for p in chunk]}).encode())
    for p, r in zip(chunk, res["results"]):
        name_ver = p.split("/")[-1]
        name, _, ver = name_ver.rpartition("@")
        for v in r.get("vulns", []):
            expected.add((name.replace("%40", "@"), ver, v["id"]))

out = json.load(open(OUT))
got = {(v["component"]["product"], v["component"]["version"], v["scanner_id"]) for v in out["vulnerabilities"]}
inst_ids = {i["instance_id"] for i in out["instances"]}
orphans = [v for v in out["vulnerabilities"] if v["instance_id"] not in inst_ids]
print(f"purls={len(purls)} expected={len(expected)} got={len(got)} missing={len(expected - got)} extra={len(got - expected)} orphans={len(orphans)}")
sys.exit(0 if expected == got and not orphans else 1)
