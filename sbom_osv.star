# Zafran custom integration: CycloneDX SBOM + OSV.dev
#
# Fetches a CycloneDX JSON SBOM from api_url, records it as one instance with
# its components as SBOM components, then looks every component's purl up in
# OSV.dev (free, no key) and collects a vulnerability per (component, advisory).
#
# Parameters (the standard three):
#   api_url    - URL of a CycloneDX JSON SBOM
#   api_key    - optional bearer token for fetching the SBOM (e.g. a private repo)
#   api_secret - unused

load("http", "http")
load("json", "json")
load("log", "log")
load("zafran", "zafran")

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
OSV_BATCH_SIZE = 500  # OSV allows up to 1000 queries per batch
JSON_HEADERS = {"Content-Type": "application/json"}

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}

def main(**kwargs):
    sbom_url = kwargs.get("api_url", "")
    if not sbom_url:
        log.error("api_url (the SBOM URL) is required")
        return None
    api_key = kwargs.get("api_key", "")

    pb = zafran.proto_file

    headers = {}
    if api_key:
        headers["Authorization"] = "Bearer " + api_key
    resp = http.get(sbom_url, headers = headers)
    if resp["status_code"] != 200:
        log.error("Failed to fetch SBOM:", resp["status_code"])
        return None
    sbom = json.decode(resp["body"])
    if sbom.get("bomFormat") != "CycloneDX":
        log.error("Not a CycloneDX JSON SBOM")
        return None

    components = flatten_components(sbom.get("components", []))
    with_purl = [c for c in components if c.get("purl")]
    log.info("SBOM components: %d (%d with a purl)" % (len(components), len(with_purl)))

    instance = sbom_to_instance(sbom, sbom_url, components, pb)

    # One OSV query per unique purl.
    purls = []
    seen = {}
    for c in with_purl:
        p = strip_purl_extras(c["purl"])
        if p not in seen:
            seen[p] = True
            purls.append(p)

    hits = query_osv(purls)  # purl -> [osv ids]
    details = {}  # osv id -> advisory json
    vulns = []
    for purl in purls:
        for vid in hits.get(purl, []):
            if vid not in details:
                details[vid] = fetch_advisory(vid)
            vulns.append(to_vulnerability(instance.instance_id, purl, details[vid], vid, pb))

    # The shipped runner takes an instance's vulnerabilities with the instance
    # (the README's zafran.collect_vulnerability is not in the binary).
    zafran.collect_instance(instance, vulns)
    log.info("Advisories: %d unique, %d component findings" % (len(details), len(vulns)))
    return None

def flatten_components(comps):
    """CycloneDX components can nest; walk them iteratively (Starlark has no recursion)."""
    out = []
    stack = list(comps)
    for _ in range(1000000):
        if not stack:
            break
        c = stack.pop()
        out.append(c)
        stack.extend(c.get("components", []))
    return out

def strip_purl_extras(purl):
    """Drop qualifiers (?...) and subpath (#...); OSV matches on type/namespace/name@version."""
    for sep in ["#", "?"]:
        i = purl.find(sep)
        if i >= 0:
            purl = purl[:i]
    return purl

def parse_purl(purl):
    """pkg:type/namespace/name@version -> (type, namespace, name, version)."""
    p = strip_purl_extras(purl)
    if p.startswith("pkg:"):
        p = p[4:]
    version = ""
    at = p.rfind("@")
    if at > p.find("/"):
        version = p[at + 1:]
        p = p[:at]
    parts = p.split("/")
    ptype = parts[0]
    name = unquote(parts[-1]) if len(parts) > 1 else ""
    namespace = unquote("/".join(parts[1:-1])) if len(parts) > 2 else ""
    return ptype, namespace, name, unquote(version)

def unquote(s):
    return s.replace("%40", "@").replace("%2F", "/").replace("%2f", "/").replace("%2B", "+").replace("%2b", "+")

def to_component(purl, pb):
    ptype, namespace, name, version = parse_purl(purl)
    display = (namespace + "/" + name) if namespace else name
    return pb.Component(
        type = pb.ComponentType.LIBRARY,
        product = name,
        vendor = namespace,
        version = version,
        display_name = display,
    )

def sbom_to_instance(sbom, sbom_url, components, pb):
    meta = sbom.get("metadata", {})
    subject = meta.get("component", {})
    name = subject.get("name", "") or sbom_url
    if subject.get("version"):
        name = name + "@" + subject["version"]
    instance_id = sbom.get("serialNumber", "") or subject.get("bom-ref", "") or sbom_url

    sbom_components = []
    for c in components:
        if not c.get("purl"):
            continue
        sbom_components.append(pb.SBOMComponent(
            component = to_component(c["purl"], pb),
            dynamic_properties = {"purl": c["purl"]},
        ))

    return pb.InstanceData(
        instance_id = instance_id,
        name = name,
        instance_type = pb.InstanceType.INSTANCE_TYPE_CODE_PROJECT,
        sbom_components = sbom_components,
        key_value_tags = [pb.InstanceTagKeyValue(key = "sbom_url", value = sbom_url)],
    )

def query_osv(purls):
    hits = {}
    for start in range(0, len(purls), OSV_BATCH_SIZE):
        chunk = purls[start:start + OSV_BATCH_SIZE]
        body = json.encode({"queries": [{"package": {"purl": p}} for p in chunk]})
        resp = http.post(OSV_BATCH_URL, headers = JSON_HEADERS, body = body)
        if resp["status_code"] != 200:
            log.error("OSV querybatch failed:", resp["status_code"])
            continue
        results = json.decode(resp["body"]).get("results", [])
        for i, res in enumerate(results):
            ids = [v["id"] for v in res.get("vulns", [])]
            if res.get("next_page_token"):
                log.warn("OSV returned more pages for", chunk[i], "- only the first page is used")
            if ids:
                hits[chunk[i]] = ids
    return hits

def fetch_advisory(vid):
    resp = http.get(OSV_VULN_URL + vid)
    if resp["status_code"] != 200:
        log.warn("Could not fetch advisory", vid, resp["status_code"])
        return {"id": vid}
    return json.decode(resp["body"])

def fixed_versions(adv, purl):
    """Every 'fixed' event in the affected entries that match this package."""
    ptype, namespace, name, _ = parse_purl(purl)
    full = (namespace + "/" + name) if namespace else name
    out = []
    for aff in adv.get("affected", []):
        pkg = aff.get("package", {})
        apurl = pkg.get("purl", "")
        matches = False
        if apurl:
            _, ans, an, _ = parse_purl(apurl)
            matches = ((ans + "/" + an) if ans else an) == full
        elif pkg.get("name") == full or pkg.get("name") == name:
            matches = True
        if not matches:
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                f = ev.get("fixed")
                if f and f not in out:
                    out.append(f)
    return out

def version_key(v):
    """Numeric key for dotted versions like 1.2.3 or v2.0.1; None if not plain numeric."""
    v = v.lstrip("v")
    for sep in ["-", "+"]:
        i = v.find(sep)
        if i >= 0:
            return None  # pre-releases / build tags: don't guess
    key = []
    for part in v.split("."):
        if not part.isdigit():
            return None
        key.append(int(part))
    for _ in range(4 - len(key)):
        key.append(0)
    return key

def next_fixed(current, fixes):
    """Smallest fixed version above the installed one, or "" if it can't be ordered."""
    cur = version_key(current)
    if cur == None:
        return ""
    best = ""
    best_key = None
    for f in fixes:
        k = version_key(f)
        if k == None:
            continue
        if k > cur and (best_key == None or k < best_key):
            best = f
            best_key = k
    return best

def to_vulnerability(instance_id, purl, adv, vid, pb):
    aliases = adv.get("aliases", [])
    cve = ""
    for a in aliases:
        if a.startswith("CVE-"):
            cve = a
            break

    severity = ""
    raw_sev = adv.get("database_specific", {}).get("severity", "")
    if raw_sev:
        severity = SEVERITY_MAP.get(raw_sev.upper(), raw_sev.lower())

    cvss = []
    for s in adv.get("severity", []):
        if s.get("type", "").startswith("CVSS_V") and s.get("score", "").startswith("CVSS:"):
            cvss.append(pb.CVSS(
                version = s["score"].split("/")[0][5:],
                vector = s["score"],
                source = "osv",
            ))

    fixes = fixed_versions(adv, purl)
    fix = next_fixed(parse_purl(purl)[3], fixes)
    if fix:
        suggestion = "Upgrade to " + fix + " or later"
    elif fixes:
        suggestion = "Fixed in " + ", ".join(fixes)
    else:
        suggestion = "No fixed version listed in OSV"
    remediation = pb.Remediation(
        suggestion = suggestion,
        source = "osv.dev",
        fixed_in_version = fix,
    )

    cwes = []
    for c in adv.get("database_specific", {}).get("cwe_ids", []):
        if c.startswith("CWE-") and c[4:].isdigit():
            cwes.append(int(c[4:]))

    return pb.Vulnerability(
        instance_id = instance_id,
        cve = cve or vid,
        component = to_component(purl, pb),
        remediation = remediation,
        CVSS = cvss,
        cwe_ids = cwes,
        description = adv.get("summary", "") or adv.get("details", "")[:500],
        scanner_id = vid,
        scanner_name = adv.get("summary", ""),
        references_url = "https://osv.dev/vulnerability/" + vid,
        severity = severity,
        scan_type = pb.ScanType.SCA,
        finding_type = pb.FindingType.VULNERABILITY,
        vulnerability_sources = [pb.VulnerabilitySource(source = "osv", source_key = "osv_id", source_value = vid)],
    )
