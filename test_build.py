import build, tempfile, pathlib
build.OUT = pathlib.Path(tempfile.mkdtemp())
BOD = "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use."
def kev(id, vendor, product, ransom="Unknown", cwes=None):
    d = {"cveID": id, "vendorProject": vendor, "product": product, "vulnerabilityName": "<b>bad</b>", "dateAdded": "2026-01-02",
         "shortDescription": "flaws everywhere", "requiredAction": BOD, "knownRansomwareCampaignUse": ransom}
    return d if cwes is None else {**d, "cwes": cwes}
def gh(id, pkg, eco="go", cve_id=None, rng=None, patched=None, cwes=None):
    vuln = {"package": {"ecosystem": eco, "name": pkg}}
    if rng is not None:
        vuln["vulnerable_version_range"] = rng
    if patched is not None:
        vuln["first_patched_version"] = patched
    d = {"ghsa_id": id, "summary": "aws flaws", "severity": "high", "published_at": "2026-01-03T00:00:00Z", "description": None,
         "vulnerabilities": [vuln]}
    if cve_id is not None:
        d["cve_id"] = cve_id
    if cwes is not None:
        d["cwes"] = cwes
    return d
k = {"vulnerabilities": [kev("CVE-1", "VMware", "ESXi", "Known", ["CWE-78"]), kev("CVE-2", "Microsoft", "Windows"), kev("CVE-3", "Ivanti", "Cloud Services Appliance"), kev("CVE-4", "Apple", "iCloud for Windows")]}
g = [gh("GHSA-a", "github.com/aws/aws-sdk-go", cve_id="CVE-2026-9999", rng="< 1.2.0", patched="1.2.0", cwes=[{"cwe_id": "CWE-79"}]),
     gh("GHSA-b", "github.com/kubeshark/kubeshark"), gh("GHSA-c", "next", "npm"), gh("GHSA-d", "nextcloud/server", "composer")]
its = {i["id"]: i for i in build.items(k, g)}
cloud = {i for i, v in its.items() if v["cloud"]}
# phrase BOD, "flaws"/"aws" dans le texte et "iCloud"/"nextcloud" ne doivent pas classer en cloud
assert cloud == {"CVE-1", "CVE-3", "GHSA-a", "GHSA-b"}, cloud
assert its["CVE-1"]["ransom"] and not its["CVE-2"]["ransom"] and its["CVE-1"]["sev"] == "exploitée"
assert its["GHSA-c"]["eco"] == "npm" and its["CVE-2"]["vendor"] == "Microsoft"
assert its["CVE-1"]["product"] == "ESXi" and its["CVE-1"]["cwes"] == ["CWE-78"]
assert its["CVE-2"]["product"] == "Windows" and its["CVE-2"]["cwes"] == []
assert its["GHSA-a"]["cve_id"] == "CVE-2026-9999" and its["GHSA-a"]["cwes"] == ["CWE-79"]
assert its["GHSA-a"]["packages"] == [{"ecosystem": "go", "name": "github.com/aws/aws-sdk-go", "vulnerable_version_range": "< 1.2.0", "first_patched_version": "1.2.0"}]
assert its["GHSA-c"]["cve_id"] == "" and its["GHSA-c"]["packages"][0]["vulnerable_version_range"] == ""
assert build.items({"vulnerabilities": []}, [dict(gh("GHSA-z", "x"), vulnerabilities=None)])[0]["eco"] == ""
from datetime import date
build.render(list(its.values()), today=date(2026, 1, 5))
idx = (build.OUT / "liste.html").read_text()
dash = (build.OUT / "index.html").read_text()
# tuiles 7 jours : 4 KEV exploitées, 1 rançongiciel, 0 critique, 4 cloud
for n, q in [(4, "sev=exploitée"), (1, "ransom=1"), (0, "sev=critical"), (4, "cat=cloud")]:
    assert f'href="liste.html#days=7&{q}"><b>{n}</b>' in dash, q
top = dash.split("<ul>")[1]
assert top.count("<li>") == 5 and "CVE-1" in top.split("</li>")[0] and "rançongiciels" in top.split("</li>")[0] and "http" not in dash
assert "Aucune nouvelle faille" in build.dashboard(list(its.values()), date(2027, 1, 1))
assert "&lt;b&gt;" in (build.OUT / "a/CVE-1.html").read_text() and "http" not in idx
assert 'data-cat="cloud" data-sev="exploitée" data-ransom="1"' in idx and '<option value="npm">' in idx
assert 'border-radius:0' in dash and 'aria-current="page"' in dash and 'id="rst"' in idx and 'id="more"' in idx
cve_html = (build.OUT / "a/CVE-1.html").read_text()
assert 'class="callout"' in cve_html and 'href="../liste.html"' in cve_html
assert 'href="https://nvd.nist.gov/vuln/detail/CVE-1"' in cve_html and 'rel="noopener noreferrer"' in cve_html
assert 'href="https://github.com/advisories/GHSA-a"' in (build.OUT / "a/GHSA-a.html").read_text()
assert '<use href="#i-vmware"/>' in cve_html and '<use href="#i-npm"/>' in idx
assert 'class="tech-head"' in idx and 'width:2.25rem;height:2.25rem' in dash
assert 'class="ico-m"' in build.tech_title(dict(id="X", tech="Zabbix", vendor="Zabbix", eco="", summary="bug"))
md_out = build.md_html("## Impact\n\n- `foo` **bar**\n\n```\n<script>\n```")
assert "<h2>Impact</h2>" in md_out and "<code>foo</code>" in md_out and "<strong>bar</strong>" in md_out and "&lt;script&gt;" in md_out
assert 'id="techs"' in idx and 'id="tq"' in idx and 'id="tclr"' in idx and 'id="tc"' in idx and 'id="tck"' in idx
assert 'value="e:npm"' in idx and 'value="v:VMware"' in idx and 'technews_techs' in idx and 'SameSite=Lax' in idx
assert build.tech_picker([], []) == ""
assert 'value="v:A &amp; &lt;B&gt;"' in build.tech_picker([], ["A & <B>"])
import json
catalogue = json.loads((build.OUT / "failles.json").read_text())
assert catalogue["generated_at"] == "2026-01-05" and catalogue["count"] == len(its) == len(catalogue["items"])
by_id = {x["id"]: x for x in catalogue["items"]}
assert by_id["CVE-1"]["product"] == "ESXi" and by_id["CVE-1"]["cwes"] == ["CWE-78"]
assert by_id["GHSA-a"]["cve_id"] == "CVE-2026-9999" and by_id["GHSA-a"]["cwes"] == ["CWE-79"] and by_id["GHSA-a"]["packages"][0]["first_patched_version"] == "1.2.0"
print("ok")
