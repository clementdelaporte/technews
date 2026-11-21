import build, tempfile, pathlib
build.OUT = pathlib.Path(tempfile.mkdtemp())
BOD = "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use."
def kev(id, vendor, product, ransom="Unknown"):
    return {"cveID": id, "vendorProject": vendor, "product": product, "vulnerabilityName": "<b>bad</b>", "dateAdded": "2026-01-02",
            "shortDescription": "flaws everywhere", "requiredAction": BOD, "knownRansomwareCampaignUse": ransom}
def gh(id, pkg, eco="go"):
    return {"ghsa_id": id, "summary": "aws flaws", "severity": "high", "published_at": "2026-01-03T00:00:00Z", "description": None,
            "vulnerabilities": [{"package": {"ecosystem": eco, "name": pkg}}]}
k = {"vulnerabilities": [kev("CVE-1", "VMware", "ESXi", "Known"), kev("CVE-2", "Microsoft", "Windows"), kev("CVE-3", "Ivanti", "Cloud Services Appliance"), kev("CVE-4", "Apple", "iCloud for Windows")]}
g = [gh("GHSA-a", "github.com/aws/aws-sdk-go"), gh("GHSA-b", "github.com/kubeshark/kubeshark"), gh("GHSA-c", "next", "npm"), gh("GHSA-d", "nextcloud/server", "composer")]
its = {i["id"]: i for i in build.items(k, g)}
cloud = {i for i, v in its.items() if v["cloud"]}
# phrase BOD, "flaws"/"aws" dans le texte et "iCloud"/"nextcloud" ne doivent pas classer en cloud
assert cloud == {"CVE-1", "CVE-3", "GHSA-a", "GHSA-b"}, cloud
assert its["CVE-1"]["ransom"] and not its["CVE-2"]["ransom"] and its["CVE-1"]["sev"] == "exploitée"
assert its["GHSA-c"]["eco"] == "npm" and its["CVE-2"]["vendor"] == "Microsoft"
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
print("ok")
