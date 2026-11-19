"""Génère un site statique cyber/cloud sans aucun lien sortant. Sources: CISA KEV (domaine public), GitHub Advisory DB (CC-BY 4.0)."""
import json, re, urllib.request
from html import escape
from pathlib import Path

KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GHSA = "https://api.github.com/advisories?type=reviewed&per_page=50"
OUT = Path("public")

# Classement cloud sur champs structurés uniquement, jamais sur le texte libre (la phrase type KEV "BOD 22-01 ... cloud services" faussait tout).
CLOUD_VENDORS = {"Amazon", "AWS", "Aquasecurity", "Aviatrix", "Citrix", "Docker", "MinIO", "Omnissa", "ownCloud", "VMware", "VMware Tanzu"}
CLOUD_PRODUCT = re.compile(r"\b(azure|aws|kubernetes|openshift|vcenter|esxi|cloud|daas|saas)\b", re.I)
CLOUD_PKG_TOKENS = {"aws", "amazon", "amazonaws", "azure", "k8s", "kubernetes", "docker", "moby", "containerd", "helm", "terraform", "hashicorp", "istio", "openstack", "gcp", "cloud"}

def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "cybercloud-news-builder"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)

def kev_cloud(v):
    return v["vendorProject"] in CLOUD_VENDORS or bool(CLOUD_PRODUCT.search(v["product"]))

def pkg_cloud(name):
    toks = re.split(r"[^a-z0-9]+", name.lower())
    return any(t in CLOUD_PKG_TOKENS or t.startswith("kube") or t.endswith("kube") for t in toks)

def items(kev, ghsa):
    out = []
    for v in kev["vulnerabilities"]:
        out.append(dict(id=v["cveID"], date=v["dateAdded"], title=f'{v["vendorProject"]} {v["product"]} : {v["vulnerabilityName"]}',
            body=f'{v["shortDescription"]}\n\nAction requise : {v["requiredAction"]}\nUtilisée par des rançongiciels : {v["knownRansomwareCampaignUse"]}',
            source="CISA KEV (domaine public)", cloud=kev_cloud(v), sev="exploitée",
            ransom=v["knownRansomwareCampaignUse"] == "Known", eco="", vendor=v["vendorProject"]))
    for a in ghsa:
        pkgs = [p["package"] for p in a.get("vulnerabilities") or [] if p.get("package")]
        out.append(dict(id=a["ghsa_id"], date=a["published_at"][:10], title=f'[{a["severity"]}] {a["summary"]}',
            body=(a.get("description") or "")[:3000], source="GitHub Advisory Database (CC-BY 4.0)",
            cloud=any(pkg_cloud(p["name"]) for p in pkgs), sev=a["severity"], ransom=False,
            eco=pkgs[0]["ecosystem"] if pkgs else "", vendor=""))
    return sorted(out, key=lambda i: i["date"], reverse=True)

PAGE = """<!doctype html><html lang="fr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>
body{{margin:0;background:#fff;color:#000;font:16px/1.5 system-ui,sans-serif}}
header{{background:#fff;border-bottom:1px solid #000;padding:.9rem 1rem}}header a{{color:#000;text-decoration:none;font-weight:700;letter-spacing:.03em}}
main{{max-width:48rem;margin:0 auto;padding:1.5rem 1rem}}
h1{{font-size:1.5rem;line-height:1.25;margin:0 0 1rem;padding-bottom:.5rem;border-bottom:3px solid #000}}
form{{display:grid;grid-template-columns:repeat(auto-fill,minmax(10rem,1fr));gap:.75rem;padding:1rem;border:2px solid #000;border-radius:1rem}}
label{{display:flex;flex-direction:column;font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em}}
input,select{{font:inherit;font-size:1rem;margin-top:.25rem;padding:.35rem .5rem;border:2px solid #000;border-radius:.6rem;background:#fff;color:#000}}
input[type=checkbox]{{width:1.25rem;height:1.25rem;accent-color:#000}}
:focus-visible{{outline:3px solid #000;outline-offset:2px}}
:focus-visible{{border-radius:.6rem}}#n{{font-weight:700;margin:1rem 0 .5rem}}ul{{list-style:none;padding:0;margin:0;display:grid;gap:.6rem}}
li{{border:1px solid #000;border-radius:1rem;padding:.75rem 1rem}}li[hidden]{{display:none}}
li a{{color:#000;font-weight:600;text-decoration:none}}li a:hover{{text-decoration:underline}}a{{color:#000}}
small{{color:#555}}pre{{white-space:pre-wrap;font:inherit;border:1px solid #000;border-radius:1rem;padding:1rem;margin-top:1.5rem}}
</style><header><a href="{home}">CYBER &amp; CLOUD NEWS</a></header><main>{body}</main></html>"""

# Filtre côté client sur les data-* de chaque <li>; l'état vit dans le hash pour qu'une vue filtrée soit partageable.
SCRIPT = """<script>
const F=document.getElementById('f'),L=[...document.querySelectorAll('#l li')],N=document.getElementById('n');
function run(){const q=new FormData(F),s=new URLSearchParams();for(const[k,v]of q)if(v)s.set(k,v);history.replaceState(null,'','#'+s);
const t=(q.get('q')||'').toLowerCase(),d=+q.get('days'),now=Date.now();let n=0;
for(const l of L){const x=l.dataset,ok=(!q.get('cat')||x.cat==q.get('cat'))&&(!q.get('sev')||x.sev==q.get('sev'))&&(!q.get('ransom')||x.ransom=='1')
&&(!q.get('eco')||x.eco==q.get('eco'))&&(!q.get('vendor')||x.vendor==q.get('vendor'))&&(!d||now-Date.parse(x.date)<d*864e5)&&(!t||l.textContent.toLowerCase().includes(t));
l.hidden=!ok;n+=ok}N.textContent=n+' résultat'+(n>1?'s':'')}
for(const[k,v]of new URLSearchParams(location.hash.slice(1))){const e=F.elements[k];if(e)e.type=='checkbox'?e.checked=true:e.value=v}
F.addEventListener('input',run);run();
</script>"""

def select(name, label, values):
    opts = "".join(f'<option value="{escape(v)}">{escape(v)}</option>' for v in values)
    return f'<label>{label}<select name="{name}"><option value="">Tous</option>{opts}</select></label>'

def render(its):
    OUT.mkdir(exist_ok=True); (OUT / "a").mkdir(exist_ok=True)  # liens internes uniquement
    for i in its:
        tags = " · ".join(t for t in ("cloud" if i["cloud"] else "", i["sev"], "rançongiciel" if i["ransom"] else "", i["eco"], i["vendor"]) if t)
        (OUT / "a" / f'{i["id"]}.html').write_text(PAGE.format(title=escape(i["title"]), home="../index.html", body=
            f'<p><a href="../index.html">← Accueil</a></p><h1>{escape(i["title"])}</h1><small>{i["date"]} · {escape(tags)} · Source : {escape(i["source"])}</small><pre>{escape(i["body"])}</pre>'))
    rows = "".join(f'<li data-cat="{"cloud" if i["cloud"] else "autre"}" data-sev="{escape(i["sev"])}" data-ransom="{int(i["ransom"])}" data-eco="{escape(i["eco"])}" data-vendor="{escape(i["vendor"])}" data-date="{i["date"]}">'
                   f'<a href="a/{i["id"]}.html">{escape(i["title"])}</a><br><small>{i["date"]}{" · cloud" if i["cloud"] else ""}{" · rançongiciel" if i["ransom"] else ""}</small></li>' for i in its)
    uniq = lambda k: sorted({i[k] for i in its if i[k]}, key=str.lower)
    form = ('<form id="f" role="search"><label>Recherche<input type="search" name="q"></label>'
            '<label>Catégorie<select name="cat"><option value="">Toutes</option><option value="cloud">Cloud</option><option value="autre">Hors cloud</option></select></label>'
            + select("sev", "Sévérité", uniq("sev")) + select("eco", "Écosystème", uniq("eco")) + select("vendor", "Vendeur", uniq("vendor")) +
            '<label>Période<select name="days"><option value="">Tout</option><option value="7">7 jours</option><option value="30">30 jours</option><option value="365">1 an</option></select></label>'
            '<label><span>Rançongiciel</span><input type="checkbox" name="ransom" value="1"></label></form>')
    (OUT / "index.html").write_text(PAGE.format(title="Cyber & Cloud News", home="index.html", body=
        f'<h1>Dernières vulnérabilités</h1>{form}<p id="n" aria-live="polite"></p><ul id="l">{rows}</ul>{SCRIPT}'))

if __name__ == "__main__":
    render(items(get(KEV), get(GHSA)))
