"""Génère un site statique cyber/cloud. Sources: CISA KEV (domaine public), GitHub Advisory DB (CC-BY 4.0)."""
import json, re, urllib.request
from datetime import date, timedelta
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
    req = urllib.request.Request(url, headers={"User-Agent": "technews-builder"})
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
            body=f'{v["shortDescription"]}\n\nAction requise : {v["requiredAction"]}\n\nUtilisée par des rançongiciels : {v["knownRansomwareCampaignUse"]}',
            source="CISA KEV (domaine public)", url=f'https://nvd.nist.gov/vuln/detail/{v["cveID"]}', cloud=kev_cloud(v), sev="exploitée",
            ransom=v["knownRansomwareCampaignUse"] == "Known", eco="", vendor=v["vendorProject"]))
    for a in ghsa:
        pkgs = [p["package"] for p in a.get("vulnerabilities") or [] if p.get("package")]
        out.append(dict(id=a["ghsa_id"], date=a["published_at"][:10], title=a["summary"],
            body=(a.get("description") or "")[:3000], source="GitHub Advisory Database (CC-BY 4.0)",
            url=a.get("html_url") or f'https://github.com/advisories/{a["ghsa_id"]}',
            cloud=any(pkg_cloud(p["name"]) for p in pkgs), sev=a["severity"], ransom=False,
            eco=pkgs[0]["ecosystem"] if pkgs else "", vendor=""))
    return sorted(out, key=lambda i: i["date"], reverse=True)

PAGE = """<!doctype html><html lang="fr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>
:root{{--bg:#f4f5f7;--card:#fff;--ink:#111827;--muted:#4b5563;--line:#d1d5db;--strong:#111827;--hover:#f1f5f9;--code:#eef0f3;
--crit:#b91c1c;--crit-bg:#fef2f2;--high:#b45309;--high-bg:#fffbeb;--med:#1d4ed8;--med-bg:#eff6ff;--cloud:#0f766e;--cloud-bg:#f0fdfa}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0d1117;--card:#161b22;--ink:#e6edf3;--muted:#9da7b3;--line:#30363d;--strong:#f0f6fc;--hover:#1f2630;--code:#21262d;
--crit:#f87171;--crit-bg:#2d1215;--high:#fbbf24;--high-bg:#2a1f0d;--med:#60a5fa;--med-bg:#122036;--cloud:#2dd4bf;--cloud-bg:#0d2624}}}}
*{{box-sizing:border-box;border-radius:0}}
body{{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,sans-serif}}
a{{color:var(--ink)}}
header{{background:var(--card);border-bottom:1px solid var(--line)}}
.wrap{{max-width:56rem;margin:0 auto;padding:.85rem 1rem;display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:.5rem 1.5rem}}
.brand{{text-decoration:none;font-weight:800;letter-spacing:.06em}}
nav{{display:flex;gap:1.25rem}}
nav a{{text-decoration:none;padding:.2rem 0;border-bottom:2px solid transparent}}
nav a:hover,nav a[aria-current=page]{{border-bottom-color:var(--strong);font-weight:600}}
main{{max-width:56rem;margin:0 auto;padding:1.5rem 1rem 3rem}}
h1{{font-size:1.5rem;line-height:1.25;margin:0 0 .75rem;padding-bottom:.5rem;border-bottom:2px solid var(--strong)}}
h2{{font-size:1.1rem;margin:2rem 0 .75rem;text-transform:uppercase;letter-spacing:.04em}}
form{{display:grid;grid-template-columns:repeat(auto-fill,minmax(10.5rem,1fr));gap:.75rem;align-items:end;padding:1rem;background:var(--card);border:1px solid var(--line)}}
label{{display:flex;flex-direction:column;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}}
input,select,button{{font:inherit;font-size:.95rem;margin-top:.25rem;padding:.45rem .6rem;border:1px solid var(--line);background:var(--bg);color:var(--ink);height:2.35rem}}
label.chk{{flex-direction:row;align-items:center;gap:.5rem;height:2.35rem;color:var(--ink);cursor:pointer}}
input[type=checkbox]{{width:1.15rem;height:1.15rem;margin:0;accent-color:var(--strong)}}
button{{background:var(--card);border:1px solid var(--strong);font-size:.78rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;cursor:pointer;padding:0 .9rem}}
button:hover{{background:var(--strong);color:var(--card)}}
:focus-visible{{outline:2px solid var(--strong);outline-offset:2px}}
#n{{font-weight:700;margin:1rem 0 .5rem}}
ul{{list-style:none;padding:0;margin:0;display:grid;gap:.5rem}}
#l li,main>ul li{{background:var(--card);border:1px solid var(--line);padding:.85rem 1rem}}
#l li:hover,main>ul li:hover{{border-color:var(--strong);background:var(--hover)}}
li[hidden]{{display:none}}
li a{{font-weight:600;text-decoration:none}}
li a:hover{{text-decoration:underline}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(11rem,1fr));gap:.75rem}}
.tile{{display:block;background:var(--card);border:1px solid var(--line);border-top:3px solid var(--strong);padding:1rem;text-decoration:none}}
.tile.warn{{border-top-color:var(--crit)}}
.tile:hover{{border-color:var(--strong);background:var(--hover)}}
.tile b{{display:block;font-size:2.1rem;line-height:1.05;margin-bottom:.25rem}}
.tags{{display:flex;flex-wrap:wrap;gap:.35rem;align-items:center;margin-top:.45rem;font-size:.82rem;color:var(--muted)}}
.b{{display:inline-block;padding:.1rem .4rem;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em;border:1px solid currentColor}}
.b-exploitee,.b-critical,.b-ransom{{color:var(--crit);background:var(--crit-bg)}}
.b-high{{color:var(--high);background:var(--high-bg)}}
.b-medium{{color:var(--med);background:var(--med-bg)}}
.b-low,.b-meta{{color:var(--muted);background:var(--code)}}
.b-cloud{{color:var(--cloud);background:var(--cloud-bg)}}
.b-id{{font-family:ui-monospace,monospace;color:var(--ink);background:var(--code);border-color:var(--line)}}
.back{{margin:0 0 1rem;font-size:.9rem;color:var(--muted)}}
.doc{{background:var(--card);border:1px solid var(--line);padding:1.25rem;margin-top:1rem}}
.doc h2,.doc h3{{text-transform:none;letter-spacing:0;margin:1.25rem 0 .5rem}}
.doc p{{margin:.6rem 0}}.doc ul{{display:block;list-style:square;padding-left:1.25rem;margin:.5rem 0}}
.doc li{{margin:.25rem 0}}.doc code{{font-family:ui-monospace,monospace;font-size:.9em;background:var(--code);padding:.1rem .3rem}}
.doc pre{{background:var(--code);border:1px solid var(--line);padding:.85rem;overflow-x:auto}}
.doc pre code{{background:none;padding:0}}
.callout{{border-left:3px solid var(--crit);background:var(--crit-bg);padding:.75rem 1rem;margin:.85rem 0}}
#more{{margin-top:1rem;width:100%;height:2.6rem}}
</style><header><div class="wrap"><a class="brand" href="{root}index.html">TECHNEWS</a><nav><a href="{root}index.html"{nav_dash}>Tableau de bord</a><a href="{root}liste.html"{nav_list}>Toutes les failles</a></nav></div></header><main>{body}</main></html>"""

# Filtre côté client sur les data-* de chaque <li>; l'état vit dans le hash pour qu'une vue filtrée soit partageable.
SCRIPT = """<script>
const F=document.getElementById('f'),L=[...document.querySelectorAll('#l li')],N=document.getElementById('n'),M=document.getElementById('more');
let lim=50;
function run(){const q=new FormData(F),s=new URLSearchParams();for(const[k,v]of q)if(v)s.set(k,v);history.replaceState(null,'','#'+s);
const t=(q.get('q')||'').toLowerCase(),d=+q.get('days'),now=Date.now();let n=0,shown=0;
for(const l of L){const x=l.dataset,ok=(!q.get('cat')||x.cat==q.get('cat'))&&(!q.get('sev')||x.sev==q.get('sev'))&&(!q.get('ransom')||x.ransom=='1')
&&(!q.get('eco')||x.eco==q.get('eco'))&&(!q.get('vendor')||x.vendor==q.get('vendor'))&&(!d||now-Date.parse(x.date)<d*864e5)&&(!t||l.textContent.toLowerCase().includes(t));
if(ok){n++;l.hidden=shown>=lim;if(shown<lim)shown++}else l.hidden=true}
N.textContent=n+' résultat'+(n>1?'s':'');M.hidden=shown>=n;M.textContent='Afficher plus ('+(n-shown)+' restants)'}
for(const[k,v]of new URLSearchParams(location.hash.slice(1))){const e=F.elements[k];if(e)e.type=='checkbox'?e.checked=true:e.value=v}
F.addEventListener('input',()=>{lim=50;run()});
document.getElementById('rst').addEventListener('click',()=>{F.reset();lim=50;run()});
M.addEventListener('click',()=>{lim+=50;run()});
run();
</script>"""

def select(name, label, values):
    opts = "".join(f'<option value="{escape(v)}">{escape(v)}</option>' for v in values)
    return f'<label>{label}<select name="{name}"><option value="">Tous</option>{opts}</select></label>'

def why(i):
    return ("Utilisée par des rançongiciels" if i["ransom"] else "Activement exploitée par des attaquants" if i["sev"] == "exploitée"
            else "Sévérité critique" if i["sev"] == "critical" else f'Sévérité {i["sev"]}')

def badges(i):
    sev_cls = "b-" + i["sev"].replace("é", "e")
    parts = [f'<span class="b b-id">{escape(i["id"])}</span>', f'<span class="b {sev_cls}">{escape(i["sev"])}</span>']
    if i["ransom"]:
        parts.append('<span class="b b-ransom">rançongiciel</span>')
    if i["cloud"]:
        parts.append('<span class="b b-cloud">cloud</span>')
    for extra in (i["vendor"], i["eco"]):
        if extra:
            parts.append(f'<span class="b b-meta">{escape(extra)}</span>')
    return "".join(parts)

def md_html(text):
    """Convertit un sous-ensemble sûr de Markdown (titres, listes, code, gras) après échappement HTML."""
    inline = lambda s: re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", re.sub(r"`([^`]+)`", r"<code>\1</code>", escape(s)))
    out = []
    for idx, part in enumerate(re.split(r"```[^\n]*\n(.*?)```", text, flags=re.S)):
        if idx % 2:
            out.append(f"<pre><code>{escape(part.strip())}</code></pre>")
            continue
        for blk in re.split(r"\n\s*\n", part.strip()):
            if not blk:
                continue
            lines = blk.splitlines()
            if lines[0].startswith("### "):
                out.append(f"<h3>{inline(lines[0][4:])}</h3>")
            elif lines[0].startswith(("## ", "# ")):
                out.append(f"<h2>{inline(lines[0].lstrip('# '))}</h2>")
            elif all(l.lstrip().startswith(("- ", "* ")) for l in lines):
                out.append("<ul>" + "".join(f"<li>{inline(l.lstrip()[2:])}</li>" for l in lines) + "</ul>")
            elif blk.startswith("Action requise :"):
                out.append(f'<div class="callout"><strong>Action requise :</strong> {inline(blk[16:].strip())}</div>')
            else:
                out.append("<p>" + "<br>".join(inline(l) for l in lines) + "</p>")
    return "".join(out) or "<p>Aucune description disponible.</p>"

def dashboard(its, today):
    since = lambda days: [i for i in its if i["date"] >= (today - timedelta(days=days)).isoformat()]
    week = since(7)
    tiles = [("Failles exploitées", "sev=exploitée", lambda i: i["sev"] == "exploitée", " warn"),
             ("Liées à des rançongiciels", "ransom=1", lambda i: i["ransom"], " warn"),
             ("Failles critiques", "sev=critical", lambda i: i["sev"] == "critical", ""),
             ("Touchent le cloud", "cat=cloud", lambda i: i["cloud"], "")]
    cards = "".join(f'<a class="tile{cls}" href="liste.html#days=7&{q}"><b>{sum(map(f, week))}</b>{label}</a>' for label, q, f, cls in tiles)
    # Importance : rançongiciel > exploitée > critique, puis la plus récente.
    top = sorted(since(30), key=lambda i: (i["ransom"], i["sev"] == "exploitée", i["sev"] == "critical", i["date"]), reverse=True)[:5]
    rows = "".join(f'<li><a href="a/{i["id"]}.html">{escape(i["title"])}</a><div class="tags"><span>{i["date"]}</span>{badges(i)}<span>{why(i)}</span></div></li>' for i in top)
    return (f'<h1>Tableau de bord</h1><p>Les nouvelles failles de sécurité à connaître, mises à jour plusieurs fois par jour. Données au {today:%d/%m/%Y}.</p>'
            f'<h2>Ces 7 derniers jours</h2><div class="tiles">{cards}</div>'
            f'<h2>Les 5 failles les plus importantes du mois</h2>' + (f'<ul>{rows}</ul>' if rows else '<p>Aucune nouvelle faille ce mois-ci.</p>') +
            '<p><a href="liste.html">Voir toutes les failles →</a></p>')

def render(its, today=None):
    today = today or date.today()
    OUT.mkdir(exist_ok=True); (OUT / "a").mkdir(exist_ok=True)  # liens internes uniquement
    for i in its:
        src_link = f'<a href="{escape(i["url"])}" rel="noopener noreferrer" target="_blank">{escape(i["source"])} ↗</a>'
        (OUT / "a" / f'{i["id"]}.html').write_text(PAGE.format(title=escape(i["title"]), root="../", nav_dash="", nav_list="", body=
            f'<p class="back"><a href="../index.html">← Tableau de bord</a> · <a href="../liste.html">Toutes les failles</a></p>'
            f'<h1>{escape(i["title"])}</h1>'
            f'<div class="tags"><span>{i["date"]}</span>{badges(i)}<span>Source : {src_link}</span></div>'
            f'<article class="doc">{md_html(i["body"])}</article>'))
    rows = "".join(f'<li data-cat="{"cloud" if i["cloud"] else "autre"}" data-sev="{escape(i["sev"])}" data-ransom="{int(i["ransom"])}" data-eco="{escape(i["eco"])}" data-vendor="{escape(i["vendor"])}" data-date="{i["date"]}">'
                   f'<a href="a/{i["id"]}.html">{escape(i["title"])}</a><div class="tags"><span>{i["date"]}</span>{badges(i)}</div></li>' for i in its)
    uniq = lambda k: sorted({i[k] for i in its if i[k]}, key=str.lower)
    form = ('<form id="f" role="search"><label>Recherche<input type="search" name="q" placeholder="CVE, produit, mot-clé…"></label>'
            '<label>Catégorie<select name="cat"><option value="">Toutes</option><option value="cloud">Cloud</option><option value="autre">Hors cloud</option></select></label>'
            + select("sev", "Sévérité", uniq("sev")) + select("eco", "Écosystème", uniq("eco")) + select("vendor", "Éditeur", uniq("vendor")) +
            '<label>Période<select name="days"><option value="">Tout</option><option value="7">7 jours</option><option value="30">30 jours</option><option value="365">1 an</option></select></label>'
            '<label class="chk"><input type="checkbox" name="ransom" value="1">Rançongiciel</label>'
            '<button type="button" id="rst">Réinitialiser</button></form>')
    (OUT / "index.html").write_text(PAGE.format(title="TechNews", root="", nav_dash=' aria-current="page"', nav_list="", body=dashboard(its, today)))
    (OUT / "liste.html").write_text(PAGE.format(title="Toutes les failles · TechNews", root="", nav_dash="", nav_list=' aria-current="page"', body=
        f'<h1>Toutes les failles</h1>{form}<p id="n" aria-live="polite"></p><ul id="l">{rows}</ul><button id="more" type="button" hidden></button>{SCRIPT}'))

if __name__ == "__main__":
    render(items(get(KEV), get(GHSA)))
