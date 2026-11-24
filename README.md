# TechNews

Site statique de veille cybersécurité et cloud en français, sans serveur ni dépendance externe.

## Intérêt

Le site rassemble au même endroit les failles publiées par deux sources gratuites : le catalogue CISA KEV (failles activement exploitées) et la base GitHub Advisory Database (avis relus). Il met en avant les vulnérabilités exploitées, liées à des rançongiciels, critiques ou touchant le cloud, et se reconstruit toutes les 6 heures via GitHub Actions.

## Utiliser le site

- `index.html` (tableau de bord) : affiche les compteurs des 7 derniers jours, cliquables pour filtrer la liste, ainsi que les 5 failles les plus importantes du mois.
- `liste.html` (toutes les failles) : permet de rechercher par CVE, produit ou mot-clé, de filtrer par catégorie (cloud ou hors cloud), sévérité, écosystème, éditeur, période ou usage par des rançongiciels, et de cocher ses technos préférées (mémorisées dans un cookie).
- Fiches détaillées : chaque faille renvoie vers une page locale avec sa description, l'action requise pour les entrées CISA KEV et un lien vers la source officielle.

## Générer en local

```bash
python build.py        # génère le site dans public/
python test_build.py   # lance les tests
```

Ouvrez ensuite `public/index.html` dans un navigateur, ou servez le dossier avec `python -m http.server -d public`.
