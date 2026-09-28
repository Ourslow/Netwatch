# Site produit (GitHub Pages)

Site statique, sans framework ni CDN — HTML + CSS + un peu de JS, polices vendorées, captures du portail.

- Publié par `.github/workflows/pages.yml` à chaque push touchant `site/` → https://ourslow.github.io/Netwatch/
- Aperçu local : `python3 -m http.server 8080 --directory site` puis http://localhost:8080
- Captures : `assets/img/*.webp` (générées depuis le labo, données de démo `make demo-data`)
- Le nom « NetWatch » est un nom de code : à remplacer dans `index.html` (rechercher `NetWatch`) une fois le nom commercial déposé.
