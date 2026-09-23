# -*- coding: utf-8 -*-
"""NetWatch — présentation BP2i (équipe Réseau / NPM). python-pptx, 16:9 large (13.333 × 7.5 in)."""
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "NetWatch_BP2i_reseau-npm.pptx")

# ── Palette (console SOC du portail) ─────────────────────────────────────────
NAVY   = RGBColor(0x0B, 0x12, 0x20)   # fond sombre (titre / clôture)
NAVY2  = RGBColor(0x14, 0x1F, 0x36)   # cartes sur fond sombre
INK    = RGBColor(0x11, 0x1B, 0x2E)   # texte principal sur clair
MUTED  = RGBColor(0x5B, 0x67, 0x7D)   # texte secondaire
CYAN   = RGBColor(0x0E, 0xA5, 0xC0)   # accent (plus dense que le 22D3EE écran, lisible en salle)
CYAN_L = RGBColor(0xE6, 0xF7, 0xFA)   # teinte de carte
GREY_L = RGBColor(0xF3, 0xF5, 0xF8)   # teinte de carte neutre
WHITE  = RGBColor(0xFF, 0xFF, 0xFF)
RED    = RGBColor(0xC8, 0x3E, 0x4D)
GREEN  = RGBColor(0x1E, 0x9E, 0x6A)
AMBER  = RGBColor(0xD9, 0x8E, 0x1A)
FONT = "Calibri"

prs = Presentation()
prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
BLANK = prs.slide_layouts[6]
W, H = 13.333, 7.5


# ── Helpers ──────────────────────────────────────────────────────────────────
def bg(slide, color):
    f = slide.background.fill; f.solid(); f.fore_color.rgb = color

def rect(slide, x, y, w, h, fill, shape=MSO_SHAPE.RECTANGLE, line=None, radius=None):
    s = slide.shapes.add_shape(shape, Inches(x), Inches(y), Inches(w), Inches(h))
    s.fill.solid(); s.fill.fore_color.rgb = fill
    if line is None: s.line.fill.background()
    else: s.line.color.rgb = line; s.line.width = Pt(0.75)
    s.shadow.inherit = False
    if radius is not None and shape == MSO_SHAPE.ROUNDED_RECTANGLE:
        s.adjustments[0] = radius
    return s

def text(slide, x, y, w, h, runs, size=14, color=INK, bold=False, align=PP_ALIGN.LEFT,
         anchor=MSO_ANCHOR.TOP, font=FONT, margin=0.05, line_spacing=1.1, space_after=4):
    """runs : str | list de paragraphes ; un paragraphe = str | list de (texte, {opts})."""
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame; tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(margin); tf.margin_top = tf.margin_bottom = Inches(0.03)
    tf.vertical_anchor = anchor
    paras = runs if isinstance(runs, list) else [runs]
    for i, p in enumerate(paras):
        para = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        para.alignment = align; para.line_spacing = line_spacing; para.space_after = Pt(space_after)
        segs = p if isinstance(p, list) else [(p, {})]
        for seg in segs:
            t, o = (seg if isinstance(seg, tuple) else (seg, {}))
            r = para.add_run(); r.text = t
            r.font.name = o.get("font", font); r.font.size = Pt(o.get("size", size))
            r.font.bold = o.get("bold", bold); r.font.italic = o.get("italic", False)
            r.font.color.rgb = o.get("color", color)
    return tb

def bullets(slide, x, y, w, h, items, size=14, color=INK, gap=6, bullet_color=CYAN):
    """Liste à puces (puce = ▸ colorée, retrait suspendu via tabulation simple)."""
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame; tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(0.05); tf.margin_top = tf.margin_bottom = Inches(0.03)
    for i, it in enumerate(items):
        para = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        para.space_after = Pt(gap); para.line_spacing = 1.08
        r = para.add_run(); r.text = "▸ "; r.font.name = FONT; r.font.size = Pt(size); r.font.color.rgb = bullet_color; r.font.bold = True
        segs = it if isinstance(it, list) else [(it, {})]
        for seg in segs:
            t, o = (seg if isinstance(seg, tuple) else (seg, {}))
            r = para.add_run(); r.text = t; r.font.name = FONT; r.font.size = Pt(o.get("size", size))
            r.font.bold = o.get("bold", False); r.font.color.rgb = o.get("color", color); r.font.italic = o.get("italic", False)
    return tb

def title(slide, t, sub=None, dark=False):
    c = WHITE if dark else INK
    text(slide, 0.6, 0.38, 12.1, 0.8, t, size=32, bold=True, color=c)
    if sub:
        text(slide, 0.6, 1.08, 12.1, 0.5, sub, size=15, color=(RGBColor(0xB8, 0xC4, 0xD6) if dark else MUTED))

def footer(slide, n, dark=False):
    c = RGBColor(0x7C, 0x8A, 0xA3) if dark else MUTED
    text(slide, 0.6, 7.02, 9, 0.3, "NetWatch (nom de code) · Axians — présentation BP2i · équipe Réseau / NPM", size=9, color=c)
    text(slide, 12.0, 7.02, 0.75, 0.3, str(n), size=9, color=c, align=PP_ALIGN.RIGHT)

def num_circle(slide, x, y, n, d=0.42, fill=CYAN, color=WHITE, size=13):
    c = rect(slide, x, y, d, d, fill, MSO_SHAPE.OVAL)
    tf = c.text_frame; tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    p = tf.paragraphs[0]; p.alignment = PP_ALIGN.CENTER; tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    r = p.add_run(); r.text = str(n); r.font.name = FONT; r.font.size = Pt(size); r.font.bold = True; r.font.color.rgb = color
    return c

def card(slide, x, y, w, h, head, body, fill=GREY_L, head_color=INK, body_size=13, n=None, head_size=15):
    rect(slide, x, y, w, h, fill, MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.06)
    hx = x + 0.25
    if n is not None:
        num_circle(slide, x + 0.22, y + 0.22, n); hx = x + 0.78
    text(slide, hx, y + 0.18, w - (hx - x) - 0.2, 0.5, head, size=head_size, bold=True, color=head_color)
    if isinstance(body, list):
        bullets(slide, x + 0.2, y + 0.72, w - 0.4, h - 0.85, body, size=body_size, gap=4)
    else:
        text(slide, x + 0.25, y + 0.72, w - 0.5, h - 0.85, body, size=body_size, color=INK)

def stat(slide, x, y, w, h, value, label, fill=CYAN_L, vcolor=CYAN):
    rect(slide, x, y, w, h, fill, MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.08)
    text(slide, x, y + 0.18, w, 0.9, value, size=36, bold=True, color=vcolor, align=PP_ALIGN.CENTER)
    text(slide, x + 0.15, y + 1.05, w - 0.3, h - 1.15, label, size=12, color=MUTED, align=PP_ALIGN.CENTER)

def arrow(slide, x, y, w, h=0.35, fill=CYAN):
    return rect(slide, x, y, w, h, fill, MSO_SHAPE.RIGHT_ARROW)

def image(slide, path, x, y, w=None, h=None, frame=True):
    pic = slide.shapes.add_picture(os.path.join(HERE, path), Inches(x), Inches(y),
                                   Inches(w) if w else None, Inches(h) if h else None)
    if frame:
        pic.line.color.rgb = RGBColor(0xD5, 0xDB, 0xE5); pic.line.width = Pt(0.75)
    return pic

def notes(slide, s):
    slide.notes_slide.notes_text_frame.text = s

def table(slide, x, y, w, rows, col_w, head_fill=NAVY2, size=12, row_h=0.42):
    nrows, ncols = len(rows), len(rows[0])
    shp = slide.shapes.add_table(nrows, ncols, Inches(x), Inches(y), Inches(w), Inches(row_h * nrows))
    tbl = shp.table
    for j, cw in enumerate(col_w): tbl.columns[j].width = Inches(cw)
    for i, row in enumerate(rows):
        tbl.rows[i].height = Inches(row_h)
        for j, val in enumerate(row):
            cell = tbl.cell(i, j); cell.margin_left = cell.margin_right = Inches(0.08)
            cell.margin_top = cell.margin_bottom = Inches(0.03)
            cell.fill.solid(); cell.fill.fore_color.rgb = head_fill if i == 0 else (WHITE if i % 2 else GREY_L)
            tf = cell.text_frame; tf.word_wrap = True
            p = tf.paragraphs[0]; r = p.add_run(); r.text = val
            r.font.name = FONT; r.font.size = Pt(size); r.font.bold = (i == 0 or j == 0)
            r.font.color.rgb = WHITE if i == 0 else INK
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
    return tbl

n = 0
def new(dark=False):
    global n; n += 1
    s = prs.slides.add_slide(BLANK); bg(s, NAVY if dark else WHITE); footer(s, n, dark); return s


# ═════════════════════════════════════════════════════════════════════════════
# 1 — Titre
s = new(dark=True)
rect(s, 0.6, 2.05, 0.16, 1.55, CYAN)
text(s, 0.95, 1.95, 11, 1.1, "NetWatch", size=54, bold=True, color=WHITE)
text(s, 0.95, 2.95, 11.5, 0.7, "Sonde NPM / NDR open-source — souveraine, on-prem, déployée en 30 minutes", size=22, color=RGBColor(0xB8, 0xC4, 0xD6))
text(s, 0.95, 4.25, 11, 0.5, "Présentation BP2i — équipe Réseau / NPM", size=18, bold=True, color=CYAN)
text(s, 0.95, 4.75, 11, 0.9, ["Axians · Vinci Energies — Nicolas Malok, analyste observabilité NPM", "Septembre 2026 · version 2.1"], size=14, color=RGBColor(0xB8, 0xC4, 0xD6))
text(s, 0.95, 6.35, 11, 0.4, "Démonstration live sur une sonde réelle en fin de séance", size=12, color=RGBColor(0x7C, 0x8A, 0xA3), )
notes(s, "Bonjour. Je vais vous présenter NetWatch : une sonde d'observabilité réseau open-source que nous avons développée et éprouvée chez Axians. "
         "Le fil rouge : ce qu'elle voit, comment elle le calcule, ce qu'elle ne fait pas, et ce qu'on vous propose de tester. Démo live à la fin sur une sonde qui tourne.")

# ═════════════════════════════════════════════════════════════════════════════
# 2 — Le constat
s = new()
title(s, "Le trou dans la couverture", "Ce que le NPM commercial ne voit pas — et pourquoi ça coûte")
card(s, 0.6, 1.8, 3.9, 2.55, "Périmètres non instrumentés", [
    "agences et sites secondaires", "labs, hors-prod, pré-production", "filiales et sites distants",
    "segments IoT / OT / gestion"], n=1)
card(s, 4.72, 1.8, 3.9, 2.55, "Coût marginal d'une sonde", [
    "licence par sonde : 10–100 k€ / an", "prix ≠ valeur du périmètre couvert",
    "résultat : on choisit de ne pas voir"], n=2)
card(s, 8.84, 1.8, 3.9, 2.55, "Exigences réglementaires", [
    "DORA (art. 9–10) : surveillance et détection sur l'ensemble du SI",
    "NIS2 : journalisation, détection, réponse", "l'audit ne s'arrête pas au cœur de réseau"], n=3)
rect(s, 0.6, 4.75, 12.13, 1.45, CYAN_L, MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.08)
text(s, 0.9, 4.93, 11.6, 1.1, [
    [("La question : ", {"bold": True}), ("comment instrumenter les 20 % de périmètre restants avec les mêmes indicateurs "
     "(ART, santé TCP, SLA, flux) — sans multiplier les licences, et sans qu'une donnée sorte du SI ?", {})]], size=15)
notes(s, "Le constat qu'on retrouve sur la plupart des grands SI : le NPM commercial couvre le cœur, très bien, et autour il reste des périmètres "
         "qu'on n'instrumente pas parce que le coût d'une sonde ne se justifie pas. DORA et NIS2 rendent ce trou visible dans l'audit. "
         "La question n'est pas de remplacer ce qui marche, c'est de couvrir le reste avec le même vocabulaire.")

# ═════════════════════════════════════════════════════════════════════════════
# 3 — NetWatch en une phrase + chiffres
s = new()
title(s, "NetWatch en une phrase", "Une sonde passive + active qui reproduit les fonctions clés d'un NPM/NDR avec des briques open-source")
text(s, 0.6, 1.8, 12.1, 1.0, [
    [("Un port SPAN, une VM, une commande. ", {"bold": True, "color": CYAN}),
     ("Zeek, Snort et Suricata analysent le trafic ; GoFlow2 collecte NetFlow/IPFIX/sFlow ; Prometheus scrute SNMP et lance des sondes actives ; "
      "Elasticsearch stocke ; un portail unique restitue — flux, temps de réponse, santé TCP, SLA, alertes.", {})]], size=16)
stat(s, 0.6, 3.15, 2.9, 1.9, "0 €", "de licence — AGPL v3, code auditable")
stat(s, 3.68, 3.15, 2.9, 1.9, "100 %", "on-prem — aucune donnée ne sort, IA locale comprise")
stat(s, 6.76, 3.15, 2.9, 1.9, "24", "services conteneurisés, 1 ou 2 VM")
stat(s, 9.84, 3.15, 2.9, 1.9, "30 min", "d'installation (install.sh), 10 min de démo")
text(s, 0.6, 5.4, 12.1, 1.3, [
    [("Ce que ça n'est pas : ", {"bold": True}), ("un remplaçant de votre NPM cœur de réseau. ", {}),
     ("Ce que c'est : ", {"bold": True}), ("le même vocabulaire — ART p50/p95/p99, retransmissions, zero-window, SLA heures ouvrées — "
     "porté sur les périmètres où une sonde commerciale n'ira jamais, et un labo pour tester des scénarios avant de les déployer.", {})]], size=14, color=INK)
notes(s, "En une phrase : un port SPAN, une VM, une commande. Trois moteurs d'analyse, la collecte de flux, du SNMP, des sondes actives, "
         "et un portail qui parle le même vocabulaire que vos outils actuels. Zéro licence, zéro donnée sortante — même l'IA d'aide à l'analyse tourne en local.")

# ═════════════════════════════════════════════════════════════════════════════
# 4 — Positionnement : complément
s = new()
title(s, "Complément, pas remplacement", "Où NetWatch se place par rapport au NPM commercial de BP2i")
# centre : cœur
rect(s, 4.5, 2.35, 4.3, 1.9, NAVY2, MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.08)
text(s, 4.6, 2.5, 4.1, 0.5, "Cœur BP2i", size=18, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
text(s, 4.6, 3.0, 4.1, 1.2, ["NPM commercial (Netscout / Riverbed)", "datacenters, WAN, applications critiques", "→ inchangé"], size=13, color=RGBColor(0xB8, 0xC4, 0xD6), align=PP_ALIGN.CENTER)
# satellites
sat = [(0.6, 1.75, "Agences / sites secondaires", "1 sonde par site, autonome"),
       (0.6, 4.6, "Labs · hors-prod · préprod", "tester une signature, un seuil, une règle"),
       (9.4, 1.75, "Filiales · sites distants", "visibilité locale, rien ne transite"),
       (9.4, 4.6, "Qualification & démonstration", "dégrossir un besoin avant un PoC éditeur")]
for x, y, h1, h2 in sat:
    rect(s, x, y, 3.35, 1.3, CYAN_L, MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.1)
    text(s, x + 0.2, y + 0.15, 3.0, 0.5, h1, size=14, bold=True, color=INK)
    text(s, x + 0.2, y + 0.62, 3.0, 0.6, h2, size=12, color=MUTED)
# liaisons
for (x1, y1) in [(3.95, 2.4), (3.95, 4.55)]:
    ln = s.shapes.add_connector(1, Inches(x1), Inches(y1), Inches(4.5), Inches(3.3)); ln.line.color.rgb = CYAN; ln.line.width = Pt(1.5)
for (x1, y1) in [(9.4, 2.4), (9.4, 4.55)]:
    ln = s.shapes.add_connector(1, Inches(8.8), Inches(3.3), Inches(x1), Inches(y1)); ln.line.color.rgb = CYAN; ln.line.width = Pt(1.5)
text(s, 4.5, 4.45, 4.3, 0.8, [[("Même vocabulaire : ", {"bold": True}), ("ART · santé TCP · SLA · NetFlow · SNMP", {})]], size=12, color=INK, align=PP_ALIGN.CENTER)
rect(s, 0.6, 6.1, 12.13, 0.75, GREY_L, MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.1)
text(s, 0.85, 6.22, 11.7, 0.55, [[("Chaque sonde est autonome : ", {"bold": True}),
     ("stockage, analyse et restitution locaux — pas de collecteur central, pas de flux vers l'extérieur. Une consolidation multi-sites est possible (Elasticsearch cross-cluster), pas obligatoire.", {})]], size=12)
notes(s, "Le positionnement, pour qu'il n'y ait pas d'ambiguïté : votre cœur reste sur le NPM commercial. NetWatch va sur les périmètres périphériques, "
         "et sert de labo. L'intérêt pour une équipe réseau : les mêmes indicateurs partout, donc le même raisonnement de triage quel que soit le site.")

# ═════════════════════════════════════════════════════════════════════════════
# 5 — Architecture d'une sonde
s = new()
title(s, "Architecture d'une sonde", "Un pipeline capture → analyse → stockage → restitution, entièrement conteneurisé")
cols = [
    (0.6, "Entrées", NAVY2, WHITE, ["port SPAN / TAP (Zeek, Snort, Suricata, Arkime, ntopng)", "NetFlow v5/v9 · IPFIX · sFlow (UDP 2055/4739/6343)", "SNMP IF-MIB / LLDP-MIB", "sondes actives HTTP/ICMP/TCP/DNS"]),
    (3.72, "Analyse", CYAN_L, INK, ["Zeek 6.2 — conn/dns/http/ssl/x509, JA3/HASSH, intel", "Snort 3.3.5 + Suricata 7 — signatures, MITRE, Community ID", "GoFlow2 — flux normalisés JSON", "beacon-detect (RITA-lite), app-classifier (SNI)"]),
    (6.84, "Stockage", CYAN_L, INK, ["Elasticsearch 8.13 — logs, flux, sessions Arkime (ILM 30 j)", "Prometheus 2.51 — métriques, SNMP, Blackbox, capacity", "Filebeat — pipeline unique, GeoIP à l'ingestion", "NetBox — inventaire / IPAM (source de vérité)"]),
    (9.96, "Restitution", NAVY2, WHITE, ["Portail NetWatch — 22 pages, plage temporelle globale", "Grafana — 13 dashboards, alerting → AutoBlock / n8n", "Kibana Discover, Arkime, ntopng depuis le portail", "HTTPS unique (Caddy) + session unifiée"]),
]
for x, head, fill, col, items in cols:
    rect(s, x, 1.8, 2.9, 3.55, fill, MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.06)
    text(s, x + 0.2, 1.95, 2.5, 0.5, head, size=17, bold=True, color=col)
    bullets(s, x + 0.15, 2.5, 2.65, 2.8, items, size=12.5, color=col, gap=7, bullet_color=CYAN)
for x in (3.5, 6.62, 9.74):
    arrow(s, x, 3.42, 0.22, 0.3)
text(s, 0.6, 5.65, 12.1, 0.95, [
    [("Empreinte mesurée (labo, 14/09) : ", {"bold": True}),
     ("stack complète ≈ 6 Go RAM hors IA (ES 3 Go avec heap 2 Go, NetBox 1,2 Go, Kibana 0,5 Go, Suricata 0,3–1 Go) ; +4–5 Go quand le modèle IA est chargé. "
      "1 VM 4 vCPU / 16 Go, ou 2 VM Sensors (6 Go, port SPAN) + Data (10 Go). Rétention PCAP Arkime sur volume dédié.", {})]], size=12, color=INK)
notes(s, "L'architecture, de gauche à droite. Les entrées : un port SPAN pour les moteurs d'analyse et la capture, les flux depuis vos équipements, le SNMP, et des sondes actives. "
         "Trois moteurs sur le même trafic. Deux bases : Elasticsearch pour tout ce qui est événement, Prometheus pour les séries temporelles. "
         "Et une restitution unique. Les chiffres d'empreinte sont mesurés, pas estimés.")

# ═════════════════════════════════════════════════════════════════════════════
# 6 — Flux & performance (screenshot)
s = new()
title(s, "Flux & performance — ce que voit l'équipe réseau", "Page /flows du portail — données réelles du labo")
image(s, "flows.png", 0.6, 1.75, w=7.2)
bullets(s, 8.1, 1.75, 4.65, 5.0, [
    [("Top talkers / ports ", {"bold": True}), ("— NetFlow/IPFIX si vos équipements exportent, sinon repli automatique sur Zeek conn.log", {})],
    [("ART par service ", {"bold": True}), ("— p50 / p95 / p99 HTTP, DNS, TLS, seuils colorés (HTTP 200–500 ms, DNS 50–200 ms)", {})],
    [("Santé TCP ", {"bold": True}), ("— RTT, retransmissions par IP source, ratio zero-window (congestion côté récepteur)", {})],
    [("Trafic applicatif ", {"bold": True}), ("— dictionnaire SNI/domaine → application métier, catégories ; nDPI (ntopng) en complément", {})],
    [("SNMP ", {"bold": True}), ("— débit et saturation par interface, capacity planning (jours avant saturation)", {})],
    [("Plage globale 1 h → 30 j ", {"bold": True}), ("et filtre par hostgroup sur toutes les pages", {})],
], size=12.5, gap=7)
notes(s, "La page que vous utiliserez le plus. Top talkers, ART par service avec les percentiles, santé TCP avec les retransmissions et le zero-window, "
         "la classification applicative. Ce sont les mêmes indicateurs que sur vos outils — on verra sur la slide suivante comment ils sont calculés.")

# ═════════════════════════════════════════════════════════════════════════════
# 7 — Comment les métriques sont calculées
s = new()
title(s, "D'où viennent les chiffres", "Pas de boîte noire : chaque indicateur a une source et une formule vérifiables")
rows = [
    ["Indicateur", "Source brute", "Calcul", "Limite connue"],
    ["ART (Application Response Time)", "Zeek http.log / dns.log / ssl.log (ts requête → réponse)", "percentiles p50/p95/p99 par service (agrégation ES), fenêtre glissante", "protocoles chiffrés sans SNI : non classés"],
    ["RTT réseau", "handshake TCP dans Zeek conn.log (SYN → SYN/ACK)", "moyenne / p95 par paire, séparation Network Time vs Server Time", "estimation côté sonde (position du SPAN)"],
    ["Retransmissions · zero-window", "conn.log champ history (T/t = retrans., W/w = fenêtre nulle)", "ratio connexions affectées / total, top IP sources", "occurrence, pas encore durée des épisodes"],
    ["SLA passif", "p95 ART/RTT par heure vs cibles (200 ms HTTP, 50 ms DNS/RTT)", "% d'heures conformes sur N jours, heures ouvrées vs non", "besoin de trafic réel sur la fenêtre"],
    ["SLA actif", "Blackbox exporter (HTTP, ICMP, TCP, DNS) via Prometheus", "probe_success, latence, avg_over_time sur la plage", "dépend de la position réseau de la sonde"],
    ["Capacity planning", "SNMP IF-MIB ifHCInOctets / ifHCOutOctets", "predict_linear Prometheus → jours avant saturation", "linéaire, pas de saisonnalité"],
    ["Application", "SNI TLS + DNS (Zeek) + table ports", "dictionnaire domaine → application (425 ports, SaaS majeurs)", "70–80 % des cas ; pas de DPI propriétaire"],
]
table(s, 0.6, 1.75, 12.13, rows, [2.55, 3.35, 3.5, 2.73], size=10.5, row_h=0.6)
notes(s, "C'est la slide pour une équipe technique : chaque indicateur, sa source, sa formule, et sa limite. L'ART vient des timestamps requête/réponse de Zeek, "
         "le RTT du handshake, le zero-window du champ history de conn.log — la donnée existe nativement, on l'expose. "
         "Tout est dans le code, sous licence AGPL : vous pouvez vérifier chaque formule.")

# ═════════════════════════════════════════════════════════════════════════════
# 8 — Passif + actif (SLA)
s = new()
title(s, "Passif + actif", "Le passif voit le trafic qui existe ; l'actif vérifie que le service répond, même quand personne ne l'utilise")
image(s, "sla.png", 0.6, 1.75, w=7.2)
card(s, 0.6, 4.3, 3.5, 2.4, "SLA passif", ["conformité p95 HTTP / DNS / RTT sur N jours", "heures ouvrées vs nuits & week-ends", "timeline de compliance par jour"], fill=GREY_L, body_size=12)
card(s, 4.3, 4.3, 3.5, 2.4, "SLA actif — Blackbox", ["HTTP 2xx, ICMP, TCP connect, DNS A", "disponibilité + latence depuis la sonde", "cibles : un fichier YAML rechargé à chaud"], fill=CYAN_L, body_size=12)
bullets(s, 8.1, 1.75, 4.65, 5.0, [
    [("Pourquoi les deux : ", {"bold": True}), ("une passerelle qui ne répond plus à 3 h du matin ne génère aucun trafic — le passif ne la verra pas, l'actif oui.", {})],
    [("Triage de la home : ", {"bold": True}), ("une sonde KO remonte en critique, une disponibilité < 99 % en avertissement, avec le lien vers la preuve.", {})],
    [("Auto-surveillance : ", {"bold": True}), ("la sonde se surveille elle-même avec les mêmes sondes (portail, ES, Grafana) — page /status.", {})],
    [("Intégration : ", {"bold": True}), ("mêmes séries Prometheus que vos exporters existants ; alerting Grafana → webhook / n8n / ITSM.", {})],
], size=12.5, gap=8)
notes(s, "Un point que les équipes réseau apprécient : le couplage passif/actif dans la même vue. Le passif dit comment se comporte le trafic réel ; "
         "l'actif dit si le service répond. Les cibles Blackbox sont un fichier YAML rechargé à chaud — pas de redémarrage.")

# ═════════════════════════════════════════════════════════════════════════════
# 9 — L'inventaire au centre (NetBox)
s = new()
title(s, "Une adresse devient un serveur", "NetBox (IPAM) comme source de vérité : le contexte métier est injecté dans chaque vue")
image(s, "ip.png", 0.6, 1.75, w=7.2)
bullets(s, 8.1, 1.75, 4.65, 5.0, [
    [("Pivot IP : ", {"bold": True}), ("device, interface, site, préfixe, VLAN, rôle, tenant — lus dans NetBox via l'API (token v2), cache 2 min.", {})],
    [("Hostgroups : ", {"bold": True}), ("import des préfixes IPAM en un clic → un groupe par préfixe → filtre global sur toutes les pages (esprit NetScout).", {})],
    [("Mêmes widgets ", {"bold": True}), ("de performance pour un hôte, un groupe ou le site entier : ART, santé TCP, top talkers.", {})],
    [("Depuis le pivot : ", {"bold": True}), ("logs Zeek de l'adresse (Kibana, requête KQL préremplie) et sessions capturées (Arkime, filtre ip ==).", {})],
    [("Si vous avez déjà un IPAM : ", {"bold": True}), ("l'API NetBox est standard ; un export CSV type NetScout est aussi accepté pour les hostgroups.", {})],
], size=12.5, gap=8)
notes(s, "Le pivot IP : une adresse nue ne dit rien ; avec NetBox elle devient srv-erp-01, Datacenter Lyon, VLAN serveurs, production. "
         "Et les hostgroups — le découpage réseau que vous connaissez chez NetScout — viennent directement des préfixes de l'inventaire, pas d'un tableur.")

# ═════════════════════════════════════════════════════════════════════════════
# 10 — Quand il faut la preuve
s = new()
title(s, "Quand il faut la preuve", "Cinq outils complémentaires, une seule console, une seule session")
tools = [
    ("Arkime", "Full packet capture", ["capture continue sur le port SPAN, sessions indexées dans le même Elasticsearch", "filtre par IP depuis le pivot, export PCAP d'une session", "rétention par espace disque (ARKIME_FREE_SPACE_G)"]),
    ("Kibana", "Fouiller les logs", ["Discover sur des data views prêtes : zeek, suricata, snort, netflow, beacons, arkime", "ouvert depuis /zeek ou depuis une IP avec la requête préremplie"]),
    ("ntopng", "Visibilité nDPI", ["300+ protocoles reconnus en temps réel", "valide et complète le dictionnaire applicatif SNI"]),
    ("Analyse PCAP", "Conversation par conversation", ["tshark : handshake, retransmissions, fenêtre, QoS/VLAN, timeline", "notion de point d'écoute ; narration IA optionnelle"]),
]
for i, (name, sub, items) in enumerate(tools):
    x = 0.6 + i * 3.08
    rect(s, x, 1.8, 2.9, 3.35, GREY_L if i % 2 else CYAN_L, MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.06)
    text(s, x + 0.2, 1.95, 2.5, 0.45, name, size=18, bold=True, color=INK)
    text(s, x + 0.2, 2.38, 2.5, 0.4, sub, size=12, color=CYAN, bold=True)
    bullets(s, x + 0.15, 2.85, 2.65, 2.25, items, size=12, gap=6)
rect(s, 0.6, 5.5, 12.13, 0.7, NAVY2, MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.1)
text(s, 0.85, 5.62, 11.7, 0.45, "Un seul point d'entrée HTTPS (Caddy) : /grafana/, /kibana/, /arkime/, /ntopng/, /netbox/ — la session du portail vaut pour tous les outils.", size=12.5, color=WHITE)
notes(s, "Quand le tableau de bord ne suffit plus : Arkime pour le paquet, Kibana pour le log brut, ntopng pour la classification fine, et l'analyse de conversation TCP. "
         "Tout s'ouvre depuis le portail, au bon endroit, avec le bon filtre — et derrière un seul point d'entrée HTTPS avec une seule authentification.")

# ═════════════════════════════════════════════════════════════════════════════
# 11 — Sécurité (bonus)
s = new()
title(s, "Et la détection, dans la même sonde", "Le volet NDR : utile à l'équipe réseau pour distinguer un incident de performance d'un incident de sécurité")
image(s, "home-triage.png", 0.6, 1.7, w=12.13)
card(s, 0.6, 3.55, 3.9, 3.0, "Trois moteurs, un trafic", ["Zeek (protocoles, JA3/HASSH, intel), Snort 3, Suricata 7 (ET Open)", "corrélation Community ID entre Suricata et Zeek", "incidents = fenêtres 5 min + chaîne MITRE ATT&CK"], body_size=12.5)
card(s, 4.72, 3.55, 3.9, 3.0, "Comportemental", ["beaconing C2 (régularité des connexions), connexions longues, DNS tunneling", "threat intel Feodo / URLhaus, réputation IP", "score IOC composite, graphe interactif"], fill=CYAN_L, body_size=12.5)
card(s, 8.84, 3.55, 3.9, 3.0, "Réponse & aide à l'analyse", ["AutoBlock (iptables) en dry-run par défaut, allowlist", "escalade n8n → ServiceNow / JIRA", "édition IA : explication d'alerte par un modèle local (Ollama), optionnelle"], body_size=12.5)
notes(s, "Le bandeau de triage en haut de la home : une ligne pour dire si le réseau va bien, avec des chips cliquables vers la preuve. "
         "Pour une équipe réseau, l'intérêt du volet sécurité est surtout de ne pas chasser un problème de performance qui est en fait un incident. "
         "L'IA est une option — un modèle local, rien ne sort.")

# ═════════════════════════════════════════════════════════════════════════════
# 12 — Correspondance fonctionnelle
s = new()
title(s, "Correspondance fonctionnelle", "Ce que couvre NetWatch v2.1 face aux fonctions NPM que vous utilisez")
rows = [
    ["Fonction NPM", "NetWatch v2.1", "Équivalent commercial"],
    ["Flux NetFlow / IPFIX / sFlow", "GoFlow2 → Elasticsearch netflow-*, top talkers, top apps", "nGeniusONE · Gigamon · Riverbed"],
    ["Application Response Time", "Zeek → percentiles ES p50/p95/p99 par service, seuils", "nGeniusONE Service Triage · Riverbed"],
    ["Santé TCP (RTT, retrans., zero-window)", "conn.log history → ratios, top IP, seuils", "nGeniusONE TCP/IP Triage"],
    ["Supervision SNMP · capacity planning", "SNMP exporter IF-MIB, predict_linear", "Netscout · SolarWinds · PRTG"],
    ["Topologie L2/L3", "LLDP-MIB + ARP Zeek → carte D3.js", "Riverbed NetIM · SolarWinds NTM"],
    ["SLA / Business Hours", "p95 par heure vs cibles, heures ouvrées vs non ; sondes actives", "nGeniusONE · Riverbed"],
    ["Dictionnaire applicatif", "SNI / domaine → application + nDPI (ntopng)", "Riverbed AppFlow (1300 sign.) · Netscout DPI"],
    ["Full packet capture", "Arkime (sessions indexées, export PCAP)", "InfiniStreamNG · Gigamon"],
    ["Qualité VoIP", "SIP/RTP Zeek → MOS E-model G.107", "InfiniStreamNG · Empirix"],
    ["Coût de licence", "0 € (Community AGPL) ; Pro = support + fonctions avancées", "10 000 – 100 000+ € / an / sonde"],
]
table(s, 0.6, 1.75, 12.13, rows, [3.6, 5.0, 3.53], size=11, row_h=0.45)
notes(s, "La correspondance fonction par fonction. Ligne par ligne, vous avez d'un côté la brique NetWatch et sa méthode, de l'autre l'outil commercial équivalent. "
         "Deux lignes à retenir : le dictionnaire applicatif — SNI plus nDPI, pas de DPI propriétaire — et le coût.")

# ═════════════════════════════════════════════════════════════════════════════
# 13 — Souveraineté, exploitation, conformité
s = new()
title(s, "Souveraineté · exploitation · conformité", "Ce qu'un déploiement chez BP2i implique concrètement")
card(s, 0.6, 1.8, 3.9, 3.7, "Souveraineté", [
    "100 % on-prem : stockage, analyse, restitution sur la sonde",
    "aucune télémétrie, aucun appel sortant (GeoIP et threat intel = fichiers locaux, mise à jour maîtrisée)",
    "IA d'aide à l'analyse en local (Ollama) — désactivable",
    "code AGPL v3 : auditable, forkable, pas de dépendance éditeur",
    "briques standard : Zeek, Suricata, Elasticsearch, Prometheus, Grafana"], body_size=12)
card(s, 4.72, 1.8, 3.9, 3.7, "Exploitation", [
    "install.sh : Docker, prérequis noyau, secrets générés, interface détectée, service systemd",
    "HTTPS unique (Caddy) : TLS interne, Let's Encrypt ou certificat fourni ; auth unifiée",
    "backup.sh / restore.sh (config + snapshot ES), upgrade.sh versionné, CHANGELOG",
    "make health : exit code 0/1/2 pour votre supervision ; 140+ tests, CI",
    "2 VM Sensors / Data si le port SPAN et le stockage doivent être séparés"], fill=CYAN_L, body_size=12)
card(s, 8.84, 1.8, 3.9, 3.7, "Conformité", [
    "DORA art. 9 (protection & prévention) et 10 (détection) : surveillance continue, journalisation, alerting",
    "NIS2 : détection, réponse, preuve (PCAP, logs horodatés)",
    "matrices NIS2 · NIST CSF 2.0 · ANSSI · ISO 27001 dans le portail (/compliance)",
    "rapport exécutif PDF à la demande, historique",
    "à cadrer avec vous : durcissement, comptes nominatifs, rétention"], body_size=12)
notes(s, "Trois colonnes pour les questions qui arrivent toujours en second. Souveraineté : rien ne sort, y compris l'IA. Exploitation : ce qu'on a industrialisé ces dernières semaines — "
         "installation en une commande, HTTPS unique, sauvegarde, mise à jour, tests. Conformité : la sonde produit les preuves que DORA et NIS2 demandent ; "
         "le durcissement et la rétention se cadrent avec vous.")

# ═════════════════════════════════════════════════════════════════════════════
# 14 — Limites
s = new()
title(s, "Ce que NetWatch ne fait pas", "Les limites, avant que vous ne les trouviez vous-mêmes")
lim = [
    ("Support éditeur & garanties", "pas de SLA contractuel ni de TAM. Le support est porté par Axians (édition Pro) — à contractualiser."),
    ("Échelle", "1 sonde ≈ 1 site ; validé sur du trafic PME/labo, pas en multi-Tbps. Pas de sonde matérielle, pas d'agrégation de trafic type Gigamon."),
    ("DPI propriétaire", "classification par SNI/domaine + nDPI : 70–80 % des cas d'usage ; pas les 1 300 signatures d'un Riverbed AppFlow."),
    ("Métriques TCP fines", "zero-window en occurrence, pas en durée ; RTT estimé à la position du SPAN, pas côté client."),
    ("Certification produit", "aucune certification ANSSI / Critères Communs ; durcissement à votre charge selon vos standards."),
    ("Maturité", "v2.1 — validé en labo et sur Proxmox ; premier pilote client à faire. Multi-utilisateurs / RBAC prévus, pas livrés."),
]
for i, (h1, body) in enumerate(lim):
    x = 0.6 + (i % 2) * 6.15; y = 1.8 + (i // 2) * 1.6
    rect(s, x, y, 5.98, 1.4, GREY_L, MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.08)
    rect(s, x + 0.2, y + 0.2, 0.34, 0.34, RED, MSO_SHAPE.OVAL)
    text(s, x + 0.68, y + 0.13, 5.1, 0.45, h1, size=14, bold=True, color=INK)
    text(s, x + 0.68, y + 0.55, 5.1, 0.8, body, size=11.5, color=INK)
notes(s, "Je préfère lister les limites moi-même. Pas de support éditeur — c'est Axians qui le porte. Pas de multi-Tbps. Pas de DPI propriétaire. "
         "Le zero-window est compté, pas mesuré en durée. Aucune certification. Et c'est une v2.1 : validée en labo, le premier pilote client reste à faire — c'est l'objet de la proposition.")

# ═════════════════════════════════════════════════════════════════════════════
# 15 — Proposition : pilote
s = new()
title(s, "Proposition : un pilote de 6 semaines", "Un périmètre que vous n'instrumentez pas aujourd'hui, une VM, un port SPAN — et des critères de succès fixés au départ")
steps = [
    ("S1", "Cadrage", "choix du périmètre (agence, lab ou préprod), port SPAN / export NetFlow, VM 4 vCPU · 16 Go, comptes"),
    ("S2", "Installation", "install.sh, HTTPS, import des préfixes IPAM, cibles actives, seuils SLA alignés sur les vôtres"),
    ("S3–S5", "Observation", "exploitation par votre équipe ; comparaison des indicateurs avec le NPM cœur sur un flux commun ; un incident rejoué"),
    ("S6", "Bilan", "critères de succès, écarts constatés, décision : étendre, arrêter, ou intégrer au catalogue Axians"),
]
for i, (tag, h1, body) in enumerate(steps):
    x = 0.6 + i * 3.08
    rect(s, x, 1.85, 2.9, 2.6, CYAN_L if i % 2 == 0 else GREY_L, MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.06)
    text(s, x + 0.2, 2.0, 2.5, 0.45, tag, size=20, bold=True, color=CYAN)
    text(s, x + 0.2, 2.45, 2.5, 0.4, h1, size=15, bold=True, color=INK)
    text(s, x + 0.2, 2.9, 2.5, 1.5, body, size=11.5, color=INK)
    if i < 3: arrow(s, x + 2.92, 2.95, 0.18, 0.28)
text(s, 0.6, 4.75, 5.9, 0.4, "Critères de succès proposés", size=15, bold=True, color=INK)
bullets(s, 0.6, 5.15, 5.9, 1.7, [
    "un périmètre non instrumenté devient visible (flux, ART, SLA) en moins d'une journée",
    "écart des indicateurs communs avec le NPM cœur documenté et expliqué",
    "temps de qualification d'un incident de performance mesuré avant / après",
    "coût complet du pilote : la VM et le temps d'exploitation — pas de licence"], size=12, gap=5)
text(s, 6.9, 4.75, 5.8, 0.4, "Deux éditions, un seul dépôt", size=15, bold=True, color=INK)
bullets(s, 6.9, 5.15, 5.8, 1.7, [
    [("Community ", {"bold": True}), ("(AGPL v3) : sonde complète — moteurs, dashboards, install, health. Gratuite.", {})],
    [("Pro ", {"bold": True}), ("(abonnement, clé de licence) : support Axians, fonctions avancées, multi-utilisateurs. Le pilote se fait en Community.", {})],
    [("Passage Core → IA ", {"bold": True}), ("(assistant local) : deux lignes de configuration, aucune migration.", {})]], size=12, gap=5)
notes(s, "La proposition : six semaines, un périmètre que vous ne couvrez pas, une VM, un port SPAN. On fixe les critères de succès avant d'installer. "
         "Le pilote se fait en édition Community, donc sans licence ; l'édition Pro, c'est le support et les fonctions avancées si vous décidez d'étendre.")

# ═════════════════════════════════════════════════════════════════════════════
# 16 — Démo live
s = new()
title(s, "Démonstration live — 10 minutes", "Sur une sonde réelle : une question d'exploitant par étape, la page qui y répond")
demo = [
    ("Le réseau va bien, là, maintenant ?", "Home — triage, KPIs, plage globale"),
    ("Qui consomme, et est-ce que ça rame ?", "/flows — top talkers, ART, santé TCP · ntopng"),
    ("C'est quoi cette adresse ?", "/ip/<ip> — contexte NetBox, mêmes widgets"),
    ("Et si le lien tombe à 3 h du matin ?", "/sla — sondes Blackbox, ajout d'une cible à chaud"),
    ("Paquet par paquet ?", "Arkime depuis le pivot IP, export PCAP"),
    ("Montrez-moi le log brut", "/zeek → Kibana Discover, requête préremplie"),
    ("Tout ça, c'est fiable ?", "/status — 10 services, sondes 7/7, latences"),
    ("Vous me laissez quoi ?", "/report — PDF ; hostgroups importés de NetBox"),
]
for i, (q, page) in enumerate(demo):
    x = 0.6 + (i % 2) * 6.15; y = 1.8 + (i // 2) * 1.2
    rect(s, x, y, 5.98, 1.02, GREY_L if i % 2 == 0 else CYAN_L, MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.1)
    num_circle(s, x + 0.2, y + 0.3, i + 1)
    text(s, x + 0.78, y + 0.12, 5.05, 0.45, q, size=14, bold=True, color=INK)
    text(s, x + 0.78, y + 0.55, 5.05, 0.4, page, size=12, color=MUTED)
notes(s, "La démo suit huit questions qu'un exploitant pose vraiment, et pour chacune la page qui répond. Si un service ne répond pas pendant la démo, "
         "make health depuis un terminal et on continue sur la page suivante — tout est rejouable.")

# ═════════════════════════════════════════════════════════════════════════════
# 17 — Clôture
s = new(dark=True)
rect(s, 0.6, 2.2, 0.16, 1.2, CYAN)
text(s, 0.95, 2.1, 11, 0.9, "Questions", size=44, bold=True, color=WHITE)
text(s, 0.95, 3.05, 11.5, 0.6, "Un pilote de 6 semaines, un périmètre non instrumenté, zéro licence.", size=20, color=RGBColor(0xB8, 0xC4, 0xD6))
text(s, 0.95, 4.35, 11, 1.4, ["Nicolas Malok — analyste observabilité NPM, Axians (Vinci Energies)",
                              "Dépôt : github.com/Ourslow/Netwatch · licence AGPL v3 · v2.1 (septembre 2026)",
                              "Documentation : parcours de démo, plan de déploiement 2 VM, troubleshooting, checklist de validation"], size=14, color=RGBColor(0xB8, 0xC4, 0xD6))
text(s, 0.95, 6.35, 11, 0.4, "« NetWatch » est un nom de code — le nom commercial est en cours de dépôt.", size=11, color=RGBColor(0x7C, 0x8A, 0xA3))
notes(s, "Merci. Je suis disponible pour une démonstration approfondie sur votre périmètre, et pour cadrer le pilote.")

prs.save(OUT)
print("écrit :", OUT, "—", len(prs.slides), "slides")
