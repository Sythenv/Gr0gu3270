#!/usr/bin/env python3
"""
Generateur de presentation PDF — Coding Agents & Pentest CICS
15 minutes, multi-audience (DG, Cyber, Juridique)
Animable par tout public.

Usage: python3 generate_presentation.py
Produit: research/presentation.pdf
"""

from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib.units import cm, mm
from reportlab.lib.colors import HexColor, white, black
from reportlab.pdfgen import canvas
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import Paragraph, Frame
from reportlab.lib.styles import ParagraphStyle
import os

# ── Couleurs ──
DARK = HexColor('#1a1a2e')
ACCENT = HexColor('#e94560')
BLUE = HexColor('#0f3460')
LIGHT = HexColor('#f5f5f5')
GREEN = HexColor('#2d6a4f')
ORANGE = HexColor('#e76f51')
GREY = HexColor('#6c757d')
WHITE = white

W, H = landscape(A4)

# ── Styles texte ──
def style_title():
    return ParagraphStyle('title', fontName='Helvetica-Bold', fontSize=28,
                          textColor=WHITE, leading=34, alignment=TA_LEFT)

def style_subtitle():
    return ParagraphStyle('subtitle', fontName='Helvetica', fontSize=16,
                          textColor=HexColor('#cccccc'), leading=22, alignment=TA_LEFT)

def style_body():
    return ParagraphStyle('body', fontName='Helvetica', fontSize=14,
                          textColor=WHITE, leading=20, alignment=TA_LEFT)

def style_body_small():
    return ParagraphStyle('bodysmall', fontName='Helvetica', fontSize=11,
                          textColor=WHITE, leading=15, alignment=TA_LEFT)

def style_accent():
    return ParagraphStyle('accent', fontName='Helvetica-Bold', fontSize=14,
                          textColor=ACCENT, leading=20, alignment=TA_LEFT)

def style_label():
    return ParagraphStyle('label', fontName='Helvetica-Bold', fontSize=12,
                          textColor=HexColor('#aaaaaa'), leading=16, alignment=TA_LEFT)

# ── Helpers ──
def draw_bg(c, color=DARK):
    c.setFillColor(color)
    c.rect(0, 0, W, H, fill=1, stroke=0)

def draw_header_bar(c, color=ACCENT):
    c.setFillColor(color)
    c.rect(0, H - 8*mm, W, 8*mm, fill=1, stroke=0)

def draw_slide_number(c, num, total):
    c.setFillColor(GREY)
    c.setFont('Helvetica', 9)
    c.drawRightString(W - 15*mm, 8*mm, f'{num} / {total}')

def draw_footer(c, text="Coding Agents & Pentest CICS — Projet de recherche exploratoire"):
    c.setFillColor(GREY)
    c.setFont('Helvetica', 8)
    c.drawString(15*mm, 8*mm, text)

def draw_text_block(c, x, y, width, height, text, style):
    f = Frame(x, y, width, height, showBoundary=0, leftPadding=0, rightPadding=0,
              topPadding=0, bottomPadding=0)
    f.addFromList([Paragraph(text, style)], c)

def draw_box(c, x, y, w, h, color, text, text_style, radius=8):
    c.setFillColor(color)
    c.roundRect(x, y, w, h, radius, fill=1, stroke=0)
    draw_text_block(c, x + 8*mm, y + 4*mm, w - 16*mm, h - 8*mm, text, text_style)

def new_slide(c):
    c.showPage()

TOTAL_SLIDES = 15

def make_pdf(filename):
    c = canvas.Canvas(filename, pagesize=landscape(A4))
    c.setTitle("Coding Agents & Pentest CICS")
    c.setAuthor("Projet de recherche exploratoire")

    # ╔══════════════════════════════════════╗
    # ║  SLIDE 1 — Titre                     ║
    # ╚══════════════════════════════════════╝
    draw_bg(c)
    c.setFillColor(ACCENT)
    c.rect(0, H*0.48, W, 4*mm, fill=1, stroke=0)
    draw_text_block(c, 40*mm, H*0.55, W - 80*mm, 60*mm,
                    "Coding Agents &amp; Pentest CICS", style_title())
    draw_text_block(c, 40*mm, H*0.38, W - 80*mm, 40*mm,
                    "Impact des agents IA sur la securite des mainframes<br/>"
                    "Projet de recherche exploratoire — 2026",
                    style_subtitle())
    draw_text_block(c, 40*mm, H*0.18, W - 80*mm, 40*mm,
                    "<b>Public</b> : DG / DGA / Ingenieurs Cyber / Juridique<br/>"
                    "<b>Duree</b> : 15 minutes<br/>"
                    "<b>Prerequis</b> : aucun — ce support est auto-portant",
                    style_body_small())
    draw_slide_number(c, 1, TOTAL_SLIDES)
    new_slide(c)

    # ╔══════════════════════════════════════╗
    # ║  SLIDE 2 — Agenda                    ║
    # ╚══════════════════════════════════════╝
    draw_bg(c)
    draw_header_bar(c)
    draw_text_block(c, 40*mm, H - 55*mm, W - 80*mm, 30*mm, "Agenda", style_title())

    items = [
        ("1.", "Le contexte : qu'est-ce qu'un mainframe CICS et pourquoi le tester"),
        ("2.", "L'outil : Gr0gu3270 — proxy d'interception TN3270"),
        ("3.", "L'experience : un prompt, 4 modules, 30 minutes"),
        ("4.", "Les resultats : ce que l'agent a produit"),
        ("5.", "Ce que ca change pour chaque metier"),
        ("6.", "Securite et gouvernance des coding agents"),
        ("7.", "Perspectives et prochaines etapes"),
    ]
    y_pos = H - 80*mm
    for num, text in items:
        draw_text_block(c, 50*mm, y_pos, 30*mm, 18*mm,
                        f'<font color="#e94560"><b>{num}</b></font>', style_body())
        draw_text_block(c, 70*mm, y_pos, W - 120*mm, 18*mm, text, style_body())
        y_pos -= 18*mm

    draw_footer(c)
    draw_slide_number(c, 2, TOTAL_SLIDES)
    new_slide(c)

    # ╔══════════════════════════════════════╗
    # ║  SLIDE 3 — Contexte mainframe        ║
    # ╚══════════════════════════════════════╝
    draw_bg(c)
    draw_header_bar(c)
    draw_text_block(c, 40*mm, H - 55*mm, W - 80*mm, 30*mm,
                    "Les mainframes sont partout", style_title())

    draw_text_block(c, 40*mm, H - 85*mm, W - 80*mm, 25*mm,
                    "71% des entreprises du Fortune 500 utilisent des mainframes IBM.<br/>"
                    "CICS traite <b>1.2 million de transactions par seconde</b> dans le monde.<br/>"
                    "Banques, assurances, administrations, transport aerien.",
                    style_body())

    bw = (W - 100*mm) / 3
    draw_box(c, 40*mm, H*0.22, bw - 5*mm, 55*mm, BLUE,
             '<b>DG / DGA</b><br/><br/>Votre coeur de metier tourne '
             'probablement sur un mainframe. Les transactions CICS = '
             'vos operations bancaires, vos contrats, vos polices.',
             style_body_small())
    draw_box(c, 40*mm + bw, H*0.22, bw - 5*mm, 55*mm, GREEN,
             '<b>Cyber</b><br/><br/>Le mainframe est le dernier '
             'perimetre non teste. Peu d\'outils, peu d\'experts, '
             'peu de CVE publiques. Surface d\'attaque meconnue.',
             style_body_small())
    draw_box(c, 40*mm + 2*bw, H*0.22, bw - 5*mm, 55*mm, ORANGE,
             '<b>Juridique</b><br/><br/>Les donnees les plus sensibles '
             '(comptes, identites, transactions) resident sur mainframe. '
             'Obligation de test (PCI-DSS 11.3, ISO 27001 A.14).',
             style_body_small())

    draw_footer(c)
    draw_slide_number(c, 3, TOTAL_SLIDES)
    new_slide(c)

    # ╔══════════════════════════════════════╗
    # ║  SLIDE 4 — Gr0gu3270 avant            ║
    # ╚══════════════════════════════════════╝
    draw_bg(c)
    draw_header_bar(c)
    draw_text_block(c, 40*mm, H - 55*mm, W - 80*mm, 30*mm,
                    "Gr0gu3270 : l'outil de depart", style_title())

    draw_text_block(c, 40*mm, H - 78*mm, W - 80*mm, 20*mm,
                    "Un proxy man-in-the-middle entre l'emulateur TN3270 et le mainframe",
                    style_subtitle())

    # ASCII diagram
    c.setFont('Courier', 12)
    c.setFillColor(HexColor('#88ccff'))
    diagram = [
        "Emulateur TN3270  <──>  Gr0gu3270 (proxy)  <──>  Mainframe CICS",
        "                            │",
        "                       SQLite DB",
    ]
    y = H - 100*mm
    for line in diagram:
        c.drawString(60*mm, y, line)
        y -= 6*mm

    draw_text_block(c, 40*mm, H*0.15, (W - 80*mm)/2, 60*mm,
                    '<font color="#e94560"><b>Ce qu\'il faisait deja</b></font><br/>'
                    '• Intercepter le flux EBCDIC<br/>'
                    '• Retirer les protections de champs<br/>'
                    '• Reveler les champs caches<br/>'
                    '• Injecter des payloads (fuzzing)<br/>'
                    '• Logger tout en SQLite',
                    style_body_small())

    draw_text_block(c, 40*mm + (W - 80*mm)/2, H*0.15, (W - 80*mm)/2, 60*mm,
                    '<font color="#e94560"><b>Ce qui manquait</b></font><br/>'
                    '• Comprendre les ecrans (champs, types)<br/>'
                    '• Detecter les crashes (ABENDs)<br/>'
                    '• Suivre les transactions (timing)<br/>'
                    '• Tester les controles d\'acces<br/>'
                    '→ Travail 100% manuel, ecran par ecran',
                    style_body_small())

    draw_footer(c)
    draw_slide_number(c, 4, TOTAL_SLIDES)
    new_slide(c)

    # ╔══════════════════════════════════════╗
    # ║  SLIDE 5 — Qu'est-ce qu'un coding agent ║
    # ╚══════════════════════════════════════╝
    draw_bg(c)
    draw_header_bar(c)
    draw_text_block(c, 40*mm, H - 55*mm, W - 80*mm, 30*mm,
                    "Qu'est-ce qu'un coding agent ?", style_title())

    draw_text_block(c, 40*mm, H - 95*mm, W - 80*mm, 35*mm,
                    "Un coding agent est une IA qui <b>lit, ecrit et execute du code</b> "
                    "dans un terminal, sous la supervision d'un humain.<br/><br/>"
                    "Il ne remplace pas l'expert. Il <b>amplifie</b> sa capacite de production.",
                    style_body())

    bw = (W - 100*mm) / 2
    draw_box(c, 40*mm, H*0.15, bw - 5*mm, 55*mm, BLUE,
             '<font color="#e94560"><b>L\'humain decide</b></font><br/><br/>'
             '• Quoi construire (strategie)<br/>'
             '• Pourquoi (objectif metier)<br/>'
             '• Dans quel ordre (architecture)<br/>'
             '• Ou integrer (connaissance du code)',
             style_body_small())
    draw_box(c, 50*mm + bw, H*0.15, bw - 5*mm, 55*mm, GREEN,
             '<font color="#e94560"><b>L\'agent execute</b></font><br/><br/>'
             '• Ecrit le code (syntaxe, API)<br/>'
             '• Gere le boilerplate (GUI, DB, IO)<br/>'
             '• Verifie la compilation<br/>'
             '• Documente (journal, fiches)',
             style_body_small())

    draw_footer(c)
    draw_slide_number(c, 5, TOTAL_SLIDES)
    new_slide(c)

    # ╔══════════════════════════════════════╗
    # ║  SLIDE 6 — L'experience              ║
    # ╚══════════════════════════════════════╝
    draw_bg(c)
    draw_header_bar(c)
    draw_text_block(c, 40*mm, H - 55*mm, W - 80*mm, 30*mm,
                    "L'experience : 1 prompt → 4 modules", style_title())

    draw_text_block(c, 40*mm, H - 80*mm, W - 80*mm, 20*mm,
                    "Un seul document de specification soumis au coding agent :",
                    style_subtitle())

    specs = [
        ("PR1", "Detection d'ABEND", "Capturer automatiquement les crashes CICS"),
        ("PR2", "Screen Map", "Cartographier chaque ecran (champs, types, contenus)"),
        ("PR3", "Correlation transactions", "Suivre chaque transaction avec son timing"),
        ("PR4", "Audit securite", "Tester 186+ transactions, classifier les reponses"),
    ]
    y_pos = H - 105*mm
    for pr, name, desc in specs:
        draw_text_block(c, 50*mm, y_pos, 30*mm, 16*mm,
                        f'<font color="#e94560"><b>{pr}</b></font>', style_body())
        draw_text_block(c, 80*mm, y_pos, 60*mm, 16*mm, f'<b>{name}</b>', style_body())
        draw_text_block(c, 145*mm, y_pos, W - 195*mm, 16*mm, desc, style_body())
        y_pos -= 17*mm

    draw_box(c, 40*mm, 18*mm, W - 80*mm, 30*mm, HexColor('#2a2a4a'),
             '<b>Resultat</b> : ~600 lignes de code Python, 3 tables SQLite, '
             '4 onglets GUI, integration dans la boucle reseau existante. '
             'Temps humain : <font color="#e94560"><b>~30 minutes de supervision</b></font>.',
             style_body())

    draw_footer(c)
    draw_slide_number(c, 6, TOTAL_SLIDES)
    new_slide(c)

    # ╔══════════════════════════════════════╗
    # ║  SLIDE 7 — Détail PR1 + PR2          ║
    # ╚══════════════════════════════════════╝
    draw_bg(c)
    draw_header_bar(c)
    draw_text_block(c, 40*mm, H - 55*mm, W - 80*mm, 30*mm,
                    "Comprendre ce qui se passe (PR1 + PR2)", style_title())

    hw = (W - 90*mm) / 2
    draw_box(c, 40*mm, H*0.28, hw - 3*mm, 75*mm, BLUE,
             '<font color="#e94560"><b>PR1 — Detection ABEND</b></font><br/><br/>'
             '<b>DG</b> : un controle interne automatise qui detecte les '
             'defaillances applicatives en temps reel<br/><br/>'
             '<b>Cyber</b> : un crash monitor — comme capturer les segfaults '
             'lors d\'un fuzzing. ASRA = vuln confirmee<br/><br/>'
             '<b>Juridique</b> : chaque crash est horodate en base avec '
             'reference au log d\'origine (preuve)',
             style_body_small())

    draw_box(c, 47*mm + hw, H*0.28, hw - 3*mm, 75*mm, GREEN,
             '<font color="#e94560"><b>PR2 — Screen Map</b></font><br/><br/>'
             '<b>DG</b> : une radiographie de chaque ecran — quels champs '
             'sont visibles, caches, modifiables<br/><br/>'
             '<b>Cyber</b> : les DevTools du navigateur pour mainframe. '
             'Champs hidden reperes instantanement<br/><br/>'
             '<b>Juridique</b> : documentation de la surface d\'attaque, '
             'champ par champ, pour le rapport',
             style_body_small())

    draw_footer(c)
    draw_slide_number(c, 7, TOTAL_SLIDES)
    new_slide(c)

    # ╔══════════════════════════════════════╗
    # ║  SLIDE 8 — Détail PR3 + PR4          ║
    # ╚══════════════════════════════════════╝
    draw_bg(c)
    draw_header_bar(c)
    draw_text_block(c, 40*mm, H - 55*mm, W - 80*mm, 30*mm,
                    "Mesurer et auditer (PR3 + PR4)", style_title())

    hw = (W - 90*mm) / 2
    draw_box(c, 40*mm, H*0.28, hw - 3*mm, 75*mm, BLUE,
             '<font color="#e94560"><b>PR3 — Correlation transactions</b></font><br/><br/>'
             '<b>DG</b> : chaque operation est tracee avec son temps '
             'de reponse — comme un audit de performance<br/><br/>'
             '<b>Cyber</b> : l\'onglet Network des DevTools. Transactions '
             'lentes = DoS potentiel. Reponses anormales = fuite<br/><br/>'
             '<b>Juridique</b> : journal chronologique complet, '
             'exportable en CSV pour le dossier de mission',
             style_body_small())

    draw_box(c, 47*mm + hw, H*0.28, hw - 3*mm, 75*mm, ORANGE,
             '<font color="#e94560"><b>PR4 — Audit securite</b></font><br/><br/>'
             '<b>DG</b> : test exhaustif des 186 transactions CICS. '
             'Resultat = matrice de controle d\'acces complete<br/><br/>'
             '<b>Cyber</b> : scanner automatise type Nuclei. Vert=ouvert, '
             'rouge=protege, jaune=crash, gris=inexistant<br/><br/>'
             '<b>Juridique</b> : verification du moindre privilege (ISO 27001 '
             'A.9.4.1). Chaque ecart = non-conformite documentee',
             style_body_small())

    draw_footer(c)
    draw_slide_number(c, 8, TOTAL_SLIDES)
    new_slide(c)

    # ╔══════════════════════════════════════╗
    # ║  SLIDE 9 — Le ratio humain/agent     ║
    # ╚══════════════════════════════════════╝
    draw_bg(c)
    draw_header_bar(c)
    draw_text_block(c, 40*mm, H - 55*mm, W - 80*mm, 30*mm,
                    "Le ratio humain / agent", style_title())

    # Table
    rows = [
        ("Strategie", "Humain", "—", "Definir les 4 features, leur ordre, leurs dependances"),
        ("Architecture", "Humain", "—", "Specifier les points d'integration dans le code existant"),
        ("Protocole", "Humain", "—", "Decrire l'algorithme de parsing au niveau octet"),
        ("Implementation", "—", "Agent", "Traduire les specs en ~600 lignes Python"),
        ("GUI", "—", "Agent", "Generer 4 onglets Tkinter complets"),
        ("Base de donnees", "—", "Agent", "Creer 3 tables, CRUD, exports CSV"),
        ("Documentation", "—", "Agent", "Journal, fiches knowledge, CLAUDE.md"),
        ("Verification", "Humain", "Agent", "L'humain supervise, l'agent compile"),
    ]

    c.setFont('Helvetica-Bold', 10)
    c.setFillColor(ACCENT)
    headers = ["Aspect", "Humain", "Agent", "Detail"]
    x_positions = [50*mm, 120*mm, 150*mm, 180*mm]
    y = H - 78*mm
    for i, h in enumerate(headers):
        c.drawString(x_positions[i], y, h)

    c.setFont('Helvetica', 10)
    c.setFillColor(WHITE)
    y -= 5*mm
    for row in rows:
        y -= 14*mm
        for i, cell in enumerate(row):
            if i == 1 and cell != "—":
                c.setFillColor(HexColor('#88ccff'))
            elif i == 2 and cell != "—":
                c.setFillColor(HexColor('#90ee90'))
            else:
                c.setFillColor(WHITE)
            c.drawString(x_positions[i], y, cell)

    draw_footer(c)
    draw_slide_number(c, 9, TOTAL_SLIDES)
    new_slide(c)

    # ╔══════════════════════════════════════╗
    # ║  SLIDE 10 — Impact DG/DGA            ║
    # ╚══════════════════════════════════════╝
    draw_bg(c)
    draw_header_bar(c, BLUE)
    draw_text_block(c, 40*mm, H - 55*mm, W - 80*mm, 30*mm,
                    "Impact : Direction Generale", style_title())

    draw_text_block(c, 40*mm, H*0.30, W - 80*mm, 80*mm,
                    '<font color="#e94560" size="16"><b>Le changement de paradigme</b></font><br/><br/>'
                    '<b>Avant</b> : l\'audit CICS est un echantillonnage. '
                    'On teste 5% des transactions par manque de temps et de ressources. '
                    '95% du perimetre est un risque non mesure.<br/><br/>'
                    '<b>Avec un coding agent</b> : on passe a l\'exhaustivite. '
                    '186 transactions testees en 2 minutes au lieu de 2 jours. '
                    'Le cout marginal d\'un test supplementaire tend vers zero.<br/><br/>'
                    '<font color="#e94560"><b>Question strategique</b></font> : '
                    'si vos experts cyber produisent 10 a 20 fois plus, '
                    'faut-il revoir le programme d\'audit SI ? '
                    'Le budget ? Le perimetre ?',
                    style_body())

    draw_footer(c)
    draw_slide_number(c, 10, TOTAL_SLIDES)
    new_slide(c)

    # ╔══════════════════════════════════════╗
    # ║  SLIDE 11 — Impact Cyber             ║
    # ╚══════════════════════════════════════╝
    draw_bg(c)
    draw_header_bar(c, GREEN)
    draw_text_block(c, 40*mm, H - 55*mm, W - 80*mm, 30*mm,
                    "Impact : Ingenieur Cyber", style_title())

    draw_text_block(c, 40*mm, H*0.30, W - 80*mm, 80*mm,
                    '<font color="#e94560" size="16"><b>Le boilerplate absorbe</b></font><br/><br/>'
                    '<b>Avant</b> : ecrire un plugin Burp ou un module Metasploit = '
                    '80% de boilerplate (GUI, DB, parsing, IO) et 20% de logique metier. '
                    'Le pentesteur passe plus de temps a coder qu\'a tester.<br/><br/>'
                    '<b>Avec un coding agent</b> : le pentesteur decrit la logique metier '
                    '(ex: "scanner les ABEND codes apres injection"). L\'agent genere '
                    'le boilerplate. Le ratio s\'inverse : 80% reflexion, 20% supervision.<br/><br/>'
                    '<font color="#e94560"><b>Consequence</b></font> : '
                    'les outils sur mesure deviennent viables pour chaque mission. '
                    'Plus besoin d\'attendre qu\'un editeur publie la feature.',
                    style_body())

    draw_footer(c)
    draw_slide_number(c, 11, TOTAL_SLIDES)
    new_slide(c)

    # ╔══════════════════════════════════════╗
    # ║  SLIDE 12 — Impact Juridique         ║
    # ╚══════════════════════════════════════╝
    draw_bg(c)
    draw_header_bar(c, ORANGE)
    draw_text_block(c, 40*mm, H - 55*mm, W - 80*mm, 30*mm,
                    "Impact : Juridique (offensif &amp; defensif)", style_title())

    hw = (W - 90*mm) / 2
    draw_box(c, 40*mm, H*0.22, hw - 3*mm, 80*mm, HexColor('#3a3a5a'),
             '<font color="#e94560"><b>Offensif (pentest autorise)</b></font><br/><br/>'
             '• Le prompt initial = plan de test documente<br/>'
             '• Chaque action journalisee (SQLite + git)<br/>'
             '• Export CSV = pieces justificatives<br/>'
             '• Mode offline = preuves preservees<br/>'
             '• Le CLAUDE.md = cadre d\'execution (scope)<br/><br/>'
             '<b>Valeur</b> : tracabilite complete de la '
             'mission, de l\'intention a l\'execution',
             style_body_small())

    draw_box(c, 47*mm + hw, H*0.22, hw - 3*mm, 80*mm, HexColor('#3a3a5a'),
             '<font color="#e94560"><b>Defensif (conformite, RSSI)</b></font><br/><br/>'
             '• PR4 verifie le moindre privilege (A.9.4.1)<br/>'
             '• PR1 detecte les defauts applicatifs (A.12.6.1)<br/>'
             '• PR3 journalise les evenements (A.12.4.1)<br/>'
             '• Chaque finding = non-conformite mesuree<br/>'
             '• Diff multi-profils = preuve de segregation<br/><br/>'
             '<b>Valeur</b> : transformation des obligations '
             'de test en controles automatises',
             style_body_small())

    draw_footer(c)
    draw_slide_number(c, 12, TOTAL_SLIDES)
    new_slide(c)

    # ╔══════════════════════════════════════╗
    # ║  SLIDE 13 — Gouvernance agents       ║
    # ╚══════════════════════════════════════╝
    draw_bg(c)
    draw_header_bar(c, ACCENT)
    draw_text_block(c, 40*mm, H - 55*mm, W - 80*mm, 30*mm,
                    "Securite : gouverner un coding agent", style_title())

    draw_text_block(c, 40*mm, H - 82*mm, W - 80*mm, 20*mm,
                    "Un coding agent a les memes capacites qu'un developpeur avec acces terminal.<br/>"
                    "Les controles doivent etre equivalents.",
                    style_subtitle())

    rows_gov = [
        ("Charte informatique", "CLAUDE.md — politique lisible par la machine"),
        ("Perimetre reseau", "Execution confinee a la machine locale (WSL)"),
        ("Classification donnees", "Zero donnee sensible — pas d'interpretation"),
        ("Procedure d'incident", "Ambiguite = STOP immediat + alerte utilisateur"),
        ("Tracabilite", "Journal horodate + git + SQLite"),
        ("Moindre privilege", "L'agent ne fait que ce qui est specifie"),
    ]

    c.setFont('Helvetica-Bold', 11)
    c.setFillColor(ACCENT)
    c.drawString(50*mm, H - 100*mm, "Controle classique")
    c.drawString(150*mm, H - 100*mm, "Equivalent coding agent")

    c.setFont('Helvetica', 11)
    y = H - 105*mm
    for trad, agent in rows_gov:
        y -= 15*mm
        c.setFillColor(HexColor('#aaaaaa'))
        c.drawString(50*mm, y, trad)
        c.setFillColor(WHITE)
        c.drawString(150*mm, y, agent)

    draw_footer(c)
    draw_slide_number(c, 13, TOTAL_SLIDES)
    new_slide(c)

    # ╔══════════════════════════════════════╗
    # ║  SLIDE 14 — Framework CLAUDE.md      ║
    # ╚══════════════════════════════════════╝
    draw_bg(c)
    draw_header_bar(c)
    draw_text_block(c, 40*mm, H - 55*mm, W - 80*mm, 30*mm,
                    "Livrable : framework CLAUDE.md", style_title())

    draw_text_block(c, 40*mm, H - 80*mm, W - 80*mm, 20*mm,
                    "Un template reutilisable pour tout projet de recherche securite avec coding agent",
                    style_subtitle())

    sections = [
        ("1", "Contraintes de securite", "Perimetre, donnees, comportement en cas d'ambiguite"),
        ("2", "Grille d'analogies", "Tableau public/analogie pour chaque concept technique"),
        ("3", "Convention de journal", "Horodatage + categorie + fait. Tracabilite complete"),
        ("4", "Structure recherche", "Journal, Findings, Knowledge base, Roadmap"),
        ("5", "Prompt fondateur", "Le 1er prompt = reference commune de l'equipe"),
    ]

    y_pos = H - 105*mm
    for num, title, desc in sections:
        draw_text_block(c, 50*mm, y_pos, 15*mm, 18*mm,
                        f'<font color="#e94560" size="16"><b>{num}</b></font>', style_body())
        draw_text_block(c, 65*mm, y_pos + 2*mm, 80*mm, 16*mm,
                        f'<b>{title}</b>', style_body())
        draw_text_block(c, 150*mm, y_pos + 2*mm, W - 200*mm, 16*mm, desc, style_body_small())
        y_pos -= 18*mm

    draw_box(c, 40*mm, 18*mm, W - 80*mm, 25*mm, HexColor('#2a2a4a'),
             'Disponible dans le repository : <b>framework/CLAUDE-TEMPLATE.md</b><br/>'
             'Cloner, adapter, utiliser. Aucune dependance, aucun outil supplementaire.',
             style_body_small())

    draw_footer(c)
    draw_slide_number(c, 14, TOTAL_SLIDES)
    new_slide(c)

    # ╔══════════════════════════════════════╗
    # ║  SLIDE 15 — Perspectives             ║
    # ╚══════════════════════════════════════╝
    draw_bg(c)
    draw_header_bar(c)
    draw_text_block(c, 40*mm, H - 55*mm, W - 80*mm, 30*mm,
                    "Perspectives", style_title())

    draw_text_block(c, 40*mm, H*0.35, (W - 80*mm) / 2 - 5*mm, 75*mm,
                    '<font color="#e94560"><b>Pour l\'outil</b></font><br/><br/>'
                    '• Audit differentiel multi-profils<br/>'
                    '• Fuzzing cible par champ (PR2 + injection)<br/>'
                    '• Fingerprinting ESM automatique<br/>'
                    '• Export rapport pentest (HTML/PDF)<br/>'
                    '• Scripting Python reproductible',
                    style_body())

    draw_text_block(c, 40*mm + (W - 80*mm) / 2, H*0.35, (W - 80*mm) / 2 - 5*mm, 75*mm,
                    '<font color="#e94560"><b>Pour la recherche</b></font><br/><br/>'
                    '• Mesurer le ratio productivite sur 6 mois<br/>'
                    '• Comparer coding agent vs developpement manuel<br/>'
                    '• Formaliser la gouvernance des agents<br/>'
                    '• Publier le framework CLAUDE.md<br/>'
                    '• Contribuer a l\'etat de l\'art pentest CICS',
                    style_body())

    c.setFillColor(ACCENT)
    c.rect(40*mm, 20*mm, W - 80*mm, 1*mm, fill=1, stroke=0)
    draw_text_block(c, 40*mm, 22*mm, W - 80*mm, 20*mm,
                    '<font color="#cccccc">L\'expert reste indispensable. '
                    'L\'agent change l\'echelle a laquelle il opere.</font>',
                    ParagraphStyle('closing', fontName='Helvetica-Oblique', fontSize=14,
                                   textColor=HexColor('#cccccc'), alignment=TA_CENTER))

    draw_footer(c)
    draw_slide_number(c, 15, TOTAL_SLIDES)

    c.save()
    return filename


if __name__ == '__main__':
    outdir = os.path.dirname(os.path.abspath(__file__))
    outfile = os.path.join(outdir, 'presentation.pdf')
    make_pdf(outfile)
    print(f'PDF genere : {outfile}')
