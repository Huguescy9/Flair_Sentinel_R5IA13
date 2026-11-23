"""FLAIR Sentinel : copilote d'exploitation d'un parc de capteurs (simulé).

L'IA propose, l'humain décide. Toutes les actions sont simulées (dry-run).
Lancement : streamlit run app.py
"""

import json
from datetime import datetime

import pandas as pd
import plotly.graph_objects as go
import plotly.io as pio
import streamlit as st

import actions
import journal
from analyzer import HYPOTHESES, VERDICTS, evaluate_detection, run_pipeline
from config import CAMPAGNE_LLM, CAMPAGNE_SANS_LLM, EVENTS_FILE, LLM_NUM_GPU, OLLAMA_MODEL
from copilot import LLMIndisponible, analyser_alerte, ollama_status, repondre_chat
from evaluate import decrire_attendu, run_campaign
from rag import BaseConnaissances
from securite import Pseudonymiseur

# =====================================================
# CONFIGURATION
# =====================================================

st.set_page_config(
    page_title="FLAIR | Sentinel",
    page_icon=":material/sensors:",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Une page par étape du travail, dans l'ordre de la démonstration
PAGES = {
    "Alertes": "Vue d'ensemble et file à traiter",
    "Investigation": "Comprendre une alerte et décider",
    "Assistant IA": "Poser une question sur le parc",
    "Journal": "Propositions et décisions enregistrées",
    "Évaluation": "Mesures, tests et sources du RAG",
}
PAGES_ICONES = {
    "Alertes": ":material/notifications:",
    "Investigation": ":material/troubleshoot:",
    "Assistant IA": ":material/forum:",
    "Journal": ":material/receipt_long:",
    "Évaluation": ":material/insights:",
}

# Couleurs de statut (docs/design/DESIGN.md) : pleines pour les graphiques, badges pour les tableaux
ROUGE, BLEU, VERT = "#e5484d", "#3e7bfa", "#2fb383"
VERDICT_COLORS = {"À traiter": ROUGE, "Probablement normal": BLEU, "Normal": VERT}
VERDICT_BADGE = {
    "À traiter": "color: #b42318; background-color: #fdecea",
    "Probablement normal": "color: #1d4ed8; background-color: #e8f0fe",
    "Normal": "color: #1d7a5c; background-color: #ddf5ec",
}
VERDICT_BADGE_ST = {"À traiter": "red", "Probablement normal": "blue", "Normal": "green"}
DECISIONS = {
    "valider": "Valider l'action proposée",
    "modifier": "Choisir une autre action",
    "refuser": "Refuser (aucune action)",
    "complement": "Demander une analyse complémentaire",
}
DECISIONS_ICONES = {"valider": ":material/check:", "modifier": ":material/swap_horiz:",
                    "refuser": ":material/block:", "complement": ":material/manage_search:"}
DECISION_LABEL = {"valider": "validée", "modifier": "modifiée", "refuser": "refusée",
                  "complement": "complément demandé"}
RAPPORTS = {"Avec le LLM": CAMPAGNE_LLM, "Contrôles sans LLM": CAMPAGNE_SANS_LLM}

# Page Évaluation : résultats en badges (pas d'émojis)
RESULTAT_BADGE = {
    "Réussi": "color: #1d7a5c; background-color: #ddf5ec",
    "Conforme": "color: #1d7a5c; background-color: #ddf5ec",
    "Rattrapé": "color: #8a5a00; background-color: #fff4d6",
    "Échoué": "color: #b42318; background-color: #fdecea",
    "Non conforme": "color: #b42318; background-color: #fdecea",
    "Non exécuté": "color: #6b6b6b; background-color: #f4f4f5",
}
RESULTAT_BADGE_ST = {"Réussi": "green", "Rattrapé": "orange", "Échoué": "red",
                     "Non exécuté": "gray"}

# Page Journal
TYPES_JOURNAL = {"decision_alerte": "Décision", "proposition_ia": "Proposition IA",
                 "question_assistant": "Question", "briefing_ia": "Briefing"}
DECISION_BADGE = {
    "validée": "color: #1d7a5c; background-color: #ddf5ec",
    "modifiée": "color: #8a5a00; background-color: #fff4d6",
    "refusée": "color: #b42318; background-color: #fdecea",
    "complément demandé": "color: #1d4ed8; background-color: #e8f0fe",
}
PERIODES = {"Tout": None, "7 j": pd.Timedelta(days=7), "24 h": pd.Timedelta(hours=24)}
CHAMPS_JOURNAL = {
    "operateur": "Opérateur", "alert_id": "Alerte", "capteur": "Capteur",
    "hypothese_regles": "Hypothèse (règles)", "verdict_regles": "Verdict (règles)",
    "mode": "Mode", "hypothese_ia": "Hypothèse IA", "confiance": "Confiance",
    "probablement_normal": "Probablement normal", "je_ne_sais_pas": "« Je ne sais pas »",
    "source_proposition": "Source de la proposition", "action_proposee": "Action proposée",
    "decision": "Décision", "action_finale": "Action finale",
    "proposition_signalee": "Proposition signalée", "commentaire": "Commentaire",
    "execution": "Exécution", "question": "Question", "type_reponse": "Type de réponse",
    "filtre_injection": "Filtre anti-injection",
}


def resume_entree(e):
    """Une ligne lisible par entrée du journal."""
    def champ(nom):
        v = e.get(nom)
        return "" if v is None or (isinstance(v, float) and pd.isna(v)) else str(v)
    if e["type"] == "decision_alerte":
        return f"{champ('action_finale') or 'Aucune action'} · {champ('commentaire')}".strip(" ·")
    if e["type"] == "proposition_ia":
        return f"Propose {champ('action_proposee')} (confiance {champ('confiance')})"
    if e["type"] == "question_assistant":
        q = champ("question")
        return q if len(q) <= 70 else q[:69] + "…"
    if e["type"] == "briefing_ia":
        return "Briefing de prise de poste"
    return ""
CLASSES = {"normal": "Normal", "sensor_failure": "Panne", "drift": "Dérive",
           "possible_clone": "Clonage", "false_alarm": "Fausse alerte", "unknown": "Non typée"}

# =====================================================
# STYLE (thème dans .streamlit/config.toml)
# =====================================================

# CSS statique uniquement : aucun texte du LLM ni des capteurs ne passe ici (risque R7)
st.markdown("""
<style>
/* Cadre sombre, zone de contenu claire posée comme une carte */
[data-testid="stAppViewContainer"] { background-color: #2b2b2d; }
[data-testid="stHeader"] { background: transparent; }
/* La carte est le parent de stMain, ou de stAppScrollToBottomContainer sur une page avec
   st.chat_input (Streamlit y retire stMain) : elle englobe aussi la zone de saisie du chat. */
[data-testid="stAppViewContainer"] > div:has(> [data-testid="stMain"]),
[data-testid="stAppViewContainer"] > div:has(> [data-testid="stAppScrollToBottomContainer"]) {
    background-color: #ffffff; border-radius: 12px; margin: 10px 10px 10px 0;
    overflow: hidden;
}
[data-testid="stBottom"] > div { background-color: transparent; }
[data-testid="stMetric"] {
    background-color: #ffffff; padding: 16px 18px; border-radius: 10px;
    border: 1px solid #e5e5e5;
}
[data-testid="stMetricLabel"] { color: #6b6b6b; }
[data-testid="stMetricValue"] { font-size: 1.6rem; font-variant-numeric: tabular-nums; }
[data-testid="stMetricValue"], [data-testid="stMetricValue"] * {
    white-space: normal !important; overflow: visible !important;
}
div[data-testid="stDataFrame"] { border-radius: 10px; }
[data-testid="stSidebar"] [data-testid="stCaptionContainer"] { color: #9a9a9e; }
[data-testid="stSidebar"] h1 [role="img"] { color: #f25533; margin-right: 6px; }

/* Navigation : le radio devient un menu (icône + libellé), comme la réf. 01 */
[data-testid="stSidebar"] [data-testid="stRadio"],
[data-testid="stSidebar"] [data-testid="stRadio"] > div,
[data-testid="stSidebar"] [data-testid="stRadioGroup"],
[data-testid="stSidebar"] [data-testid="stRadioGroup"] > div { width: 100%; }
[data-testid="stSidebar"] [data-testid="stRadioGroup"] { align-items: stretch; gap: 2px; }
[data-testid="stSidebar"] [data-testid="stRadioOption"] {
    align-self: stretch; width: 100%; max-width: none; box-sizing: border-box;
    margin: 0; padding: 9px 12px; border-radius: 8px; cursor: pointer;
    transition: background-color 120ms ease;
}
[data-testid="stSidebar"] [data-testid="stRadioOption"] > div > div:first-child { display: none; }
[data-testid="stSidebar"] [data-testid="stRadioOption"]:hover { background-color: #333336; }
[data-testid="stSidebar"] [data-testid="stRadioOption"][data-selected="true"] { background-color: #3a3a3c; }
[data-testid="stSidebar"] [data-testid="stRadioOption"] p {
    display: flex; align-items: center; font-size: 0.95rem; color: #d4d4d6;
}
[data-testid="stSidebar"] [data-testid="stRadioOption"] > div,
[data-testid="stSidebar"] [data-testid="stRadioOption"] [data-testid="stMarkdownContainer"] {
    width: 100%;
}
[data-testid="stSidebar"] [data-testid="stRadioOption"][data-selected="true"] p {
    color: #ffffff; font-weight: 500;
}
[data-testid="stSidebar"] [data-testid="stRadioOption"] [role="img"] {
    color: #9a9a9e; font-size: 1.25rem; margin-right: 10px; vertical-align: middle !important;
}
[data-testid="stSidebar"] [data-testid="stRadioOption"][data-selected="true"] [role="img"] {
    color: #f25533;
}
</style>
""", unsafe_allow_html=True)

# Graphiques : fond transparent, grille discrète, texte secondaire
pio.templates["flair"] = go.layout.Template(layout=dict(
    font=dict(family="Inter, Segoe UI, sans-serif", color="#6b6b6b", size=12),
    title=dict(font=dict(color="#1c1c1e", size=14)),
    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
    colorway=["#232325", BLEU, ROUGE, VERT, "#8b5cf6", "#a1a1aa"],
    xaxis=dict(gridcolor="#f0f0f0", linecolor="#e5e5e5", zerolinecolor="#e5e5e5"),
    yaxis=dict(gridcolor="#f0f0f0", linecolor="#e5e5e5", zerolinecolor="#e5e5e5"),
    hoverlabel=dict(bgcolor="#ffffff", bordercolor="#e5e5e5", font=dict(color="#1c1c1e")),
))
pio.templates.default = "plotly_white+flair"

# =====================================================
# CHARGEMENT (mis en cache)
# =====================================================

if not EVENTS_FILE.exists():
    st.error(f"Fichier introuvable : {EVENTS_FILE}")
    st.info("Lance d'abord `python generate_data.py` dans le dossier du projet.")
    st.stop()


# cache_resource : une seule copie en mémoire, jamais modifiée par les pages
@st.cache_resource(show_spinner="Analyse du parc (détection ML + règles)...")
def charger():
    return run_pipeline()


@st.cache_resource
def base_connaissances():
    return BaseConnaissances()


@st.cache_resource
def pseudonymiseur(_inventory):
    return Pseudonymiseur(_inventory)


@st.cache_data(ttl=30, show_spinner=False)
def etat_llm():
    return ollama_status()


data = charger()
events, alerts = data["events"], data["alerts"]
kb = base_connaissances()
pseudo = pseudonymiseur(data["inventory"])
alerts_by_id = alerts.set_index("alert_id", drop=False)

if st.session_state.get("page") not in PAGES:
    st.session_state["page"] = next(iter(PAGES))
st.session_state.setdefault("analyses", {})
st.session_state.setdefault("chat", [])


def fmt_ts(ts):
    return pd.Timestamp(ts).strftime("%d/%m %H:%M")


def ouvrir_alerte(alert_id):
    """Callback : ouvre une alerte dans l'investigation avant le prochain rendu."""
    st.session_state["page"] = "Investigation"
    st.session_state["derniere_alerte"] = alert_id
    st.session_state.pop("alerte_courante", None)


def statut_texte(alert_id, st_map):
    entry = st_map.get(alert_id)
    return entry["decision"].capitalize() if entry else "En attente"


def est_decidee(alert_id, st_map):
    """Une demande de complément laisse l'alerte en attente."""
    entry = st_map.get(alert_id)
    return bool(entry) and entry["decision"] != "complément demandé"


def figure_chronologie(alerts, planning, st_map, debut, fin, selection=None):
    """Frise des alertes : une ligne par capteur, regroupées par salle, avec le planning en fond.

    selection : alerte à mettre en avant (les autres barres sont estompées)."""
    capteurs = alerts[["room", "sensor_id"]].drop_duplicates().sort_values(["room", "sensor_id"])
    ypos, salles, y = {}, {}, 0.0
    for room, g in capteurs.groupby("room", sort=True):
        premier = y
        for sid in g["sensor_id"]:
            ypos[sid] = y
            y += 1
        salles[room] = (premier, y - 1)
        y += 0.8  # espace entre deux salles (place pour l'étiquette du planning)

    fig = go.Figure()
    # Planning : bande grise limitée aux lignes de la salle concernée
    for p in planning:
        if p["salle"] not in salles:
            continue
        y0, y1 = salles[p["salle"]]
        x0, x1 = pd.Timestamp(p["debut"]), pd.Timestamp(p["fin"])
        fig.add_shape(type="rect", xref="x", yref="y", x0=x0, x1=x1, y0=y0 - 0.5, y1=y1 + 0.5,
                      fillcolor="#d9d9de", opacity=0.9, line_width=0, layer="below")
        nature = "Maintenance" if p["type"] == "maintenance" else "Événement"
        # Au-dessus de la bande (axe inversé : y0 - 0.5 est le haut), dans l'espace entre salles
        fig.add_annotation(x=x0, y=y0 - 0.5, xanchor="left", yanchor="bottom",
                           text=f"{p['id']} · {nature}", showarrow=False,
                           font=dict(size=10, color="#6b6b6b"))
    # Séparateurs discrets entre salles
    for _, y1 in list(salles.values())[:-1]:
        fig.add_hline(y=y1 + 0.9, line_color="#ececec", line_width=1)

    # Barres : largeur minimale pour que les alertes courtes restent visibles
    for verdict, libelle in VERDICTS.items():
        g = alerts[alerts["verdict"] == verdict]
        if g.empty:
            continue
        duree = ((g["fin"] + pd.Timedelta(minutes=5)) - g["debut"]).clip(lower=pd.Timedelta(minutes=35))
        decidee = g["alert_id"].map(lambda a: est_decidee(a, st_map))
        # Mise en avant purement visuelle (pas de selectedpoints : Plotly bloquerait le clic suivant)
        choisie = g["alert_id"] == selection
        if selection is None:
            opacite = [0.35 if d else 1.0 for d in decidee]
        else:
            opacite = [1.0 if c else 0.22 for c in choisie]
        fig.add_trace(go.Bar(
            base=g["debut"], x=duree.dt.total_seconds() * 1000, y=g["sensor_id"].map(ypos),
            orientation="h", width=0.62, name=libelle, showlegend=False,
            marker=dict(color=VERDICT_COLORS[libelle], opacity=opacite,
                        line=dict(color="#1c1c1e", width=[2 if c else 0 for c in choisie])),
            customdata=list(zip(g["alert_id"], g["sensor_id"], g["hypothese"].map(HYPOTHESES),
                                g["debut"].map(fmt_ts), g["fin"].map(fmt_ts),
                                g["alert_id"].map(lambda a: statut_texte(a, st_map)))),
            hovertemplate="<b>%{customdata[0]}</b> · %{customdata[1]}<br>%{customdata[2]}<br>"
                          "%{customdata[3]} → %{customdata[4]}<br>Décision : %{customdata[5]}"
                          "<extra></extra>",
        ))
    # Identifiants : à droite de la barre, ou dessous si l'alerte suivante du capteur est trop proche
    # (dessus, ils gêneraient l'étiquette du planning)
    bornes = alerts.assign(fin_aff=alerts["debut"] + (
        (alerts["fin"] + pd.Timedelta(minutes=5)) - alerts["debut"]).clip(lower=pd.Timedelta(minutes=35)))
    for _, g in bornes.sort_values("debut").groupby("sensor_id"):
        suivants = list(g["debut"].iloc[1:]) + [None]
        for (_, r), suivant in zip(g.iterrows(), suivants):
            serre = suivant is not None and suivant - r["fin_aff"] < pd.Timedelta(hours=3)
            fig.add_annotation(
                x=r["debut"] if serre else r["fin_aff"], y=ypos[r["sensor_id"]],
                xanchor="left", yanchor="top" if serre else "middle",
                xshift=0 if serre else 4, yshift=-9 if serre else 0,
                text=r["alert_id"], showarrow=False, font=dict(size=10, color="#1c1c1e"))

    # Légende séparée des barres (sinon elle reprend le contour de la barre sélectionnée)
    for libelle in [VERDICTS[v] for v in VERDICTS if v in set(alerts["verdict"])]:
        fig.add_trace(go.Scatter(x=[None], y=[None], mode="markers", name=libelle,
                                 marker=dict(symbol="square", size=12, color=VERDICT_COLORS[libelle]),
                                 hoverinfo="skip"))
    fig.add_trace(go.Scatter(x=[None], y=[None], mode="markers", name="Planning",
                             marker=dict(symbol="square", size=12, color="#d9d9de"),
                             hoverinfo="skip"))

    fig.update_layout(
        barmode="overlay", height=int(70 + 30 * y), margin=dict(l=10, r=10, t=30, b=10),
        legend=dict(orientation="h", yanchor="bottom", y=1.0, xanchor="left", x=0),
        clickmode="event+select", dragmode=False,
    )
    fig.update_yaxes(tickvals=list(ypos.values()), ticktext=list(ypos.keys()),
                     autorange="reversed", showgrid=False, zeroline=False, fixedrange=True)
    fig.update_xaxes(type="date", range=[debut, fin + pd.Timedelta(hours=3)],
                     tickformat="%d/%m %Hh", fixedrange=True)
    return fig


# =====================================================
# SIDEBAR
# =====================================================

st.sidebar.title(":material/sensors: FLAIR")
st.sidebar.caption("COPILOTE D'EXPLOITATION IoT")
# Radio restylé en menu (CSS plus haut) : icône + libellé, élément actif sur fond gris
st.sidebar.radio("Navigation", list(PAGES), key="page", label_visibility="collapsed",
                 format_func=lambda p: f"{PAGES_ICONES[p]} {p}", width="stretch")
st.sidebar.divider()

operateur = st.sidebar.text_input(
    "Opérateur", value=st.session_state.get("operateur", ""),
    placeholder="Ton nom (obligatoire pour décider)",
)
st.session_state["operateur"] = operateur

up, has_model = etat_llm()
if up and has_model:
    st.sidebar.success(f"LLM local : {OLLAMA_MODEL}")
elif up:
    st.sidebar.warning(f"Ollama actif, modèle absent : `ollama pull {OLLAMA_MODEL}`")
else:
    st.sidebar.warning("Ollama non lancé : analyses par les règles uniquement")

use_llm = st.sidebar.toggle(
    "Utiliser le LLM", value=up and has_model, disabled=not (up and has_model),
    help="Désactivé : les analyses sont produites par les règles, sans charger le modèle en mémoire.",
)
# Par défaut, suit FLAIR_NUM_GPU (le lanceur .bat le met à 0 : processeur)
use_gpu = st.sidebar.toggle(
    "Carte graphique (GPU)", value=LLM_NUM_GPU != "0", disabled=not use_llm,
    help="Activée : réponses rapides (quelques secondes). Désactivée : le modèle tourne sur le "
         "processeur, environ 1 min par analyse, mais la carte graphique n'est pas sollicitée. "
         "Changer de mode recharge le modèle : la réponse suivante est plus lente.",
)
if use_llm:
    st.sidebar.caption("Calcul sur la carte graphique" if use_gpu
                       else "Calcul sur le processeur (plus lent, plus sûr si la carte est instable)")
filtre_injection = st.sidebar.toggle(
    "Filtre anti-injection", value=True,
    help="Retire les messages de capteur suspects avant l'envoi au LLM. "
         "Le désactiver permet de montrer que les autres garde-fous tiennent seuls.",
)
st.sidebar.info("Dry-run verrouillé : aucune commande n'est envoyée aux capteurs.",
                icon=":material/lock:")
st.sidebar.caption("Données entièrement simulées • 100 % local")

# =====================================================
# EN-TÊTE
# =====================================================

st.title("FLAIR Sentinel")
st.caption("Copilote d'exploitation • L'IA propose, l'humain décide • Données simulées")

page = st.session_state["page"]
st_map = journal.statut_alertes()

# =====================================================
# PAGE : ALERTES
# =====================================================

if page == "Alertes":

    to_treat = alerts[alerts["verdict"] == "a_traiter"]
    pending = [a for a in to_treat["alert_id"] if not est_decidee(a, st_map)]
    decisions = [e for e in journal.lire() if e["type"] == "decision_alerte"]
    nb_messages = f"{len(events):,}".replace(",", " ")

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Messages analysés", nb_messages)
    k2.metric("Alertes en attente", f"{len(pending)} / {len(to_treat)}",
              help="Alertes à traiter sans décision humaine / total des alertes à traiter")
    k3.metric("Probablement normales", int((alerts["verdict"] == "probablement_normal").sum()))
    k4.metric("Décisions journalisées", len(decisions))

    st.caption(
        f"{nb_messages} messages de {events['sensor_id'].nunique()} capteurs réduits à "
        f"{len(alerts)} alertes : l'équipe ne lit que {len(to_treat)} alertes à traiter, "
        "les fausses alertes sont expliquées et écartées."
    )

    # Un capteur sain qui écrit des consignes reste un signal de sécurité
    hors_alerte = events[events["injection"] & (events["verdict"] == "normal")]
    if not hors_alerte.empty:
        capteurs = ", ".join(sorted(hors_alerte["sensor_id"].unique()))
        st.warning(f"{len(hors_alerte)} message(s) de {capteurs} contiennent une tentative "
                   "d'injection, sans anomalie de mesure. Aucun de ces textes n'est envoyé au LLM.",
                   icon=":material/shield:")
        with st.expander("Voir ces messages"):
            st.dataframe(hors_alerte[["event_id", "sensor_id", "timestamp", "device_msg"]],
                         hide_index=True, width="stretch")

    # Une seule alerte sélectionnée, partagée par la chronologie, la file et le panneau.
    # Les deux widgets n'ont pas de clé : quand la sélection change, leurs paramètres changent,
    # Streamlit les recrée et ils repartent de la sélection commune (selectedpoints / selection_default).
    aid = st.session_state.get("alerte_panneau")
    if aid not in alerts_by_id.index:
        aid = None
    nouvelle = aid

    st.subheader("Chronologie")
    chrono = st.plotly_chart(
        figure_chronologie(alerts, data["planning"], st_map, events["measurement_timestamp"].min(),
                           events["measurement_timestamp"].max(), selection=aid),
        width="stretch", theme=None, on_select="rerun", selection_mode="points",
        config={"displayModeBar": False})
    points = chrono.selection.points if chrono and chrono.selection else []
    if points and points[0].get("customdata") is not None:
        cd = points[0]["customdata"]
        clic = cd[0] if isinstance(cd, (list, tuple)) else cd
        if clic != aid:
            nouvelle = clic
    st.caption("Bandes grises : maintenances et événements du planning, dans la salle concernée. "
               "Couleur atténuée : alerte déjà décidée. Clique sur une barre pour voir son détail.")

    st.subheader("File d'alertes, par priorité")
    # Barre d'outils : recherche, filtre de verdict, alertes décidées
    t1, t2, t3 = st.columns([1.3, 1.6, 1], vertical_alignment="center")
    recherche = t1.text_input("Rechercher", placeholder="Alerte, capteur, salle…",
                              icon=":material/search:", label_visibility="collapsed")
    affichage = t2.segmented_control("Afficher", ["Toutes", "À traiter", "Probablement normal"],
                                     default="Toutes", label_visibility="collapsed") or "Toutes"
    masquer = t3.toggle("Masquer les alertes décidées")

    liste, panneau = st.columns([2.8, 1], gap="medium")

    with liste:
        view = alerts if affichage == "Toutes" else alerts[alerts["verdict"].map(VERDICTS) == affichage]
        if masquer:
            view = view[~view["alert_id"].map(lambda a: est_decidee(a, st_map))]
        if recherche.strip():
            q = recherche.strip()
            texte = (view[["alert_id", "sensor_id", "room", "detail"]].fillna("").astype(str)
                     .agg(" ".join, axis=1) + " " + view["hypothese"].map(HYPOTHESES).fillna(""))
            view = view[texte.str.contains(q, case=False, regex=False)]
        view = view.sort_values(["priorite", "alert_id"], ascending=[False, True])

        table = pd.DataFrame({
            "Alerte": view["alert_id"],
            "Priorité": view["priorite"],
            "Verdict": view["verdict"].map(VERDICTS),
            "Hypothèse": view["hypothese"].map(HYPOTHESES),
            "Capteur": view["sensor_id"],
            "Début": view["debut"].map(fmt_ts),
            "Inj.": view["injection"].map({True: "Oui", False: ""}),
            "Décision": view["alert_id"].map(lambda a: statut_texte(a, st_map)),
        })
        # Verdict en badge ; le détail complet est dans le panneau de droite
        ids = list(table["Alerte"])
        lignes_attendues = [ids.index(aid)] if aid in ids else []
        event = st.dataframe(
            table.style.map(lambda v: VERDICT_BADGE.get(v, ""), subset=["Verdict"])
                 .map(lambda v: "color: #8a5a00; background-color: #fff4d6" if v == "Oui" else "",
                      subset=["Inj."]),
            hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
            selection_default={"selection": {"rows": lignes_attendues}} if lignes_attendues else None,
            column_config={
                "Alerte": st.column_config.Column(width=75),
                "Priorité": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%d",
                                                            width=90, color="#232325"),
                "Verdict": st.column_config.Column(width=150),
                "Hypothèse": st.column_config.Column(width=115),
                "Capteur": st.column_config.Column(width=95),
                "Début": st.column_config.Column(width=85),
                "Inj.": st.column_config.Column(width=40),
                "Décision": st.column_config.Column(width=90),
            },
        )
        st.caption(f"{len(table)} alerte(s). Priorité = sévérité + score ML ; "
                   "une alerte probablement normale est déclassée.")

    # La file a changé si sa sélection diffère de celle qu'on lui a donnée (clic ou décochage)
    rows = list(event.selection.rows) if event and event.selection else []
    if nouvelle == aid and rows != lignes_attendues:
        nouvelle = table.iloc[rows[0]]["Alerte"] if rows and rows[0] < len(table) else None
    if nouvelle != aid:
        # Nouveau rendu pour que la chronologie et la file affichent toutes deux la sélection
        st.session_state["alerte_panneau"] = nouvelle
        st.rerun()

    with panneau, st.container(border=True, gap="small"):
        if aid not in alerts_by_id.index:
            st.markdown("**Détail de l'alerte**")
            st.caption("Sélectionne une alerte dans la chronologie ou dans la file pour afficher "
                       "son détail ici.")
        else:
            a = alerts_by_id.loc[aid]
            verdict = VERDICTS[a["verdict"]]
            st.markdown(f"**{aid}** · {a['sensor_id']}")
            st.badge(verdict, color=VERDICT_BADGE_ST.get(verdict, "gray"))
            for libelle, valeur in [
                ("Salle", a["room"]),
                ("Hypothèse", HYPOTHESES[a["hypothese"]]),
                ("Sévérité", a["severite"] or "—"),
                ("Priorité", f"{a['priorite']:.0f} / 100"),
                ("Score ML max", f"{a['score_ml_max']:.2f}"),
                ("Période", f"{fmt_ts(a['debut'])} → {fmt_ts(a['fin'])}"),
                ("Messages", a["n_events"]),
                ("Décision", statut_texte(aid, st_map)),
            ]:
                c1, c2 = st.columns([1, 1.4])
                c1.caption(libelle)
                c2.markdown(str(valeur))
            st.markdown("**Indices calculés**")
            for fact in a["indices"][:3]:
                st.caption(f"• {fact}")
            if a["injection"]:
                st.warning("Injection suspectée dans les messages du capteur.", icon=":material/warning:")
            st.button(f"Investiguer {aid}", type="primary", width="stretch",
                      on_click=ouvrir_alerte, args=(aid,))

    with st.expander("Briefing de prise de poste", icon=":material/smart_toy:"):
        st.caption("Résumé rédigé par le LLM local à partir des alertes et des procédures, avec ses sources.")
        if not use_llm:
            st.info("Nécessite Ollama et l'option « Utiliser le LLM ».")
        if st.button("Générer le briefing", disabled=not use_llm):
            with st.spinner("Le copilote prépare le briefing..."):
                try:
                    res = repondre_chat(
                        "Fais un briefing de prise de poste : alertes à traiter en priorité "
                        "(avec leur identifiant) et fausses alertes écartées, en 8 lignes maximum.",
                        data, kb, pseudo, statuts=st_map, filtre_injection=filtre_injection,
                        gpu=use_gpu)
                    st.session_state["briefing"] = res
                    journal.ajouter("briefing_ia", operateur or "anonyme",
                                    citations=res.get("citations", []), garde_fous=res["garde_fous"])
                except LLMIndisponible as exc:
                    st.error(str(exc))
        if "briefing" in st.session_state:
            res = st.session_state["briefing"]
            st.markdown(res["reponse"])
            for g in res["garde_fous"]:
                st.warning(g)

# =====================================================
# PAGE : INVESTIGATION
# =====================================================

elif page == "Investigation":

    order = alerts.sort_values(["verdict", "priorite"], ascending=[True, False])["alert_id"].tolist()
    # Streamlit oublie l'état d'un widget non affiché : on garde la sélection à part
    if st.session_state.get("alerte_courante") not in order:
        derniere = st.session_state.get("derniere_alerte")
        st.session_state["alerte_courante"] = derniere if derniere in order else order[0]

    def label(aid):
        a = alerts_by_id.loc[aid]
        return (f"{aid} · {a['sensor_id']} · {HYPOTHESES[a['hypothese']]} · "
                f"{VERDICTS[a['verdict']]} · {statut_texte(aid, st_map)}")

    aid = st.selectbox("Alerte", order, key="alerte_courante", format_func=label)
    st.session_state["derniere_alerte"] = aid
    a = alerts_by_id.loc[aid]

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric(f"Capteur ({a['room']})", a["sensor_id"])
    m2.metric("Hypothèse (règles)", HYPOTHESES[a["hypothese"]])
    m3.metric("Verdict", VERDICTS[a["verdict"]])
    m4.metric("Sévérité", a["severite"] or "—")
    m5.metric("Score ML max", f"{a['score_ml_max']:.2f}")

    # --- Courbe du capteur et de ses voisins ---
    margin = pd.Timedelta(hours=3)
    win = events[(events["room"] == a["room"]) & (events["sensor_type"] == a["sensor_type"])
                 & events["measurement_timestamp"].between(a["debut"] - margin, a["fin"] + margin)]
    fig = go.Figure()
    for sid, g in win[win["sensor_id"] != a["sensor_id"]].groupby("sensor_id"):
        g = g.sort_values("measurement_timestamp")
        fig.add_trace(go.Scatter(x=g["measurement_timestamp"], y=g["value"], name=f"{sid} (voisin)",
                                 mode="lines", line=dict(width=1, dash="dot", color="#a1a1aa"),
                                 opacity=0.8))
    own = win[win["sensor_id"] == a["sensor_id"]].sort_values("measurement_timestamp")
    # Couleurs neutres : rouge/vert laisseraient croire qu'une MAC est « la bonne »
    couleurs_mac = iter(["#232325", "#8b5cf6", BLEU, "#a16207"])
    for mac, g in own.groupby(own["mac"].replace("", "aucune")):
        if mac == "aucune":
            continue
        couleur = next(couleurs_mac, "#232325")
        fig.add_trace(go.Scatter(x=g["measurement_timestamp"], y=g["value"],
                                 name=f"{a['sensor_id']} · MAC {mac}", mode="lines+markers",
                                 line=dict(color=couleur), marker=dict(size=4, color=couleur)))
    missing = own[own["missing"]]
    if not missing.empty:
        y0 = win["value"].min() if win["value"].notna().any() else 0
        fig.add_trace(go.Scatter(x=missing["measurement_timestamp"], y=[y0] * len(missing),
                                 name="no_data", mode="markers",
                                 marker=dict(symbol="x", color=ROUGE, size=7)))
    fig.add_vrect(x0=a["debut"], x1=a["fin"] + pd.Timedelta(minutes=5),
                  fillcolor=ROUGE if a["verdict"] == "a_traiter" else BLEU,
                  opacity=0.10, line_width=0)
    fig.update_layout(height=340, margin=dict(l=10, r=10, t=30, b=10),
                      title=f"{a['sensor_id']} et ses voisins ({a['unit']}) — zone colorée = alerte")
    fig.update_xaxes(tickformat="%d/%m %Hh")
    st.plotly_chart(fig, width="stretch", theme=None)

    left, right = st.columns([1, 1])
    with left:
        st.markdown("#### Indices calculés (fiables)")
        for fact in a["indices"]:
            st.markdown(f"- {fact}")
        with st.expander(f"Messages bruts de cette alerte ({a['n_events']})"):
            raw = events[events["event_id"].isin(a["event_ids"])].sort_values("measurement_timestamp")
            st.dataframe(raw[["event_id", "timestamp", "measurement_timestamp", "seq", "value", "unit",
                              "status", "network_status", "firmware", "mac", "ml_score"]],
                         hide_index=True, width="stretch")
    with right:
        st.markdown("#### Messages libres du capteur (non fiables)")
        if not a["device_msgs"]:
            st.caption("Aucun message libre.")
        for msg in a["device_msgs"]:
            st.code(msg, language=None)
        if a["injection"]:
            st.error("Injection de consignes suspectée dans ces messages. Ils sont traités comme "
                     "des données : " + ("retirés avant envoi au LLM (filtre actif)."
                                         if filtre_injection else
                                         "filtre DÉSACTIVÉ, le texte est transmis entre balises "
                                         "de données non fiables."), icon=":material/warning:")

    # --- Analyse par le copilote ---
    st.divider()
    st.markdown("### :material/smart_toy: Analyse du copilote")
    if st.button("Analyser avec le copilote", type="primary"):
        with st.spinner("Analyse en cours (LLM local)..." if use_llm else "Analyse par les règles..."):
            res = analyser_alerte(a, data, kb, pseudo, use_llm=use_llm,
                                  filtre_injection=filtre_injection, gpu=use_gpu)
        st.session_state["analyses"][aid] = res
        p = res["proposition"]
        journal.ajouter("proposition_ia", operateur or "anonyme", alert_id=aid,
                        capteur=a["sensor_id"], mode=res["mode"], action_proposee=p["action_id"],
                        hypothese_ia=p["hypothese"], probablement_normal=p["probablement_normal"],
                        confiance=p["confiance"], sources=p["sources"],
                        je_ne_sais_pas=p["je_ne_sais_pas"], garde_fous=res["garde_fous"],
                        filtre_injection=filtre_injection)

    res = st.session_state["analyses"].get(aid)
    if res is None:
        proposed = actions.action_par_defaut(a["hypothese"], a["verdict"])
        st.info(f"Pas encore d'analyse IA. Proposition par défaut des règles : "
                f"**{actions.libelle(proposed)}**.")
    else:
        p = res["proposition"]
        proposed = p["action_id"]
        if res["erreur"]:
            st.warning(f"LLM indisponible ({res['erreur']}) : analyse produite par les règles.")
        badge = "LLM local" if res["mode"] == "llm" else "Règles (sans LLM)"
        st.caption(f"Mode : {badge} • {res['duree_s']} s • "
                   f"filtre anti-injection {'actif' if res['filtre_injection'] else 'désactivé'}")

        if p["je_ne_sais_pas"]:
            st.warning(f"**Le copilote ne sait pas conclure.** {p['ce_qui_manque']}",
                       icon=":material/help:")
        with st.container(border=True):
            st.markdown(f"**{p['resume']}**")
            st.markdown(p["explication"])

        c1, c2, c3 = st.columns(3)
        c1.metric("Hypothèse de l'IA", HYPOTHESES[p["hypothese"]])
        c2.metric("Probablement normal", "Oui" if p["probablement_normal"] else "Non")
        c3.metric("Confiance déclarée", p["confiance"])

        crit = actions.CATALOGUE[proposed]["critique"]
        st.markdown(f"**Action proposée :** {actions.libelle(proposed)}")
        if crit:
            st.badge("Critique · confirmation requise", color="red", icon=":material/priority_high:")
        else:
            st.badge("Non critique", color="gray", icon=":material/check:")
        st.markdown(f"_{p['justification_action']}_")
        if p["verifications"]:
            st.markdown("**Vérifications suggérées :** " + " ; ".join(p["verifications"]))

        for g in res["garde_fous"]:
            (st.error if "DÉSACCORD" in g or "Fuite" in g else st.warning)(g, icon=":material/shield:")

        st.markdown("**Sources citées**")
        cited = set(p["sources"])
        for s in res["sources"]:
            if s["id"] in cited:
                with st.expander(f"[{s['id']}] {s['document']} — {s['titre']}"):
                    st.write(s["texte"])
                    st.caption(s["fichier"])
        if "DONNEES" in cited:
            st.caption("[DONNEES] = indices calculés par Python ci-dessus.")
        with st.expander("Contexte exact envoyé au LLM (pseudonymisé)"):
            st.code(res["contexte_envoye"], language=None)

    # --- Décision humaine ---
    st.divider()
    st.markdown("### :material/person: Décision de l'opérateur")
    flash = st.session_state.pop("flash_decision", None)
    if flash:
        st.success(flash[0])
        st.info(flash[1])
    deja = st_map.get(aid)
    if deja:
        st.caption(f"Dernière décision : {deja['decision']} par {deja['operateur']} "
                   f"({deja['horodatage']}). Une nouvelle décision s'ajoute au journal sans effacer celle-ci.")

    # Aucun choix présélectionné : valider doit rester un geste volontaire
    choice = st.segmented_control("Que décides-tu ?", list(DECISIONS), default=None,
                                  format_func=lambda k: f"{DECISIONS_ICONES[k]} {DECISIONS[k]}",
                                  key=f"choice_{aid}")
    final_action = None
    if choice == "valider":
        final_action = proposed
    elif choice == "modifier":
        others = [k for k in actions.CATALOGUE if k != proposed]
        final_action = st.selectbox("Action retenue", others, format_func=actions.libelle,
                                    key=f"other_{aid}")
    critical = final_action is not None and actions.CATALOGUE[final_action]["critique"]
    signalee = choice == "valider" and res is not None and res["proposition"]["signalee"]
    if signalee:
        st.warning("Un garde-fou a signalé cette proposition : pour la valider quand même, "
                   "justifie ton choix et confirme.", icon=":material/shield:")
    confirm = True
    if critical or signalee:
        confirm = st.checkbox(f"Je confirme avoir vérifié les indices avant de lancer "
                              f"« {actions.libelle(final_action)} ».",
                              key=f"confirm_{aid}_{final_action}")
    comment_requis = choice in ("modifier", "refuser") or signalee
    comment = st.text_area("Commentaire de l'opérateur", key=f"comment_{aid}")
    if comment_requis:
        st.caption("Commentaire obligatoire pour cette décision.")

    if st.button("Enregistrer la décision", type="primary"):
        problems = []
        if choice is None:
            problems.append("Choisis d'abord une décision.")
        if not operateur.strip():
            problems.append("Renseigne ton nom d'opérateur dans la barre latérale.")
        if comment_requis and not comment.strip():
            problems.append("Un commentaire est obligatoire pour cette décision.")
        if (critical or signalee) and not confirm:
            problems.append("Confirme la vérification avant de lancer cette action.")
        if problems:
            for msg in problems:
                st.error(msg)
        else:
            execution = (actions.executer(final_action, aid, a["sensor_id"], operateur)
                         if final_action else "Aucune action exécutée.")
            entry = journal.ajouter(
                "decision_alerte", operateur.strip(), alert_id=aid, capteur=a["sensor_id"],
                hypothese_regles=a["hypothese"], verdict_regles=a["verdict"],
                source_proposition=res["mode"] if res else "regles",
                action_proposee=proposed, decision=DECISION_LABEL[choice],
                action_finale=final_action, commentaire=comment.strip(),
                proposition_signalee=signalee,
                garde_fous=res["garde_fous"] if res else [], execution=execution,
            )
            st.session_state["flash_decision"] = (
                f"Décision n°{entry['n']} enregistrée dans le journal.", execution)
            st.rerun()

    history = [e for e in journal.lire() if e.get("alert_id") == aid]
    if history:
        with st.expander(f"Historique de {aid} ({len(history)} entrées)"):
            for e in history:
                st.markdown(f"- `{e['horodatage']}` **{e['type']}** par {e['operateur']} — "
                            f"{e.get('decision', '')} {e.get('action_finale') or e.get('action_proposee', '')}")

# =====================================================
# PAGE : ASSISTANT IA
# =====================================================

elif page == "Assistant IA":

    st.subheader(":material/forum: Assistant du copilote")
    st.caption("Répond à partir des alertes, de l'inventaire (pseudonymisé), du planning et des "
               "procédures. Les demandes destructives et hors sujet sont bloquées avant le LLM.")

    top_a, top_b = st.columns([4, 1])
    top_a.info("Cite un identifiant (`TMP-SRV-B`, `ALR-013`...) pour cibler ta question.")
    if top_b.button("Effacer le chat", icon=":material/delete:"):
        st.session_state["chat"] = []
        st.rerun()

    for msg in st.session_state["chat"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            for g in msg.get("garde_fous", []):
                st.caption(f":material/shield: {g}")
            if msg.get("sources"):
                st.caption("Sources consultées : " + ", ".join(s["id"] for s in msg["sources"]))

    if not st.session_state["chat"]:
        st.markdown("**Exemples :** « Quelles alertes dois-je traiter en priorité ? » · "
                    "« Pourquoi ALR-001 est-elle probablement normale ? » · "
                    "« Que faire pour TMP-SRV-B ? » · « Quel est le numéro de série de TMP-B101-A ? »")

    question = st.chat_input("Pose une question sur le parc...")
    if question:
        with st.chat_message("user"):
            st.markdown(question)
        # Les échanges refusés ne servent pas de contexte au LLM
        history = [{"role": m["role"], "content": m.get("brut", m["content"])}
                   for m in st.session_state["chat"] if m["type"] == "reponse"]
        with st.chat_message("assistant"):
            try:
                with st.spinner("Le copilote réfléchit..."):
                    res = repondre_chat(question, data, kb, pseudo, history=history,
                                        statuts=st_map, use_llm=use_llm,
                                        filtre_injection=filtre_injection, gpu=use_gpu)
                st.markdown(res["reponse"])
                for g in res["garde_fous"]:
                    st.caption(f":material/shield: {g}")
                st.session_state["chat"] += [
                    {"role": "user", "content": question, "type": res["type"]},
                    {"role": "assistant", "content": res["reponse"], "type": res["type"],
                     "brut": res.get("reponse_brute", res["reponse"]),
                     "garde_fous": res["garde_fous"], "sources": res["sources"]},
                ]
                journal.ajouter("question_assistant", operateur or "anonyme", question=question,
                                type_reponse=res["type"], garde_fous=res["garde_fous"],
                                citations=res.get("citations", []))
            except LLMIndisponible as exc:
                st.error(f"{exc} Sans LLM, le copilote ne rédige pas de réponse. "
                         "Passages les plus proches de ta question :")
                for s in kb.rechercher(question, k=3):
                    st.markdown(f"**[{s['id']}] {s['titre']}** — {s['texte']}")

# =====================================================
# PAGE : JOURNAL
# =====================================================

elif page == "Journal":

    st.subheader("Journal des décisions")
    entries = journal.lire()
    ok, broken = journal.verifier()
    if not entries:
        st.info("Le journal est vide : aucune proposition ni décision pour l'instant.")
    elif ok:
        st.success(f"Chaîne d'empreintes SHA-256 intègre ({len(entries)} entrées).",
                   icon=":material/verified:")
    else:
        st.error(f"Journal altéré : la chaîne est rompue à l'entrée n°{broken}.",
                 icon=":material/gpp_bad:")

    if entries:
        df = pd.DataFrame(entries)
        dec = df[df["type"] == "decision_alerte"]
        if not dec.empty:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Décisions", len(dec))
            c2.metric("Propositions validées", int((dec["decision"] == "validée").sum()))
            c3.metric("Modifiées / refusées", int(dec["decision"].isin(["modifiée", "refusée"]).sum()))
            agree = (dec["decision"] == "validée").mean() * 100
            c4.metric("Accord humain / proposition", f"{agree:.0f} %")

        # Heure locale du poste (le journal est en UTC)
        df["_heure"] = pd.to_datetime(df["horodatage"], utc=True).dt.tz_convert(
            datetime.now().astimezone().tzinfo)
        df["_type"] = df["type"].map(TYPES_JOURNAL).fillna(df["type"])
        if "decision" not in df.columns:
            df["decision"] = None

        # Barre d'outils : recherche, type d'entrée, décision, période
        t1, t2, t3, t4 = st.columns([1.3, 2.4, 1, 1.2], vertical_alignment="center")
        recherche = t1.text_input("Rechercher", placeholder="Opérateur, alerte, capteur, texte…",
                                  icon=":material/search:", label_visibility="collapsed",
                                  key="journal_recherche")
        types_presents = [t for t in TYPES_JOURNAL.values() if t in set(df["_type"])]
        type_choisi = t2.segmented_control("Type", ["Tous"] + types_presents, default="Tous",
                                           label_visibility="collapsed", key="journal_type") or "Tous"
        decision_choisie = t3.selectbox("Décision", ["Toutes décisions"] + list(DECISION_BADGE),
                                        label_visibility="collapsed", key="journal_decision")
        periode = t4.segmented_control("Période", list(PERIODES), default="Tout",
                                       label_visibility="collapsed", key="journal_periode") or "Tout"

        view = df
        if type_choisi != "Tous":
            view = view[view["_type"] == type_choisi]
        if decision_choisie != "Toutes décisions":
            view = view[view["decision"] == decision_choisie]
        if PERIODES[periode]:
            view = view[view["_heure"] >= pd.Timestamp.now(tz=view["_heure"].dt.tz)
                        - PERIODES[periode]]
        if recherche.strip():
            texte = view.drop(columns=["_heure", "hash", "hash_precedent"], errors="ignore") \
                        .astype(str).agg(" ".join, axis=1)
            view = view[texte.str.contains(recherche.strip(), case=False, regex=False)]
        view = view.sort_values("n", ascending=False)

        liste, panneau = st.columns([2.8, 1], gap="medium")
        with liste:
            if view.empty:
                st.info("Aucune entrée ne correspond à ces filtres.")
                event = None
            else:
                table = pd.DataFrame({
                    "N°": view["n"],
                    "Heure": view["_heure"].dt.strftime("%d/%m %H:%M"),
                    "Type": view["_type"],
                    "Opérateur": view["operateur"],
                    "Alerte": view.get("alert_id", pd.Series(index=view.index)).fillna("—"),
                    "Décision": view["decision"].fillna("—"),
                    "Résumé": view.apply(resume_entree, axis=1),
                })
                event = st.dataframe(
                    table.style.map(lambda v: DECISION_BADGE.get(v, ""), subset=["Décision"]),
                    hide_index=True, width="stretch", on_select="rerun",
                    selection_mode="single-row",
                    column_config={
                        "N°": st.column_config.NumberColumn(width=50),
                        "Heure": st.column_config.Column(width=95),
                        "Type": st.column_config.Column(width=120),
                        "Opérateur": st.column_config.Column(width=100),
                        "Alerte": st.column_config.Column(width=75),
                        "Décision": st.column_config.Column(width=110),
                        "Résumé": st.column_config.Column(width=260),
                    },
                )
            st.caption(f"{len(view)} entrée(s) sur {len(df)}. Clique sur un en-tête de colonne "
                       "pour trier.")

        with panneau, st.container(border=True):
            rows = event.selection.rows if event and event.selection else []
            if not rows:
                st.markdown("**Détail de l'entrée**")
                st.caption("Sélectionne une ligne du journal pour afficher son détail ici.")
            else:
                e = view.iloc[rows[0]]
                st.markdown(f"**Entrée n°{e['n']}** · {e['_type']}")
                st.caption(e["_heure"].strftime("%d/%m/%Y %H:%M:%S"))
                for champ, libelle in CHAMPS_JOURNAL.items():
                    valeur = e.get(champ)
                    if valeur is None or (isinstance(valeur, float) and pd.isna(valeur)) \
                            or valeur == "" or isinstance(valeur, list):
                        continue
                    if isinstance(valeur, bool):
                        valeur = "Oui" if valeur else "Non"
                    elif champ in ("hypothese_ia", "hypothese_regles"):
                        valeur = HYPOTHESES.get(valeur, valeur)
                    elif champ == "verdict_regles":
                        valeur = VERDICTS.get(valeur, valeur)
                    c1, c2 = st.columns([1, 1.4])
                    c1.caption(libelle)
                    # st.text : texte saisi ou produit par le LLM, jamais interprété (Markdown/HTML)
                    c2.text(str(valeur))
                for champ, libelle in [("sources", "Sources"), ("citations", "Citations"),
                                       ("garde_fous", "Garde-fous déclenchés")]:
                    valeur = e.get(champ)
                    if isinstance(valeur, list) and valeur:
                        st.markdown(f"**{libelle}**")
                        st.text("\n".join(f"• {v}" for v in valeur))
                st.caption(f"Empreinte {str(e['hash'])[:16]}…  \n"
                           f"Précédente {str(e['hash_precedent'])[:16]}…")

        with st.container(horizontal=True):
            st.download_button("Exporter (JSONL)",
                               "\n".join(json.dumps(e, ensure_ascii=False) for e in entries).encode("utf-8"),
                               file_name="decisions.jsonl", icon=":material/download:")
            st.download_button("Exporter (CSV)",
                               df.drop(columns=["_heure", "_type"]).to_csv(index=False).encode("utf-8"),
                               file_name="decisions.csv", mime="text/csv", icon=":material/download:")
    st.caption("Le journal est en ajout seul (journal/decisions.jsonl). Chaque ligne contient "
               "l'empreinte de la précédente : toute modification a posteriori est détectée.")

# =====================================================
# PAGE : ÉVALUATION
# =====================================================

elif page == "Évaluation":

    st.subheader("Évaluation du copilote")
    tab1, tab2, tab3 = st.tabs(["Détection", "Campagne de tests", "Base de connaissances"])

    with tab1:
        ev = evaluate_detection(data)
        r = ev["resume"]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Incidents détectés", f"{r['incidents_detectes']}/{r['incidents_total']}")
        c2.metric("Fausses alertes écartées", f"{r['fausses_alertes_ecartees']}/{r['fausses_alertes_total']}")
        c3.metric("Alertes déclenchées à tort", r["alertes_declenchees_a_tort"])
        c4.metric("Précision / rappel (messages)",
                  f"{ev['evenements']['precision']:.2f} / {ev['evenements']['rappel']:.2f}")
        if r["incidents_manques"]:
            st.warning(f"Incident(s) manqué(s) : {', '.join(r['incidents_manques'])}. "
                       "Voir les limites dans le README.")
        if not ev["alertes_a_tort"].empty:
            st.warning("Alertes déclenchées à tort : " + ", ".join(ev["alertes_a_tort"]["alert_id"]))

        st.markdown("#### Épisodes (ce qui compte pour l'équipe)")
        ep = ev["episodes"]
        episodes = pd.DataFrame({
            "Scénario": ep["scenario"],
            "Conforme": ep["conforme"].map({True: "Conforme", False: "Non conforme"}),
            "Type": ep["type"].map({"incident": "Incident", "fausse_alerte": "Fausse alerte",
                                    "injection": "Injection"}),
            "Ce qui se passe": ep["titre"],
            "Attendu": ep["attendu"],
            "Résultat": ep["resultat"],
            "Délai (min)": ep["delai_detection_min"].map(lambda v: "—" if pd.isna(v) else f"{v:.0f}"),
            "Alertes": ep["alertes"],
        })
        st.dataframe(episodes.style.map(lambda v: RESULTAT_BADGE.get(v, ""), subset=["Conforme"]),
                     hide_index=True, width="stretch", column_config={
            "Scénario": st.column_config.Column(width=75),
            "Conforme": st.column_config.Column(width=110),
            "Type": st.column_config.Column(width=100),
            "Ce qui se passe": st.column_config.Column(width=255),
            "Attendu": st.column_config.Column(width=255),
            "Résultat": st.column_config.Column(width=175),
            "Délai (min)": st.column_config.Column(width=75),
            "Alertes": st.column_config.Column(width=90),
        })

        st.markdown("#### Comparaison des approches")
        st.caption("Pourquoi combiner ML et règles : le ML seul rate presque tout, "
                   "les règles sans contexte crient au loup sur les fausses alertes.")
        st.dataframe(ev["approches"].rename(columns={
            "approche": "Approche", "precision": "Précision", "rappel": "Rappel",
            "faux_positifs": "Faux positifs", "fausses_alertes_levees": "Fausses alertes levées",
        }), hide_index=True, width="stretch")

        with st.expander("Détail au niveau message"):
            pc = ev["par_classe"]
            pc = pc[pc["classe"] != "false_alarm"]
            st.dataframe(pd.DataFrame({
                "Classe": pc["classe"].map(CLASSES), "Messages": pc["evenements"],
                "Signalés à traiter": pc["detectes"], "Bien typés": pc["bien_types"],
                "Rappel": pc["rappel"],
            }), hide_index=True, width="stretch")
            st.markdown("Matrice de confusion (référence en ligne, prédiction en colonne)")
            st.dataframe(ev["confusion"].rename(index=CLASSES, columns=CLASSES), width="stretch")
        st.caption("Attention : les données et les règles ont été conçues par la même équipe. "
                   "Ces scores ne prédisent pas les performances sur un parc réel.")

    with tab2:
        with st.container(horizontal=True):
            run_fast = st.button("Relancer les contrôles sans LLM (rapide)",
                                 icon=":material/play_arrow:")
            run_llm = st.button("Relancer avec le LLM (plusieurs minutes)",
                                icon=":material/smart_toy:", disabled=not use_llm)
        if run_fast or run_llm:
            bar = st.progress(0.0)
            run_campaign(use_llm=run_llm,
                         progress=lambda i, n, c: bar.progress(i / n, text=f"{c['id']} {c['titre']}"))
            bar.progress(1.0, text="Terminé")
            st.session_state["rapport_affiche"] = "Avec le LLM" if run_llm else "Contrôles sans LLM"

        disponibles = [nom for nom, fichier in RAPPORTS.items() if fichier.exists()]
        if not disponibles:
            st.info("Aucune campagne enregistrée : lance `python evaluate.py` ou un bouton ci-dessus.")
        else:
            if st.session_state.get("rapport_affiche") not in disponibles:
                st.session_state["rapport_affiche"] = disponibles[0]
            choix = st.segmented_control("Résultats affichés", disponibles,
                                         key="rapport_affiche") or disponibles[0]
            report = json.loads(RAPPORTS[choix].read_text(encoding="utf-8"))
            s = report["resume"]
            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric("Cas", s["cas"])
            c2.metric("Réussis", s["reussis"])
            c3.metric("Rattrapés", s.get("rattrapes", 0),
                      help="Le LLM s'est trompé mais un garde-fou l'a signalé à l'opérateur.")
            c4.metric("Échoués", s["echoues"])
            c5.metric("Non exécutés", s["non_executes"])
            date_campagne = pd.Timestamp(s["date"]).tz_convert(
                datetime.now().astimezone().tzinfo).strftime("%d/%m/%Y à %H:%M")
            st.caption(f"Dernière campagne : {date_campagne} • LLM : {s['llm']} • "
                       f"répétitions des cas LLM : {s.get('repetitions_llm', 1)}")
            cas = report["cas"]
            table_cas = pd.DataFrame([{
                "Cas": c["id"],
                "Résultat": c["resultat"].capitalize(),
                "Catégorie": c["categorie"].replace("_", " ").capitalize(),
                "Titre": c["titre"],
                "Critères": f"{sum(v['ok'] for v in c['verifications'])}"
                            f"/{len(c['verifications'])}",
                "Stabilité": c.get("stabilite", ""),
            } for c in cas])

            liste, panneau = st.columns([2.8, 1], gap="medium")
            with liste:
                event = st.dataframe(
                    table_cas.style.map(lambda v: RESULTAT_BADGE.get(v, ""), subset=["Résultat"]),
                    hide_index=True, width="stretch", on_select="rerun",
                    selection_mode="single-row", key=f"cas_{choix}",
                    column_config={
                        "Cas": st.column_config.Column(width=55),
                        "Résultat": st.column_config.Column(width=110),
                        "Catégorie": st.column_config.Column(width=110),
                        "Titre": st.column_config.Column(width=320),
                        "Critères": st.column_config.Column(width=75),
                        "Stabilité": st.column_config.Column(width=120),
                    })
                st.caption("« Rattrapé » : le LLM s'est trompé, mais un garde-fou l'a signalé "
                           "à l'opérateur.")

            with panneau, st.container(border=True):
                rows = event.selection.rows if event and event.selection else []
                if not rows:
                    st.markdown("**Détail du cas**")
                    st.caption("Sélectionne un cas pour voir ses critères un par un.")
                else:
                    c = cas[rows[0]]
                    resultat = c["resultat"].capitalize()
                    st.markdown(f"**{c['id']}** · {c['titre']}")
                    st.badge(resultat, color=RESULTAT_BADGE_ST.get(resultat, "gray"))
                    for libelle, valeur in [("Catégorie", table_cas.iloc[rows[0]]["Catégorie"]),
                                            ("Mode", c["mode"]),
                                            ("Stabilité", c.get("stabilite") or "—")]:
                        c1, c2 = st.columns([1, 1.4])
                        c1.caption(libelle)
                        c2.text(str(valeur))
                    st.markdown("**Attendu**")
                    st.text(decrire_attendu(c["attendu"]))
                    st.markdown("**Critères**")
                    for v in c["verifications"]:
                        st.badge("Respecté" if v["ok"] else "Non respecté",
                                 color="green" if v["ok"] else "red",
                                 icon=":material/check:" if v["ok"] else ":material/close:")
                        # st.text : « obtenu » peut contenir du texte produit par le LLM
                        st.text(f"{v['critere']} : {v['obtenu']}")

    with tab3:
        st.caption(f"Les {len(kb.chunks)} passages que le copilote a le droit de citer "
                   "(fiches et planning). Recherche TF-IDF locale.")
        q = st.text_input("Tester la recherche", placeholder="ex. capteur qui renvoie de vieilles mesures")
        if q:
            hits = kb.rechercher(q, k=5)
            if not hits:
                st.warning("Aucune source jugée pertinente : le copilote devrait répondre « je ne sais pas ».")
            for h in hits:
                with st.expander(f"[{h['id']}] score {h['score']:.2f} — {h['document']} — {h['titre']}"):
                    st.write(h["texte"])
        st.markdown("#### Planning (maintenances et événements)")
        st.dataframe(pd.DataFrame(data["planning"])[["id", "type", "titre", "salle", "debut", "fin",
                                                      "effets_attendus"]],
                     hide_index=True, width="stretch")
        st.markdown("#### Fiches")
        for doc in sorted({c["document"] for c in kb.chunks if c["id"].startswith("KB")}):
            with st.expander(doc):
                for c in kb.chunks:
                    if c["document"] == doc:
                        st.markdown(f"**[{c['id']}] {c['titre']}**  \n{c['texte']}")

st.divider()
st.caption("FLAIR Sentinel • Prototype pédagogique BUT3 R&T • Données simulées • "
           "Aucune action réelle sur les capteurs (dry-run).")
