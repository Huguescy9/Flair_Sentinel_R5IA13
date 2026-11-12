"""FLAIR Sentinel : copilote d'exploitation d'un parc de capteurs (simulé).

L'IA propose, l'humain décide. Toutes les actions sont simulées (dry-run).
Lancement : streamlit run app.py
"""

import json

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
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
    page_icon="📡",
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

VERDICT_COLORS = {"À traiter": "#ef4444", "Probablement normal": "#60a5fa", "Normal": "#22c55e"}
DECISIONS = {
    "valider": "Valider l'action proposée",
    "modifier": "Choisir une autre action",
    "refuser": "Refuser (aucune action)",
    "complement": "Demander une analyse complémentaire",
}
DECISION_LABEL = {"valider": "validée", "modifier": "modifiée", "refuser": "refusée",
                  "complement": "complément demandé"}
RAPPORTS = {"Avec le LLM": CAMPAGNE_LLM, "Contrôles sans LLM": CAMPAGNE_SANS_LLM}
CLASSES = {"normal": "Normal", "sensor_failure": "Panne", "drift": "Dérive",
           "possible_clone": "Clonage", "false_alarm": "Fausse alerte", "unknown": "Non typée"}

# =====================================================
# STYLE (thème dans .streamlit/config.toml)
# =====================================================

st.markdown("""
<style>
[data-testid="stMetric"] {
    background-color: #172033; padding: 18px; border-radius: 14px;
    border: 1px solid #263449;
}
[data-testid="stMetricValue"] { font-size: 1.6rem; }
[data-testid="stMetricValue"], [data-testid="stMetricValue"] * {
    white-space: normal !important; overflow: visible !important;
}
div[data-testid="stDataFrame"] { border: 1px solid #263449; border-radius: 10px; }
</style>
""", unsafe_allow_html=True)

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


# =====================================================
# SIDEBAR
# =====================================================

st.sidebar.title("📡 FLAIR")
st.sidebar.caption("COPILOTE D'EXPLOITATION IoT")
st.sidebar.radio("Navigation", list(PAGES), captions=list(PAGES.values()), key="page")
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
st.sidebar.info("🔒 Dry-run verrouillé : aucune commande n'est envoyée aux capteurs.")
st.sidebar.caption("Données entièrement simulées • 100 % local")

# =====================================================
# EN-TÊTE
# =====================================================

st.title("📡 FLAIR Sentinel")
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
        st.warning(f"🛡️ {len(hors_alerte)} message(s) de {capteurs} contiennent une tentative "
                   "d'injection, sans anomalie de mesure. Aucun de ces textes n'est envoyé au LLM.")
        with st.expander("Voir ces messages"):
            st.dataframe(hors_alerte[["event_id", "sensor_id", "timestamp", "device_msg"]],
                         hide_index=True, width="stretch")

    st.subheader("Chronologie")
    tl = alerts.assign(
        Verdict=alerts["verdict"].map(VERDICTS),
        Hypothèse=alerts["hypothese"].map(HYPOTHESES),
        fin_aff=alerts["fin"] + pd.Timedelta(minutes=5),
    )
    fig = px.timeline(tl, x_start="debut", x_end="fin_aff", y="sensor_id", color="Verdict",
                      color_discrete_map=VERDICT_COLORS, hover_name="alert_id",
                      hover_data={"Hypothèse": True, "detail": True, "fin_aff": False},
                      template="plotly_dark")
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      margin=dict(l=10, r=10, t=10, b=10), yaxis_title=None,
                      xaxis_title=None, legend_title=None, height=300)
    fig.update_xaxes(tickformat="%d/%m %Hh")
    st.plotly_chart(fig, width="stretch")

    st.subheader("File d'alertes, par priorité")
    f1, f2 = st.columns([3, 1])
    affichage = f1.radio("Afficher", ["Toutes", "À traiter", "Probablement normal"],
                         horizontal=True, label_visibility="collapsed")
    masquer = f2.checkbox("Masquer les alertes décidées")

    view = alerts if affichage == "Toutes" else alerts[alerts["verdict"].map(VERDICTS) == affichage]
    if masquer:
        view = view[~view["alert_id"].map(lambda a: est_decidee(a, st_map))]
    view = view.sort_values(["priorite", "alert_id"], ascending=[False, True])

    table = pd.DataFrame({
        "Alerte": view["alert_id"],
        "Priorité": view["priorite"],
        "Verdict": view["verdict"].map(VERDICTS),
        "Hypothèse": view["hypothese"].map(HYPOTHESES),
        "Détail": view["detail"],
        "Capteur": view["sensor_id"],
        "Début": view["debut"].map(fmt_ts),
        "Injection": view["injection"].map({True: "⚠️", False: ""}),
        "Décision": view["alert_id"].map(lambda a: statut_texte(a, st_map)),
    })
    # Largeurs fixes : la colonne Décision reste visible sur un écran de portable
    event = st.dataframe(
        table, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
        column_config={
            "Alerte": st.column_config.Column(width=75),
            "Priorité": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%d", width=105),
            "Verdict": st.column_config.Column(width=145),
            "Hypothèse": st.column_config.Column(width=145),
            "Détail": st.column_config.Column(width=230),
            "Capteur": st.column_config.Column(width=100),
            "Début": st.column_config.Column(width=95),
            "Injection": st.column_config.Column(width=70),
            "Décision": st.column_config.Column(width=95),
        },
    )
    rows = event.selection.rows if event and event.selection else []
    if rows and rows[0] < len(table):
        aid = table.iloc[rows[0]]["Alerte"]
        st.button(f"🔍 Investiguer {aid}", type="primary", on_click=ouvrir_alerte, args=(aid,))
    else:
        st.caption("Sélectionne une ligne pour l'investiguer. Priorité = sévérité + score ML ; "
                   "une alerte probablement normale est déclassée.")

    with st.expander("🤖 Briefing de prise de poste"):
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
                                 mode="lines", line=dict(width=1, dash="dot"), opacity=0.6))
    own = win[win["sensor_id"] == a["sensor_id"]].sort_values("measurement_timestamp")
    for mac, g in own.groupby(own["mac"].replace("", "aucune")):
        if mac == "aucune":
            continue
        fig.add_trace(go.Scatter(x=g["measurement_timestamp"], y=g["value"],
                                 name=f"{a['sensor_id']} · MAC {mac}", mode="lines+markers",
                                 marker=dict(size=4)))
    missing = own[own["missing"]]
    if not missing.empty:
        y0 = win["value"].min() if win["value"].notna().any() else 0
        fig.add_trace(go.Scatter(x=missing["measurement_timestamp"], y=[y0] * len(missing),
                                 name="no_data", mode="markers",
                                 marker=dict(symbol="x", color="#ef4444", size=7)))
    fig.add_vrect(x0=a["debut"], x1=a["fin"] + pd.Timedelta(minutes=5),
                  fillcolor="#ef4444" if a["verdict"] == "a_traiter" else "#60a5fa",
                  opacity=0.12, line_width=0)
    fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                      plot_bgcolor="rgba(0,0,0,0)", height=340,
                      margin=dict(l=10, r=10, t=30, b=10),
                      title=f"{a['sensor_id']} et ses voisins ({a['unit']}) — zone colorée = alerte")
    fig.update_xaxes(tickformat="%d/%m %Hh")
    st.plotly_chart(fig, width="stretch")

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
            st.error("⚠️ Injection de consignes suspectée dans ces messages. Ils sont traités comme "
                     "des données : " + ("retirés avant envoi au LLM (filtre actif)."
                                         if filtre_injection else
                                         "filtre DÉSACTIVÉ, le texte est transmis entre balises "
                                         "de données non fiables."))

    # --- Analyse par le copilote ---
    st.divider()
    st.markdown("### 🤖 Analyse du copilote")
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
            st.warning(f"🤔 **Le copilote ne sait pas conclure.** {p['ce_qui_manque']}")
        with st.container(border=True):
            st.markdown(f"**{p['resume']}**")
            st.markdown(p["explication"])

        c1, c2, c3 = st.columns(3)
        c1.metric("Hypothèse de l'IA", HYPOTHESES[p["hypothese"]])
        c2.metric("Probablement normal", "Oui" if p["probablement_normal"] else "Non")
        c3.metric("Confiance déclarée", p["confiance"])

        crit = actions.CATALOGUE[proposed]["critique"]
        st.markdown(f"**Action proposée :** {actions.libelle(proposed)} "
                    f"{'🔴 critique (confirmation requise)' if crit else '🟢 non critique'}  \n"
                    f"_{p['justification_action']}_")
        if p["verifications"]:
            st.markdown("**Vérifications suggérées :** " + " ; ".join(p["verifications"]))

        for g in res["garde_fous"]:
            (st.error if "DÉSACCORD" in g or "Fuite" in g else st.warning)(f"🛡️ {g}")

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
    st.markdown("### 👤 Décision de l'opérateur")
    flash = st.session_state.pop("flash_decision", None)
    if flash:
        st.success(flash[0])
        st.info(flash[1])
    deja = st_map.get(aid)
    if deja:
        st.caption(f"Dernière décision : {deja['decision']} par {deja['operateur']} "
                   f"({deja['horodatage']}). Une nouvelle décision s'ajoute au journal sans effacer celle-ci.")

    # Aucun choix présélectionné : valider doit rester un geste volontaire
    choice = st.radio("Que décides-tu ?", list(DECISIONS), index=None, format_func=DECISIONS.get,
                      horizontal=True, key=f"choice_{aid}")
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
        st.warning("🛡️ Un garde-fou a signalé cette proposition : pour la valider quand même, "
                   "justifie ton choix et confirme.")
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

    st.subheader("🤖 Assistant du copilote")
    st.caption("Répond à partir des alertes, de l'inventaire (pseudonymisé), du planning et des "
               "procédures. Les demandes destructives et hors sujet sont bloquées avant le LLM.")

    top_a, top_b = st.columns([4, 1])
    top_a.info("Cite un identifiant (`TMP-SRV-B`, `ALR-013`...) pour cibler ta question.")
    if top_b.button("🗑️ Effacer le chat"):
        st.session_state["chat"] = []
        st.rerun()

    for msg in st.session_state["chat"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            for g in msg.get("garde_fous", []):
                st.caption(f"🛡️ {g}")
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
                    st.caption(f"🛡️ {g}")
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
        st.success(f"🔗 Chaîne d'empreintes SHA-256 intègre ({len(entries)} entrées).")
    else:
        st.error(f"⛔ Journal altéré : la chaîne est rompue à l'entrée n°{broken}.")

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

        types = st.multiselect("Types d'entrées", sorted(df["type"].unique()),
                               default=sorted(df["type"].unique()))
        cols = [c for c in ["n", "horodatage", "operateur", "type", "alert_id", "capteur",
                            "action_proposee", "decision", "action_finale", "commentaire",
                            "execution", "question", "garde_fous", "hash"] if c in df.columns]
        st.dataframe(df[df["type"].isin(types)][cols].iloc[::-1], hide_index=True, width="stretch")

        e1, e2 = st.columns(2)
        e1.download_button("⬇️ Exporter (JSONL)",
                           "\n".join(json.dumps(e, ensure_ascii=False) for e in entries).encode("utf-8"),
                           file_name="decisions.jsonl")
        e2.download_button("⬇️ Exporter (CSV)", df.to_csv(index=False).encode("utf-8"),
                           file_name="decisions.csv", mime="text/csv")
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
        st.dataframe(pd.DataFrame({
            "Scénario": ep["scenario"],
            "Conforme": ep["conforme"].map({True: "✅", False: "❌"}),
            "Type": ep["type"].map({"incident": "Incident", "fausse_alerte": "Fausse alerte",
                                    "injection": "Injection"}),
            "Ce qui se passe": ep["titre"],
            "Attendu": ep["attendu"],
            "Résultat": ep["resultat"],
            "Délai (min)": ep["delai_detection_min"].map(lambda v: "—" if pd.isna(v) else f"{v:.0f}"),
            "Alertes": ep["alertes"],
        }), hide_index=True, width="stretch", column_config={
            "Scénario": st.column_config.Column(width=75),
            "Conforme": st.column_config.Column(width=75),
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
        b1, b2 = st.columns(2)
        run_fast = b1.button("Relancer les contrôles sans LLM (rapide)")
        run_llm = b2.button("Relancer avec le LLM (plusieurs minutes)", disabled=not use_llm)
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
            choix = st.radio("Résultats affichés", disponibles, horizontal=True, key="rapport_affiche")
            report = json.loads(RAPPORTS[choix].read_text(encoding="utf-8"))
            s = report["resume"]
            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric("Cas", s["cas"])
            c2.metric("Réussis", s["reussis"])
            c3.metric("Rattrapés", s.get("rattrapes", 0),
                      help="Le LLM s'est trompé mais un garde-fou l'a signalé à l'opérateur.")
            c4.metric("Échoués", s["echoues"])
            c5.metric("Non exécutés", s["non_executes"])
            st.caption(f"Dernière campagne : {s['date']} • LLM : {s['llm']} • "
                       f"répétitions des cas LLM : {s.get('repetitions_llm', 1)}")
            st.dataframe(pd.DataFrame([{
                "Cas": c["id"],
                "Résultat": {"réussi": "✅ réussi", "rattrapé": "🛡️ rattrapé",
                             "échoué": "❌ échoué"}.get(c["resultat"], c["resultat"]),
                "Catégorie": c["categorie"], "Titre": c["titre"],
                "Attendu": decrire_attendu(c["attendu"]),
                "Stabilité": c.get("stabilite", ""),
                "Mode": c["mode"],
                "Détail": " ; ".join(f"{'✅' if v['ok'] else '❌'} {v['critere']} : {v['obtenu']}"
                                     for v in c["verifications"]),
            } for c in report["cas"]]), hide_index=True, width="stretch", column_config={
                "Cas": st.column_config.Column(width=55),
                "Résultat": st.column_config.Column(width=120),
                "Catégorie": st.column_config.Column(width=105),
                "Titre": st.column_config.Column(width=290),
                "Attendu": st.column_config.Column(width=290),
                "Stabilité": st.column_config.Column(width=110),
            })

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
