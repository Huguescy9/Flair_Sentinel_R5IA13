"""Configuration centrale de FLAIR Sentinel.

Aucun secret n'est écrit ici : tout ce qui est sensible passe par
des variables d'environnement (voir .env.example).
"""

import os
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
KNOWLEDGE_DIR = BASE_DIR / "knowledge"
JOURNAL_DIR = BASE_DIR / "journal"
RESULTS_DIR = BASE_DIR / "resultats"
TESTS_DIR = BASE_DIR / "tests"

EVENTS_FILE = DATA_DIR / "events.csv"
LABELS_FILE = DATA_DIR / "reference_labels.csv"
SCENARIOS_FILE = DATA_DIR / "scenarios.json"
INVENTORY_FILE = DATA_DIR / "inventory.csv"
PLANNING_FILE = DATA_DIR / "planning.json"
JOURNAL_FILE = JOURNAL_DIR / "decisions.jsonl"

# Deux fichiers : une campagne sans LLM n'écrase jamais les résultats obtenus avec lui
CAMPAGNE_LLM = RESULTS_DIR / "campagne.json"
CAMPAGNE_SANS_LLM = RESULTS_DIR / "campagne_sans_llm.json"

# =====================================================
# LLM LOCAL (Ollama) : aucune API cloud
# =====================================================

OLLAMA_BASE_URL = os.environ.get("FLAIR_OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("FLAIR_MODEL", "qwen2.5:7b")
OLLAMA_TIMEOUT = int(os.environ.get("FLAIR_OLLAMA_TIMEOUT", "180"))
LLM_TEMPERATURE = 0.2
LLM_NUM_CTX = 8192
# Couches du modèle envoyées à la carte graphique : "0" = tout sur le processeur,
# vide = choix automatique d'Ollama.
LLM_NUM_GPU = os.environ.get("FLAIR_NUM_GPU", "")

# Garde-fou : on refuse tout endpoint qui n'est pas local.
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


def est_url_locale(url):
    """Compare le nom d'hôte exact : « localhost.exemple.com » n'est pas local."""
    return urlparse(url).hostname in LOCAL_HOSTS


if not est_url_locale(OLLAMA_BASE_URL):
    raise RuntimeError(
        "FLAIR_OLLAMA_URL doit pointer vers une instance locale "
        "(règle du projet : aucune inférence dans le cloud)."
    )

# =====================================================
# SÉCURITÉ
# =====================================================

# Sel de pseudonymisation : jamais dans le dépôt.
# S'il n'est pas défini, un sel aléatoire est tiré au démarrage
# (pseudonymes stables pendant la session uniquement).
PSEUDO_SALT = os.environ.get("FLAIR_PSEUDO_SALT", "")

# Dry-run verrouillé : le prototype n'a aucun connecteur réel.
DRY_RUN = True
