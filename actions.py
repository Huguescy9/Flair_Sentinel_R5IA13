"""Catalogue fermé des actions que le copilote peut proposer.

L'IA choisit un identifiant dans cette liste, rien d'autre. Aucune action
destructive n'existe ici, et toutes sont exécutées en simulation (dry-run).
"""

import hashlib

from config import DRY_RUN

CATALOGUE = {
    "SURVEILLER": {
        "libelle": "Poursuivre la surveillance",
        "description": "Aucune intervention, l'alerte reste ouverte.",
        "critique": False,
    },
    "CLASSER_NORMAL": {
        "libelle": "Clôturer comme fausse alerte",
        "description": "L'alerte est classée « probablement normale » avec justification.",
        "critique": False,
    },
    "MARQUER_HISTORIQUE": {
        "libelle": "Marquer les mesures comme historiques",
        "description": "Mesures rejouées après coupure : elles ne décrivent pas l'instant présent.",
        "critique": False,
    },
    "COMPARER_VOISINS": {
        "libelle": "Comparer aux capteurs voisins",
        "description": "Produire une comparaison détaillée avec les capteurs de la même salle.",
        "critique": False,
    },
    "TICKET_TERRAIN": {
        "libelle": "Ouvrir un ticket d'intervention terrain",
        "description": "Un technicien vérifie physiquement le capteur.",
        "critique": True,
    },
    "REETALONNAGE": {
        "libelle": "Planifier un réétalonnage",
        "description": "Contrôle de la sonde avec un instrument de référence.",
        "critique": True,
    },
    "QUARANTAINE": {
        "libelle": "Quarantaine logique des mesures",
        "description": "Exclure temporairement et de façon réversible les mesures du pilotage.",
        "critique": True,
    },
    "ESCALADE_SECU": {
        "libelle": "Escalader à l'équipe sécurité",
        "description": "Suspicion d'équipement non autorisé ou d'usurpation d'identité.",
        "critique": True,
    },
}

# Action proposée par les règles quand le LLM n'est pas disponible
ACTION_PAR_DEFAUT = {
    ("sensor_failure", "a_traiter"): "TICKET_TERRAIN",
    ("drift", "a_traiter"): "REETALONNAGE",
    ("possible_clone", "a_traiter"): "ESCALADE_SECU",
    ("unknown", "a_traiter"): "COMPARER_VOISINS",
    ("buffer_replay", "probablement_normal"): "MARQUER_HISTORIQUE",
    ("planned_event", "probablement_normal"): "CLASSER_NORMAL",
}


def action_par_defaut(hypothese, verdict):
    return ACTION_PAR_DEFAUT.get((hypothese, verdict), "SURVEILLER")


def libelle(action_id):
    return CATALOGUE.get(action_id, {}).get("libelle", action_id)


def executer(action_id, alert_id, sensor_id, operateur):
    """Exécution SIMULÉE : décrit ce qui serait fait, n'envoie rien."""
    if action_id not in CATALOGUE:
        raise ValueError(f"Action hors catalogue refusée : {action_id}")
    if not DRY_RUN:
        raise RuntimeError("Aucun connecteur réel n'est implémenté.")
    ref = hashlib.sha1(f"{alert_id}{action_id}{operateur}".encode()).hexdigest()[:6].upper()
    messages = {
        "SURVEILLER": f"Alerte {alert_id} laissée ouverte, surveillance poursuivie.",
        "CLASSER_NORMAL": f"Alerte {alert_id} clôturée comme fausse alerte.",
        "MARQUER_HISTORIQUE": f"Mesures de {sensor_id} liées à {alert_id} marquées « historiques ».",
        "COMPARER_VOISINS": f"Rapport de comparaison de {sensor_id} avec sa salle demandé.",
        "TICKET_TERRAIN": f"Ticket TCK-DRY-{ref} créé pour une vérification physique de {sensor_id}.",
        "REETALONNAGE": f"Réétalonnage de {sensor_id} planifié (ordre ETL-DRY-{ref}).",
        "QUARANTAINE": f"Mesures de {sensor_id} exclues du pilotage (réversible, QRT-DRY-{ref}).",
        "ESCALADE_SECU": f"Dossier SEC-DRY-{ref} transmis à l'équipe sécurité pour {sensor_id}.",
    }
    return f"[DRY-RUN] {messages[action_id]} Aucune commande n'a été envoyée aux équipements."
