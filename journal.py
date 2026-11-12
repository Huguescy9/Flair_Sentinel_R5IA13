"""Journal des décisions : append-only, chaîné par empreintes SHA-256.

Chaque ligne contient l'empreinte de la ligne précédente : modifier ou
supprimer une ligne casse la chaîne, ce que verifier() détecte.
"""

import hashlib
import json
from datetime import datetime, timezone

from config import JOURNAL_DIR, JOURNAL_FILE

GENESIS = "0" * 64


def _hash(entry):
    payload = json.dumps(entry, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def lire():
    if not JOURNAL_FILE.exists():
        return []
    with JOURNAL_FILE.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def ajouter(type_entree, operateur, **champs):
    """Ajoute une entrée et la renvoie (avec son empreinte)."""
    JOURNAL_DIR.mkdir(exist_ok=True)
    entries = lire()
    entry = {
        "n": len(entries) + 1,
        "horodatage": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "type": type_entree,
        "operateur": operateur,
        **champs,
        "hash_precedent": entries[-1]["hash"] if entries else GENESIS,
    }
    entry["hash"] = _hash(entry)
    with JOURNAL_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def verifier():
    """Retourne (intègre, numéro de la première ligne invalide ou None)."""
    previous = GENESIS
    for entry in lire():
        body = {k: v for k, v in entry.items() if k != "hash"}
        if entry.get("hash_precedent") != previous or _hash(body) != entry.get("hash"):
            return False, entry.get("n")
        previous = entry["hash"]
    return True, None


def statut_alertes():
    """Dernière décision humaine connue pour chaque alerte."""
    status = {}
    for e in lire():
        if e.get("type") == "decision_alerte":
            status[e["alert_id"]] = e
    return status
