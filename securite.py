"""Garde-fous du copilote : pseudonymisation, injection, demandes destructives,
questions hors périmètre, fuite d'identifiants.

Ces contrôles sont DÉTERMINISTES : ils ne dépendent pas du bon vouloir du LLM.
"""

import hashlib
import hmac
import re
import secrets
import unicodedata

from config import PSEUDO_SALT


def _norm(text):
    """Minuscules sans accents, pour des recherches robustes."""
    text = unicodedata.normalize("NFD", str(text).lower())
    return "".join(c for c in text if unicodedata.category(c) != "Mn")


# =====================================================
# INJECTION DE PROMPT DANS LES DONNÉES
# =====================================================

INJECTION_PATTERNS = [
    r"ignore[rz]? (toutes |tous )?(les |tes |vos )?(consignes|instructions|regles)",
    r"oublie[rz]? (toutes |tous )?(les |tes |vos )?(consignes|instructions|regles)",
    r"ignore (all |the )?(previous|prior) (instructions|rules)",
    r"disregard",
    r"\bsystem\s*:",
    r"\bassistant\s*:",
    r"###",
    r"</?\s*donnees",
    r"nouvelle consigne",
    r"tu es (maintenant|desormais)",
    r"revele",
    r"jailbreak",
    r"\bprompt\b",
    r"classe (ce|les) capteurs? comme sains?",
]
_INJ_RE = [re.compile(p) for p in INJECTION_PATTERNS]


def detecter_injection(text):
    """Retourne (suspect, motifs trouvés)."""
    t = _norm(text)
    found = [p.pattern for p in _INJ_RE if p.search(t)]
    return bool(found), found


def neutraliser(text):
    """Remplace un texte suspect avant envoi au LLM (filtre activable)."""
    suspect, _ = detecter_injection(text)
    if suspect:
        return "[contenu retiré par le filtre : injection de consignes suspectée]"
    return text


# =====================================================
# DEMANDES DESTRUCTIVES
# =====================================================

DESTRUCTIVE_PATTERNS = [
    r"supprim", r"\beffac", r"detrui", r"reinitialis", r"\breset", r"formate",
    r"\bflash", r"reflash", r"eteind", r"coupe[rz]? (l'|l |le |la )?(alimentation|courant|capteur|reseau)",
    r"desactiv", r"redemarr", r"\breboot", r"\bpurge", r"\bwipe", r"\bdelete",
    r"\bremove", r"shutdown", r"rm -rf", r"drop table", r"parametres d'usine",
    r"factory", r"bloque[rz]? (le|les|ce|tous)",
]
_DESTR_RE = [re.compile(p) for p in DESTRUCTIVE_PATTERNS]

# Formes qui décrivent un fait ou une interdiction, pas une demande d'action
_PARTICIPE_RE = re.compile(
    r"(?<![-\w])(?:a|ont|avait|avaient|est|sont|ete|etait|etaient)(?:-t)?"
    r"(?:-(?:il|ils|elle|elles|on))?\s+(?:\w+\s+)?\w*e[es]{0,2}\b"
)
_NEGATION_RE = re.compile(
    r"\b(?:ne\s+(?:pas|jamais)|jamais|sans|eviter de|interdit de)\s+(?:\S+\s+){0,3}\S+"
    r"|\bne\s+\S+\s+(?:pas|jamais)(?:\s+\S+){0,3}"
)
_EXPLICATION_RE = re.compile(r"\s*(?:pourquoi|quand|depuis quand|explique|que signifie|qu'est-ce)\b")


def mentionne_operation_sensible(text):
    """Cherche une opération destructive, hors faits passés et interdictions."""
    t = _NEGATION_RE.sub(" ", _PARTICIPE_RE.sub(" ", _norm(text)))
    found = [p.pattern for p in _DESTR_RE if p.search(t)]
    return bool(found), found


def detecter_demande_destructive(text):
    """Une question d'explication (« pourquoi a-t-il redémarré ? ») n'est pas une demande."""
    if _EXPLICATION_RE.match(_norm(text)):
        return False, []
    return mentionne_operation_sensible(text)


# =====================================================
# PÉRIMÈTRE DU COPILOTE
# =====================================================

# Comparés en début de mot : « parc » ne doit pas accepter « parce que »
DOMAIN_KEYWORDS = [
    "capteur", "sonde", "alerte", "alarme", "anomal", "temperature", "humidite",
    "co2", "panne", "deriv", "clon", "rejeu", "tampon", "maintenance", "planning",
    r"parc\b", "salle", "bureau", "atelier", r"hall\b", "serveur", "mesure", "valeur",
    "journal", "decision", "action", "ticket", "priorit", "incident", "firmware",
    "batterie", "reseau", "passerelle", "sequence", r"mac\b", r"ip\b", "adresse", "referent",
    "resume", "situation", r"etat\b", "verifi", "flair", "copilote", "score",
    "isolation", "faux positif", "fausse alerte", "etalonnage", "quarantaine",
    "securite", "injection", "reunion", "numero de serie", "remplacement",
    "briefing", "urgent", "probleme", "traiter",
]
_DOMAIN_RE = re.compile(r"\b(?:" + "|".join(DOMAIN_KEYWORDS) + ")")
ID_PATTERN = re.compile(r"\b(TMP|HUM|CO2)-[A-Z0-9]+(-[A-C])?\b|\b(ALR|EVT|PLN|KB)-\d+", re.I)

# Dans une conversation en cours, « et pourquoi ? » s'appuie sur le message précédent
_SUITE_RE = re.compile(
    r"\s*(?:et|pourquoi|comment|explique|detaille|precise|lequel|laquelle|lesquels|lesquelles"
    r"|celui|celle|ca|cela|donc|alors)\b"
)


def est_hors_sujet(question, suite_conversation=False):
    t = _norm(question)
    if ID_PATTERN.search(question) or _DOMAIN_RE.search(t):
        return False
    return not (suite_conversation and _SUITE_RE.match(t))


# =====================================================
# SORTIE DU LLM AVANT AFFICHAGE
# =====================================================

_IMAGE_MD_RE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_LIEN_MD_RE = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_BALISE_RE = re.compile(r"</?[a-zA-Z][^>]*>")


def assainir_sortie(text):
    """Retire images, liens et balises HTML d'un texte produit par le LLM.

    Un texte piégé ne doit pas pouvoir déclencher une requête vers l'extérieur
    (une image distante, par exemple) depuis le navigateur de l'opérateur.
    """
    text = _IMAGE_MD_RE.sub("[image retirée]", str(text))
    text = _LIEN_MD_RE.sub(r"\1", text)
    return _BALISE_RE.sub("", text)


# =====================================================
# PSEUDONYMISATION
# =====================================================

MAC_RE = re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")


class Pseudonymiseur:
    """Remplace MAC, IP, e-mails et noms de référents par des jetons HMAC.

    La table de correspondance reste en mémoire locale : seul le texte
    pseudonymisé part vers le LLM.
    """

    def __init__(self, inventory=None, salt=PSEUDO_SALT):
        self.key = (salt or secrets.token_hex(16)).encode()
        self.reverse = {}
        self.names = []
        if inventory is not None and "referent" in inventory:
            self.names = sorted(set(inventory["referent"].dropna()), key=len, reverse=True)

    def token(self, prefix, value):
        digest = hmac.new(self.key, value.encode(), hashlib.sha256).hexdigest()[:6]
        tok = f"{prefix}-{digest}"
        self.reverse[tok] = value
        return tok

    def texte(self, text):
        if not isinstance(text, str) or not text:
            return text
        text = MAC_RE.sub(lambda m: self.token("MAC", m.group().upper()), text)
        text = IP_RE.sub(lambda m: self.token("IP", m.group()), text)
        text = EMAIL_RE.sub(lambda m: self.token("MAIL", m.group()), text)
        for name in self.names:
            if name in text:
                text = text.replace(name, self.token("PERS", name))
        return text

    def objet(self, obj):
        """Pseudonymise récursivement dict / list / str."""
        if isinstance(obj, dict):
            return {k: self.objet(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.objet(v) for v in obj]
        return self.texte(obj)

    def reveler(self, text):
        """Remet les vraies valeurs, pour l'affichage local à l'opérateur."""
        if not isinstance(text, str):
            return text
        for tok, val in self.reverse.items():
            text = text.replace(tok, val)
        return text


def contient_identifiant_reel(text, inventory):
    """Test de fuite : le texte contient-il une vraie MAC / IP / un nom ?"""
    t = str(text)
    reals = list(inventory["mac"]) + list(inventory["ip"]) + list(inventory["referent"])
    return [r for r in reals if r and r in t]
