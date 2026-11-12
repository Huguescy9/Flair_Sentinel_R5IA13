"""RAG local et sourcé.

Base de connaissances = fiches knowledge/KB-*.md (découpées par section "## ")
+ entrées du planning (data/planning.json). Recherche TF-IDF (scikit-learn) :
100 % local, aucun modèle d'embedding à télécharger.

Chaque passage porte un identifiant citable : KB-01#2, PLN-01...
"""

import json
import re

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from config import KNOWLEDGE_DIR, PLANNING_FILE

MIN_SCORE = 0.08  # en dessous : aucune source jugée pertinente

FRENCH_STOPWORDS = """
a au aux avec ce ces dans de des du elle en et eux il ils je la le les leur
lui ma mais me meme mes moi mon ne nos notre nous on ou par pas pour qu que
qui sa se ses son sur ta te tes toi ton tu un une vos votre vous c d j l m n
s t y est sont ete etre avoir ont fait faire plus tres tout tous toute toutes
cette cet si comment quoi quel quelle quels quelles dois faut peut
""".split()


def _load_chunks():
    chunks = []
    for path in sorted(KNOWLEDGE_DIR.glob("KB-*.md")):
        doc_id = path.stem.split("_")[0]
        text = path.read_text(encoding="utf-8")
        title = text.splitlines()[0].lstrip("# ").strip()
        sections = re.split(r"^## ", text, flags=re.M)[1:]
        for i, sec in enumerate(sections, start=1):
            heading, _, body = sec.partition("\n")
            chunks.append({
                "id": f"{doc_id}#{i}",
                "document": title,
                "titre": heading.strip(),
                "texte": body.strip(),
                "fichier": f"knowledge/{path.name}",
            })
    if PLANNING_FILE.exists():
        for p in json.loads(PLANNING_FILE.read_text(encoding="utf-8")):
            chunks.append({
                "id": p["id"],
                "document": "Planning des maintenances et événements",
                "titre": p["titre"],
                "texte": (f"{p['type'].capitalize()} « {p['titre']} » en salle {p['salle']}, "
                          f"du {p['debut']} au {p['fin']}. Capteurs : "
                          f"{', '.join(p['capteurs']) or 'toute la salle'}. "
                          f"Effets attendus : {p['effets_attendus']}"),
                "fichier": "data/planning.json",
            })
    return chunks


class BaseConnaissances:
    def __init__(self):
        self.chunks = _load_chunks()
        self.by_id = {c["id"]: c for c in self.chunks}
        corpus = [f"{c['document']} {c['titre']} {c['titre']} {c['texte']}" for c in self.chunks]
        self.vectorizer = TfidfVectorizer(strip_accents="unicode", lowercase=True,
                                          stop_words=FRENCH_STOPWORDS,
                                          ngram_range=(1, 2), sublinear_tf=True)
        self.matrix = self.vectorizer.fit_transform(corpus)

    def rechercher(self, query, k=4, min_score=MIN_SCORE):
        """Retourne les k passages les plus proches (avec leur score)."""
        scores = cosine_similarity(self.vectorizer.transform([query]), self.matrix)[0]
        ranked = scores.argsort()[::-1][:k]
        return [{**self.chunks[i], "score": round(float(scores[i]), 3)}
                for i in ranked if scores[i] >= min_score]

    def get(self, chunk_id):
        return self.by_id.get(chunk_id)
