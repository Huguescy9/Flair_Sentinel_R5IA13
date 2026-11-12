# Journal de bord de l'équipe

**Équipe :** CHANE-YIN Hugues (Données et Modèles), CAZANOVE Romain (Intégration), CHAN-THIEN-LONG Tao (Sécurité & évaluation).

## Grille de choix des familles d'IA (J1)

| Besoin | Option envisagée | Choix | Pourquoi |
|---|---|---|---|
| Repérer des valeurs impossibles, un silence, une MAC inconnue | Règles expertes | **Règles** | Critères connus, explicables, zéro faux positif sur ces cas |
| Hiérarchiser et repérer l'inattendu | ML supervisé | Écarté | Pas d'étiquettes réelles en exploitation ; on entraînerait sur nos propres scénarios (circulaire) |
| Idem | ML non supervisé (Isolation Forest) | **Retenu** | Pas besoin d'étiquettes, rapide, score 0–1 utilisable pour la priorité |
| Distinguer incident / fausse alerte | Règles + contexte (planning, rejeu) | **Retenu** | Le planning est une donnée métier ; le ML seul ne peut pas la deviner |
| Expliquer, citer la procédure, proposer une action | LLM local + RAG | **Qwen2.5 7B via Ollama + TF-IDF** | Local (règle du projet), français correct, sortie JSON contrainte ; TF-IDF suffit pour 36 passages et ne demande aucun modèle d'embedding |
| Décider | IA | **Jamais** | Condition de la direction : l'humain décide |

Mesure qui justifie la combinaison (page Évaluation, « Comparaison des approches ») : le ML seul est précis mais rate plus de 90 % des messages d'incident ; les règles sans contexte lèvent 84 fausses alertes ; la chaîne complète détecte 5 incidents sur 6 sans aucune alerte à tort.

## Points d'étape par jalon

### J1 · Cadrage (fin octobre 2026)

- **Avancement :** terrain choisi (parc de capteurs IoT), incidents et fausses alertes définis, grille de choix des IA, rôles répartis.
- **Blocage :** groupe de 3 au lieu de 4 ; Hugues cumule Données et Modèles.
- **Décision :** fausses alertes retenues = rejeu de tampon (imposé), maintenance planifiée, réunion.

### J2 · Données (27/10 puis 04/11/2026)

- **Avancement :** premier générateur (300 événements), puis régénération complète en séries temporelles (30 capteurs, 48 h, 17 370 messages), vérité terrain séparée, pseudonymisation.
- **Blocage :** la première version donnait 100 % d'exactitude parce que les données contenaient la réponse (`scenario_id`, capteurs nommés `S-FAIL-01`).
- **Décision :** tout régénérer sans fuite, trois sondes de température par salle.

### J3 · IA (04/11/2026)

- **Avancement :** détection (Isolation Forest + règles + contexte), regroupement en alertes, RAG sur 8 fiches et le planning, LLM local avec sortie JSON imposée. Premiers chiffres : 5 incidents sur 6, 0 alerte à tort.
- **Blocage :** avec des clés anglaises, Qwen choisissait la mauvaise hypothèse ; il citait les sources entre crochets, ce que le contrôle rejetait.
- **Décision :** hypothèses en clés françaises, normalisation des sources.

### J4 · Chaîne (04/11/2026)

- **Avancement :** validation humaine, catalogue fermé de 8 actions, dry-run verrouillé, journal chaîné SHA-256, analyse de risques.
- **Blocage :** le LLM proposait parfois une action trop faible (SURVEILLER) pour une alerte grave.
- **Décision :** garde-fou « action trop faible » et contrôle de désaccord entre l'IA et les règles.

### J5 · Évaluation (04/11 au 12/11/2026)

- **Avancement :** campagne de 23 cas avec le LLM (20 réussis, 2 rattrapés, 1 échoué), puis relecture de sécurité du code et campagne étendue à 31 cas.
- **Blocage :** instabilité matérielle (carte graphique) pendant une campagne avec le LLM.
- **Décision :** mode processeur avec un interrupteur dans l'interface, campagne sauvegardée après chaque cas, lanceur `.bat`.

## Décisions

| Jalon | Décision | Raison | Qui |
|---|---|---|---|
| J1 | Terrain IoT « parc de capteurs » : panne, dérive, clonage ; fausses alertes : rejeu de tampon, maintenance, réunion | Couvre les trois incidents du sujet et la fausse alerte imposée (rejeu) | Toute l'équipe |
| J1 | Répartition des rôles, Hugues cumule Données et Modèles | Groupe de 3 | Toute l'équipe |
| J2 | Régénérer les données en séries temporelles (30 capteurs, 48 h) | L'ancienne version contenait la réponse : 100 % d'exactitude sans valeur | Hugues |
| J2 | Trois sondes de température par salle | Sans voisins, impossible de distinguer une dérive d'une variation de la salle | Hugues |
| J2 | Ajouter MAC, IP, référent : données à pseudonymiser | Exigence du sujet : traiter les données comme réelles | Hugues |
| J3 | Isolation Forest (contamination 1 %) + règles | Voir grille ci-dessus | Hugues |
| J3 | Alertes = regroupement des messages consécutifs d'un capteur | 17 370 messages → 13 alertes, dont 5 à traiter : c'est le gain de temps de l'équipe | Hugues |
| J3 | Sortie LLM au format JSON imposé (schéma Ollama) avec enum des actions | Le modèle ne peut matériellement pas produire une action hors catalogue | Hugues |
| J3 | Hypothèses en clés françaises pour le LLM | Avec des clés anglaises, Qwen choisissait une mauvaise catégorie | Hugues |
| J4 | Catalogue fermé de 8 actions, dry-run verrouillé, confirmation pour les actions critiques | Règles non négociables du sujet | Romain |
| J4 | Journal JSONL chaîné par SHA-256 | Journal de chaque décision, falsification détectable | Romain |
| J4 | Mode dégradé « règles seules » si Ollama est absent | La démo ne doit pas dépendre d'un seul composant | Romain |
| J4 | Analyse de risques (menaces, mesures, tests associés) | Jalon J4 | Tao |
| J5 | Campagne de 23 cas (`python evaluate.py`) | Minimum 15 cas exigé, toutes les catégories du sujet | Tao |
| J5 | Garde-fou « action trop faible pour une alerte grave » | Constat en test : Qwen propose parfois SURVEILLER pour un clonage | Tao |
| J5 | Interface réduite de 7 à 5 pages (Alertes, Investigation, Assistant IA, Journal, Évaluation) | Tableau de bord et file faisaient doublon ; chaque page correspond à une étape de la démo | Romain |
| J5 | Relecture de sécurité du code : pseudonymisation de la question, filtre d'injection dans le chat, sortie du LLM assainie, contrôle d'URL strict, faux refus corrigés | Trous trouvés à la relecture, chacun couvert par un test | Tao |
| J5 | Campagne étendue à 31 cas, résultat attendu affiché pour chaque cas | Le sujet demande les cas « avec leur résultat attendu » | Tao |
| J5 | Valider une proposition signalée exige commentaire et confirmation | Un signalement que l'on peut ignorer d'un clic n'empêche pas de nuire | Romain |
| J5 | Lanceur `Lancer FLAIR.bat`, interrupteur processeur / carte graphique, campagne sauvegardée après chaque cas | Instabilité matérielle pendant une campagne avec le LLM : la démonstration ne doit pas en dépendre | Romain |

## Points ouverts

- Relancer la campagne avec le LLM sur un PC stable : les chiffres LLM affichés datent du 04/11.
- INC-06 (dérive lente d'humidité) n'est pas détectée : deuxième capteur d'humidité par salle ou comparaison avec la moyenne du bâtiment ?
- Le journal chaîné ne résiste pas à une réécriture complète : ancrer la dernière empreinte ailleurs (impression, dépôt git) ?
- Tester la robustesse sur un jeu généré avec une autre graine et d'autres amplitudes.
