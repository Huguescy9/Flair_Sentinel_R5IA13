# Direction visuelle — FLAIR Sentinel

Références dans `docs/design/refs/` (captures de produits tiers, gardées sur le poste et non versionnées). On reprend un trait précis de chacune, pas leur look entier :

| Référence | Ce qu'on garde |
|---|---|
| `01-incidentio-cadre-couleurs.png` | Cadre sombre (barre latérale) + zone de contenu claire posée comme une carte arrondie, accent orange rare, typo Inter aérée |
| `02-opensea-tableau-filtres.png` | Tableau avec barre d'outils au-dessus : tri, recherche, filtres, sélecteur de période |
| `03-leste-donnees-panneau.png` | Graphique de synthèse en haut, liste en dessous, panneau de détail à droite pour l'élément sélectionné |

Ce qu'on ne copie pas : logos, noms, icônes de marque, contenus des captures.

## Couleurs

Valeurs estimées à partir des captures, à ajuster à l'œil une fois appliquées.

| Jeton | Valeur | Usage |
|---|---|---|
| `cadre` | `#2B2B2D` | Barre latérale, fond derrière la zone de contenu |
| `cadre-actif` | `#3A3A3C` | Élément de navigation sélectionné |
| `cadre-texte` | `#D4D4D6` | Texte de la barre latérale (blanc pur pour l'actif) |
| `fond` | `#FFFFFF` | Zone de contenu |
| `fond-doux` | `#F4F4F5` | Onglet / filtre sélectionné, champs, cartes secondaires |
| `bordure` | `#E5E5E5` | Bordures 1 px, séparateurs de lignes |
| `texte` | `#1C1C1E` | Texte principal |
| `texte-2` | `#6B6B6B` | Libellés, en-têtes de colonnes, texte secondaire |
| `accent` | `#F25533` | Orange de marque : icône de navigation active, logo, onglet actif. **Rare.** |
| `bouton` | `#232325` | Bouton principal (texte blanc) |

### Couleurs de statut (sémantiques, distinctes de l'accent)

L'orange est une couleur de **marque**, pas de gravité. Une alerte « À traiter » ne doit jamais être orange : sinon l'opérateur confond la décoration et l'urgence.

| Statut | Texte | Fond | Bordure |
|---|---|---|---|
| À traiter | `#B42318` | `#FDECEA` | `#F5A8A0` |
| Probablement normal | `#1D4ED8` | `#E8F0FE` | `#A9C4F5` |
| Normal / succès | `#1D7A5C` | `#DDF5EC` | `#3CC4A0` |
| Avertissement (garde-fou, LLM en erreur) | `#8A5A00` | `#FFF4D6` | `#F0C860` |

Dans les graphiques, versions pleines : rouge `#E5484D`, bleu `#3E7BFA`, vert `#2FB383` (`ROUGE`, `BLEU`, `VERT` dans `app.py`). Les séries qui ne portent pas de verdict (plusieurs MAC d'un même capteur, par exemple) prennent des couleurs neutres (`#232325`, `#8B5CF6`…) : rouge et vert laisseraient croire qu'une série est « la bonne ».

## Typographie

- **Inter** (OFL, libre). Graisses 400 et 500 ; 600 uniquement pour les titres de page.
- Tailles : titre de page 1.5rem, titre de section 1rem / 500, texte 0.95rem, libellés et en-têtes de colonnes 0.8rem `texte-2`.
- Chiffres des tableaux : `font-variant-numeric: tabular-nums`, alignés à droite.
- **Police servie en local** (`static/fonts/`), jamais depuis Google Fonts : le projet est 100 % local, l'interface ne doit faire aucune requête externe.

## Formes

- Rayon : 10 px pour la zone de contenu et les cartes, 6 px pour boutons, champs et badges.
- Bordures 1 px `bordure` plutôt que des ombres. Ombre seulement sur les menus flottants.
- Espacements sur une grille de 4 px ; marges intérieures des cartes 16 à 20 px.

## Mise en page

- **Barre latérale** sombre (`cadre`) : navigation, état du LLM, interrupteurs. L'élément actif a le fond `cadre-actif` et son icône en `accent`.
- **Zone de contenu** claire, avec un en-tête de page : titre + sous-titre à gauche, actions à droite (bouton principal sombre, secondaires bordés).
- **Onglets** soulignés : texte `texte` + trait 2 px sous l'actif, inactifs en `texte-2`.

### Tableaux (réf. 02)

- Barre d'outils au-dessus : tri (liste déroulante), recherche, filtres, période (`Tout · 48 h · 24 h · 6 h · 1 h`) en boutons texte, l'actif souligné.
- En-têtes discrets (0.8rem, `texte-2`), lignes séparées par un trait `bordure`, pas de fond alterné.
- Valeurs numériques alignées à droite ; écarts positifs / négatifs colorés seulement quand le signe a un sens.
- Verdict affiché en badge (couleurs de statut), pas en texte coloré seul.

### Données + panneau de détail (réf. 03)

- Page Alertes / Investigation : graphique de synthèse en haut (pleine largeur), file d'alertes en dessous, **panneau de détail à droite** (~⅓ de largeur) pour l'alerte sélectionnée.
- Panneau : paires libellé / valeur (libellé `texte-2` à gauche, valeur `texte` à droite), sections séparées par un titre, actions en bas.
- Graphiques Plotly : fond transparent, grille `bordure`, texte `texte-2`, séries en couleurs de statut ; abandonner `template="plotly_dark"`.

## Mise en œuvre dans Streamlit

- Couleurs de base dans `.streamlit/config.toml` : `[theme]` pour la zone de contenu (claire) et `[theme.sidebar]` pour la barre latérale (sombre). Le thème clair reste **imposé** (`base = "light"`) pour la même raison que l'actuel thème sombre : ne pas dépendre du thème du PC.
- Police : `[[theme.fontFaces]]` pointant vers `app/static/fonts/...` avec `server.enableStaticServing = true`.
- Le reste (zone de contenu en carte, badges, onglets) en CSS dans le bloc `<style>` de `app.py`, en ciblant les `data-testid`, à revérifier à chaque mise à jour de Streamlit.

### Règle de sécurité (risque R7)

Le HTML personnalisé ne sert qu'à du contenu **statique** écrit par nous (styles, structure). Aucun texte venant du LLM ou d'un capteur (`device_msg`) ne doit passer dans un `st.markdown(..., unsafe_allow_html=True)` ou un `st.html` : il reste affiché par les composants standards, après le nettoyage existant.
