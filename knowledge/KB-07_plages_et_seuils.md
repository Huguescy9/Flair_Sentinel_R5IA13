# KB-07 · Plages physiques et seuils de détection

## Plages plausibles en intérieur
Température : -10 à 50 °C. Humidité relative : 0 à 100 %. CO2 : 350 à 5000 ppm. Hors de ces plages, la valeur est considérée comme impossible pour un bâtiment de bureaux.

## Valeurs habituelles du parc
Bureaux : 20 à 24 °C, humidité 40 à 55 %, CO2 420 à 1100 ppm en journée. Salle serveurs : environ 18 à 19 °C, CO2 stable vers 420 ppm.

## Seuils du copilote
Silence : 3 cycles consécutifs (15 min). Valeur figée : même valeur répétée 12 fois de suite (1 heure). Dérive : écart moyen de plus de 1 °C à la médiane de la salle sur 2 heures. Rejeu : statut « reconnected » et plus de 5 minutes (un cycle) entre mesure et réception. Ces seuils sont des choix de conception à ajuster avec l'équipe.

## Score du modèle d'apprentissage
Un modèle Isolation Forest attribue à chaque message un score d'anomalie entre 0 et 1 à partir de variables calculées (écart à la médiane de la salle, saut de valeur, retard, silence, séquence). Le score sert à prioriser ; il ne prouve rien à lui seul.
