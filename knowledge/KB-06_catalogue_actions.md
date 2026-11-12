# KB-06 · Catalogue des actions autorisées

## Règle générale
Le copilote propose, l'opérateur décide. Toutes les actions sont exécutées en mode simulation (dry-run) : rien n'est envoyé aux capteurs. Les actions critiques exigent une confirmation explicite de l'opérateur.

## Actions non critiques
SURVEILLER : poursuivre la surveillance sans intervention. CLASSER_NORMAL : clôturer l'alerte comme fausse alerte avec une justification. MARQUER_HISTORIQUE : marquer des mesures rejouées comme historiques. COMPARER_VOISINS : demander une comparaison détaillée avec les capteurs de la salle.

## Actions critiques (confirmation obligatoire)
TICKET_TERRAIN : ouvrir un ticket d'intervention physique. REETALONNAGE : planifier un réétalonnage de la sonde. QUARANTAINE : exclure temporairement (et de façon réversible) les mesures du capteur des tableaux de bord et du pilotage. ESCALADE_SECU : transmettre l'alerte à l'équipe sécurité.

## Actions interdites
Supprimer un capteur ou des données, réinitialiser un équipement, forcer une mise à jour firmware, couper l'alimentation, désactiver des alertes, effacer ou modifier le journal des décisions. Ces actions ne sont ni proposées ni exécutables par le copilote.
