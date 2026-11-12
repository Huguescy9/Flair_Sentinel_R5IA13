# KB-03 · Procédure : identité suspecte (clonage possible)

## Signes d'alerte
Un même identifiant de capteur qui émet depuis deux adresses MAC différentes, une adresse MAC absente de l'inventaire, des numéros de séquence qui reculent ou alternent entre deux séries, ou une cadence d'émission doublée sont des signes de clonage d'identité ou d'équipement non autorisé.

## Pourquoi c'est sérieux
Un équipement qui usurpe l'identité d'un capteur peut injecter de fausses mesures (par exemple faire croire que la salle serveurs est trop chaude ou trop froide). C'est un incident de sécurité potentiel, pas une simple panne.

## Explications légitimes à écarter
Un remplacement de capteur non déclaré dans l'inventaire ou une maintenance planifiée (redémarrage avec remise à zéro du compteur de séquence) peuvent ressembler à un clonage. Vérifier le planning des maintenances avant de conclure.

## Actions conseillées
Ne pas conclure automatiquement à une attaque. Escalader à l'équipe sécurité avec les indices (adresses MAC pseudonymisées, séquences, horaires) et placer les mesures du capteur en quarantaine logique. Ne jamais bloquer ou supprimer un équipement sans validation humaine.
