# KB-01 · Procédure : capteur défaillant

## Signes d'une panne de capteur
Un capteur défaillant se manifeste de trois façons : il se tait (la passerelle enregistre des messages `no_data` pendant plusieurs cycles), il envoie des valeurs physiquement impossibles (hors des plages de KB-07), ou sa valeur reste figée alors que les autres capteurs de la salle varient.

## Capteur muet (silence prolongé)
Un silence de plus de 15 minutes (3 cycles) sans maintenance planifiée et sans rattrapage ultérieur des mesures est anormal. Vérifier d'abord la passerelle (les autres capteurs de la même passerelle émettent-ils ?), puis l'alimentation et la batterie du capteur. Si seule cette sonde est muette, ouvrir un ticket d'intervention terrain.

## Valeurs impossibles
Une température de 85 °C ou de -40 °C dans un bureau n'est pas une mesure mais un défaut (convertisseur, sonde débranchée, court-circuit). Ces valeurs ne doivent jamais être utilisées pour piloter le chauffage. Action conseillée : ticket d'intervention terrain et quarantaine logique des mesures en attendant.

## Valeur figée
Une valeur strictement identique pendant plusieurs heures (écart-type nul) indique en général un capteur bloqué ou un firmware gelé. Comparer avec les autres capteurs de la salle avant de conclure. Action conseillée : ticket d'intervention terrain.

## Ce qu'il ne faut pas faire
Ne jamais réinitialiser, reflasher ou supprimer un capteur à distance pour « voir si ça repart » : cela détruit les indices et peut masquer un problème de sécurité. Toute intervention physique est décidée par un opérateur humain.
