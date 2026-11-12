# KB-04 · Fausse alerte connue : rejeu du tampon après coupure

## Le phénomène
Lorsqu'un capteur perd sa liaison radio, il continue à mesurer et stocke ses mesures dans une mémoire tampon. À la reconnexion, il envoie d'un coup toutes les mesures conservées : la passerelle reçoit alors une rafale de messages avec un statut réseau `reconnected` et des horodatages de mesure anciens (retard de plusieurs dizaines de minutes).

## Comment le reconnaître
Retard entre mesure et réception supérieur à un cycle (5 minutes), rafale de messages espacés de quelques secondes, valeurs plausibles et cohérentes avec les voisins, numéros de séquence continus. La période de silence qui précède est alors comblée par les mesures rejouées : aucune donnée n'est perdue.

## Conduite à tenir
C'est un comportement normal du capteur, pas une panne ni une attaque. Marquer les mesures comme historiques (elles ne décrivent pas l'instant présent) et ne pas déclencher d'intervention. Surveiller seulement si les coupures se répètent (qualité radio, RSSI faible).

## Quand s'inquiéter malgré tout
Si les valeurs rejouées sont impossibles, si les séquences reculent ou si l'adresse MAC change, il ne s'agit plus d'un simple rejeu : appliquer KB-01 ou KB-03.
