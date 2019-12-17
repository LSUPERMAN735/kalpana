# kalpana

## Version LARP

Description "formelle" du traitement d'une trame Ethernet dans un switch

## Version Python

Exemple d'utilisation :
```
./kalpana.py eth0 eth1 eth2
```

La CLI accepte les commandes suivantes :
- `debug` : mode verbeux (désactivé par défaut)
- `forwarding` : transmission des trames reçues (activé par défaut)
- `exit` : arrêt du switch

Utilise `scapy` pour la capture en l'envoi de trames L2.
