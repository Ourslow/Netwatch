# Alertes NetWatch

## Alertes Grafana configurées

| Alerte | Seuil | Description |
|--------|-------|-------------|
| Port Scan | >50 ports/min depuis une IP | Détection reconnaissance réseau |
| Pic de trafic | >3x la moyenne sur 5 min | Exfiltration potentielle / DDoS |
| DNS suspect | Entropie domaine >3.5 | Communication C2 (DGA) |
| Cert TLS expiré | Expiration <7 jours | Certificat à renouveler |

## Tester les alertes

### 1. Scan de ports (nmap)
```bash
nmap -sS -p 1-1000 <IP_CIBLE>
```

### 2. DGA simulé (dig en boucle)
```bash
for domain in xkjhqpwmzr vjkqplxnbt rnmxqjzpvl hqzwxpnrjm; do
  dig ${domain}.com @8.8.8.8
done
```

### 3. Pic de trafic
```bash
# Rejouer un PCAP volumineux en boucle
for i in {1..10}; do
  docker exec -it netwatch-zeek zeek -r /pcap/large-capture.pcap local
done
```
