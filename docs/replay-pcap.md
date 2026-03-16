# Rejouer un fichier PCAP

## Commande de base

```bash
docker exec -it netwatch-zeek zeek -r /pcap/sample.pcap local
```

## Rejouer un répertoire entier

```bash
for pcap in ./pcap/*.pcap; do
  echo "[*] Replay: $pcap"
  docker exec -it netwatch-zeek zeek -r /pcap/$(basename $pcap) local
done
```

## Sources de PCAPs recommandées

| Source | URL | Type |
|--------|-----|------|
| Malware Traffic Analysis | https://www.malware-traffic-analysis.net/ | Infections réelles |
| Wireshark Sample Captures | https://wiki.wireshark.org/SampleCaptures | Variés |
| NETRESEC | https://www.netresec.com/?page=PcapFiles | Collection publique |
| CyberDefenders | https://cyberdefenders.org/ | CTF Blue Team |
| Root-Me | https://www.root-me.org/ | CTF |
