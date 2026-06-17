FROM zeek/zeek:6.2

# Outils de build pour les plugins binaires zkg (ex. community-id)
RUN apt-get update && apt-get install -y --no-install-recommends cmake g++ make \
    && rm -rf /var/lib/apt/lists/*

# ja3/hassh : packages de script (requis). community-id : plugin binaire,
# rendu non bloquant (Community ID est deja fourni par Suricata) pour ne pas
# faire echouer le build si sa compilation casse.
RUN zkg install --force https://github.com/salesforce/ja3 && \
    zkg install --force https://github.com/salesforce/hassh && \
    (zkg install --force --skiptests corelight/zeek-community-id \
      || echo "[warn] zeek-community-id non installe — Community ID reste fourni par Suricata")

WORKDIR /zeek

ENTRYPOINT ["/bin/sh", "-c"]
CMD ["zeek -i ${IFACE:-eth0} /usr/local/zeek/share/zeek/site/local.zeek"]
