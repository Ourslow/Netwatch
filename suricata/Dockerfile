FROM jasonish/suricata:7.0

# Telecharger les regles Emerging Threats Open
RUN suricata-update enable-source et/open && \
    suricata-update

# Repertoire de logs
RUN mkdir -p /var/log/suricata

WORKDIR /var/log/suricata

ENTRYPOINT ["/bin/sh", "-c"]
CMD ["suricata -c /etc/suricata/suricata.yaml -i ${IFACE:-eth0}"]
