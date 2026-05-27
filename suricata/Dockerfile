FROM jasonish/suricata:7.0

# Regles ET Open (build time — mise a jour automatique au runtime via entrypoint.sh)
RUN suricata-update enable-source et/open && \
    suricata-update

# Repertoire de logs
RUN mkdir -p /var/log/suricata

WORKDIR /var/log/suricata

# Entrypoint : mise a jour regles au demarrage + reload quotidien via SIGUSR2
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
