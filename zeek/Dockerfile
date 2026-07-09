FROM zeek/zeek:6.2

# ja3/hassh : packages de script purs, pas de compilation C++ requise
# community-id : script integre Zeek 4+ (policy/protocols/conn/community-id-logging)
RUN zkg install --force https://github.com/salesforce/ja3 && \
    zkg install --force https://github.com/salesforce/hassh

WORKDIR /zeek/logs

ENTRYPOINT ["/bin/sh", "-c"]
CMD ["zeek -i ${IFACE:-eth0} /usr/local/zeek/share/zeek/site/local.zeek"]
