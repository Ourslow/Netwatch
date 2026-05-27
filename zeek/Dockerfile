FROM zeek/zeek:6.2

RUN zkg install https://github.com/salesforce/ja3 --force && \
    zkg install https://github.com/salesforce/hassh --force && \
    zkg install corelight/zeek-community-id --force

WORKDIR /zeek

ENTRYPOINT ["/bin/sh", "-c"]
CMD ["zeek -i ${IFACE:-eth0} /usr/local/zeek/share/zeek/site/local.zeek"]
