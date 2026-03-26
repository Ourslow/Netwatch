FROM zeek/zeek:6.2

RUN zkg install https://github.com/salesforce/ja3 --force && \
    zkg install https://github.com/salesforce/hassh --force

WORKDIR /zeek

ENTRYPOINT ["zeek"]
CMD ["-i", "eth0", "/usr/local/zeek/share/zeek/site/local.zeek"]
