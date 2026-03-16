FROM zeek/zeek:6.2

RUN zeek-pkg install zeek/ja3 && \
    zeek-pkg install zeek/hassh

WORKDIR /zeek

ENTRYPOINT ["zeek"]
CMD ["-i", "eth0", "/usr/local/zeek/share/zeek/site/local.zeek"]
