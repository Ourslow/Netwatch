# NetWatch — Zeek local config

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/frameworks/notice
@load base/frameworks/files
@load base/files/x509
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/ssl/expiring-certs
@load policy/protocols/ssl/validate-certs

# Community ID (RFC draft) — corrèle conn.log Zeek avec alertes Suricata/Snort
@load policy/protocols/conn/community-id-logging

# Packages zkg installés : ja3, hassh
@load packages

# Scripts custom NetWatch
@load ./scripts/port-scan-detect.zeek
@load ./scripts/dns-entropy.zeek
@load ./scripts/tcp-performance
@load ./scripts/app-response-time

# Intel Framework — Threat Intelligence feeds (ip_watchlist.dat, domain_watchlist.dat)
@load frameworks/intel/seen
@load frameworks/intel/do_notice
redef Intel::read_files += {
    "/usr/local/zeek/share/zeek/site/intel/ip_watchlist.dat",
    "/usr/local/zeek/share/zeek/site/intel/domain_watchlist.dat"
};

# Format JSON pour tous les logs
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

# Répertoire de sortie des logs
redef Log::default_writer = Log::WRITER_ASCII;
