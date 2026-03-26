# NetWatch — Zeek local config

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/frameworks/notice
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/ssl/expiring-certs
@load policy/protocols/ssl/validate-certs

# Scripts custom NetWatch
@load ./scripts/port-scan-detect.zeek
@load ./scripts/dns-entropy.zeek

# Format JSON pour tous les logs
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

# Répertoire de sortie des logs
redef Log::default_writer = Log::WRITER_ASCII;
