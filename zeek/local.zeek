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

# VoIP — SIP (T_026)
# policy/protocols/sip — absent de l'image Docker Zeek 6.2 utilisée ici (module non trouvé
# au chargement, crash-loop du conteneur). Désactivé : voip-mos.zeek reste alimenté via les
# fallbacks conn.log (voir voip-quality.py, 3 fallbacks).
# @load policy/protocols/sip
# NOTE: policy/protocols/rtp n'existe PAS dans Zeek 6.x (pas d'analyzer RTP natif dans
# les sources officielles zeek/zeek). Les métriques RTP sont approximées depuis conn.log
# UDP (ports 16384-32767 et 10000-20000) dans le script voip-mos.zeek ci-dessous.

# Scripts custom NetWatch
@load ./scripts/port-scan-detect.zeek
@load ./scripts/dns-entropy.zeek
# tcp-performance désactivé temporairement : référence c$conn$rtt / orig_retrans_pkts /
# resp_retrans_pkts, champs absents du record conn de cette build Zeek 6.2 (crash fatal
# au chargement). À corriger : ces métriques ne sont pas exposées nativement par Zeek,
# nécessitent soit un plugin, soit un calcul différent (ex: history string).
# @load ./scripts/tcp-performance
@load ./scripts/app-response-time
@load ./scripts/voip-mos

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
