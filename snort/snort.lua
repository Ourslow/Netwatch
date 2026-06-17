-- NetWatch — Snort 3 Configuration
-- Sortie JSON pour integration Filebeat -> Elasticsearch

-- Reseau a surveiller
HOME_NET = '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16'
EXTERNAL_NET = '!$HOME_NET'

-- Variables reseau/ports par defaut de Snort 3 (HTTP_SERVERS, HTTP_PORTS,
-- SMTP_SERVERS, etc.) requises par les regles community. Definit 'default_variables'
-- a partir des HOME_NET/EXTERNAL_NET ci-dessus.
dofile('/usr/local/etc/snort/snort_defaults.lua')

-- Serveur surveille en specifique — definir via variable d'env ou surcharge locale
-- Ne pas mettre d'IP en clair ici : creer snort.local.lua avec MONITORED_SERVER = 'x.x.x.x'
MONITORED_SERVER = os.getenv('SNORT_MONITORED_SERVER') or '127.0.0.1'

-- Decodeurs
wizard = default_wizard

-- Inspectors
stream = {}
stream_ip = {}
stream_tcp = {}
stream_udp = {}
stream_icmp = {}

http_inspect = {}
ssl = {}
dns = {}
ssh = {}
smtp = {}
pop = {}
imap = {}

-- Normalisation
normalize = {}

-- Port scan detection
port_scan = {
    protos = 'all',
    scan_types = 'all',
    memcap = 10000000
}

-- Regles IPS
ips = {
    enable_builtin_rules = true,
    variables = default_variables,
    rules = [[
        include /usr/local/etc/rules/snort3-community.rules
        include /usr/local/etc/rules/local.rules
    ]]
}

-- Sortie JSON (compatible Filebeat)
alert_json = {
    file = true,
    limit = 100,
    fields = 'timestamp pkt_num proto pkt_gen pkt_len dir src_addr src_port dst_addr dst_port service rule action msg priority class_desc'
}

-- Sortie alertes classique (backup)
alert_fast = {
    file = true,
    packet = false
}

-- Logging
output = {
    logdir = '/var/log/snort',
    show_year = true
}

-- Performances
process = {
    daemon = false,
    utc = true
}
