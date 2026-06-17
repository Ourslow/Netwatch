-- NetWatch — Snort 3 Configuration
-- Sortie JSON pour integration Filebeat -> Elasticsearch

-- Reseau a surveiller
HOME_NET = '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16'
EXTERNAL_NET = '!$HOME_NET'

-- Variables reseau/ports par defaut de Snort 3 (HTTP_SERVERS, HTTP_PORTS,
-- SMTP_SERVERS, etc.) requises par les regles community. Definit 'default_variables'
-- a partir des HOME_NET/EXTERNAL_NET ci-dessus.
dofile('/usr/local/etc/snort/snort_defaults.lua')

-- Serveur surveille en specifique — definir via SNORT_MONITORED_SERVER dans .env
-- Le placeholder 'x.x.x.x' (du .env.example) ou une valeur vide retombe sur
-- 127.0.0.1 : sinon Snort echoue a parser l'IP et casse toute la table IPS.
MONITORED_SERVER = os.getenv('SNORT_MONITORED_SERVER')
if not MONITORED_SERVER or MONITORED_SERVER == '' or MONITORED_SERVER == 'x.x.x.x' then
    MONITORED_SERVER = '127.0.0.1'
end

-- Expose MONITORED_SERVER aux regles IPS ($MONITORED_SERVER dans local.rules).
-- default_variables est defini par snort_defaults.lua (charge ci-dessus).
default_variables.nets.MONITORED_SERVER = MONITORED_SERVER

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
-- Champs valides du plugin alert_json de Snort 3.3.5 (pkt_gen / class_desc n'existent pas).
-- es_client.py (branche snort) lit : msg, src_addr, dst_addr, priority.
alert_json = {
    file = true,
    limit = 100,
    fields = 'timestamp pkt_num proto pkt_len dir src_addr src_port dst_addr dst_port service rule action msg priority class'
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
