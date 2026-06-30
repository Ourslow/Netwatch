# NetWatch — Application Response Time (ART)
# Mesure les délais applicatifs HTTP, DNS et TLS
# Output : art.log (champs ts, uid, src/dst ip+port, service, art_ms, detail)

module ART;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:       time    &log;
        uid:      string  &log;
        src_ip:   addr    &log;
        src_port: port    &log;
        dst_ip:   addr    &log;
        dst_port: port    &log;
        service:  string  &log;
        art_ms:   double  &log;
        detail:   string  &log &optional;
    };
}

# Table de suivi des timestamps de requêtes HTTP en cours
# clé : uid de la connexion
global http_req_ts: table[string] of time &create_expire=30sec;
global http_req_detail: table[string] of string &create_expire=30sec;

# Table de suivi des timestamps de client_hello TLS
global tls_hello_ts: table[string] of time &create_expire=30sec;
global tls_hello_sni: table[string] of string &create_expire=30sec;

event zeek_init()
{
    Log::create_stream(ART::LOG, [$columns=Info, $path="art"]);
}

# ─── HTTP ──────────────────────────────────────────────────────────────────────

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    http_req_ts[c$uid]     = network_time();
    http_req_detail[c$uid] = fmt("%s %s", method, original_URI);
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
    if (c$uid !in http_req_ts)
        return;

    local art = interval_to_double(network_time() - http_req_ts[c$uid]) * 1000.0;
    local det = c$uid in http_req_detail ? http_req_detail[c$uid] : "";

    local info: Info;
    info$ts       = network_time();
    info$uid      = c$uid;
    info$src_ip   = c$id$orig_h;
    info$src_port = c$id$orig_p;
    info$dst_ip   = c$id$resp_h;
    info$dst_port = c$id$resp_p;
    info$service  = "http";
    info$art_ms   = art;
    info$detail   = det;

    Log::write(ART::LOG, info);

    delete http_req_ts[c$uid];
    delete http_req_detail[c$uid];
}

# ─── DNS ───────────────────────────────────────────────────────────────────────
# Le champ rtt est déjà calculé par Zeek dans dns.log.
# On le reloggue ici dans art.log pour avoir une vue unifiée HTTP+DNS+TLS.

event dns_end(c: connection, msg: dns_msg)
{
    if (!c$dns?$rtt) return;
    if (!c$dns?$query) return;

    local art = interval_to_double(c$dns$rtt) * 1000.0;

    local info: Info;
    info$ts       = network_time();
    info$uid      = c$uid;
    info$src_ip   = c$id$orig_h;
    info$src_port = c$id$orig_p;
    info$dst_ip   = c$id$resp_h;
    info$dst_port = c$id$resp_p;
    info$service  = "dns";
    info$art_ms   = art;
    info$detail   = c$dns$query;

    Log::write(ART::LOG, info);
}

# ─── TLS ───────────────────────────────────────────────────────────────────────

event ssl_client_hello(c: connection, version: count, record_version: count,
                       possible_ts: time, client_random: string,
                       session_id: string, ciphers: index_vec,
                       comp_methods: index_vec)
{
    tls_hello_ts[c$uid] = network_time();

    # Récupérer le SNI si disponible (ajouté par Zeek lors du parsing du message)
    if (c$ssl?$server_name)
        tls_hello_sni[c$uid] = c$ssl$server_name;
    else
        tls_hello_sni[c$uid] = cat(c$id$resp_h);
}

event ssl_server_hello(c: connection, version: count, record_version: count,
                       possible_ts: time, server_random: string,
                       session_id: string, cipher: count, comp_method: count)
{
    if (c$uid !in tls_hello_ts)
        return;

    local art = interval_to_double(network_time() - tls_hello_ts[c$uid]) * 1000.0;
    local sni = c$uid in tls_hello_sni ? tls_hello_sni[c$uid] : cat(c$id$resp_h);

    local info: Info;
    info$ts       = network_time();
    info$uid      = c$uid;
    info$src_ip   = c$id$orig_h;
    info$src_port = c$id$orig_p;
    info$dst_ip   = c$id$resp_h;
    info$dst_port = c$id$resp_p;
    info$service  = "tls";
    info$art_ms   = art;
    info$detail   = sni;

    Log::write(ART::LOG, info);

    delete tls_hello_ts[c$uid];
    delete tls_hello_sni[c$uid];
}
