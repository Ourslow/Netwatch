# NetWatch — TCP Performance : RTT, retransmissions, zero-window
# Loggue les métriques de performance TCP à la fermeture de chaque connexion

module TCP_PERF;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:                 time    &log;
        uid:                string  &log;
        id:                 conn_id &log;
        proto:              transport_proto &log;
        rtt_orig_ms:        double  &log &optional;
        rtt_resp_ms:        double  &log &optional;
        retransmits_orig:   count   &log;
        retransmits_resp:   count   &log;
        zero_windows_orig:  bool    &log;
        zero_windows_resp:  bool    &log;
        syn_ack_ms:         double  &log &optional;
        history:            string  &log &optional;
        conn_state:         string  &log &optional;
    };
}

event zeek_init()
{
    Log::create_stream(TCP_PERF::LOG, [$columns=Info, $path="tcp_perf"]);
}

event connection_state_remove(c: connection)
{
    # Ne traiter que TCP
    if (get_port_transport_proto(c$id$orig_p) != tcp)
        return;

    local info: Info;
    info$ts                = c$start_time;
    info$uid               = c$uid;
    info$id                = c$id;
    info$proto             = tcp;
    info$retransmits_orig  = 0;
    info$retransmits_resp  = 0;
    info$zero_windows_orig = F;
    info$zero_windows_resp = F;

    # RTT — champ built-in Zeek (interval), converti en ms
    if (c$conn?$rtt)
    {
        # rtt est le RTT estimé côté originator
        info$rtt_orig_ms = interval_to_double(c$conn$rtt) * 1000.0;
    }

    # Retransmissions
    if (c$conn?$orig_retrans_pkts)
        info$retransmits_orig = c$conn$orig_retrans_pkts;
    if (c$conn?$resp_retrans_pkts)
        info$retransmits_resp = c$conn$resp_retrans_pkts;

    # Zero-window : présence de 'w' (orig) ou 'W' (resp) dans history
    # Zeek history : 'w' = sender (orig) closed window, 'W' = responder
    if (c$conn?$history)
    {
        local h = c$conn$history;
        info$history = h;
        if (/w/ in h) info$zero_windows_orig = T;
        if (/W/ in h) info$zero_windows_resp = T;

        # SYN-ACK delta : approximation — durée jusqu'au premier data ou établissement
        # 'S' = SYN, 'A' = ACK → si history contient 'SA' ou 'Ss', on estime via duration
        # On utilise c$duration comme borne haute si la connexion est très courte (< 1s)
        # Valeur indicative seulement
        if (/[SA]/ in h && c$conn?$duration)
        {
            local dur_ms = interval_to_double(c$conn$duration) * 1000.0;
            if (dur_ms < 1000.0)
                info$syn_ack_ms = dur_ms;
        }
    }

    if (c$conn?$conn_state)
        info$conn_state = c$conn$conn_state;

    Log::write(TCP_PERF::LOG, info);
}
