# NetWatch — VoIP Quality Monitor : MOS E-model ITU-T G.107 (T_026)
#
# Calcule le MOS score depuis les métriques RTP/UDP et corrèle avec SIP call_id.
#
# NOTE: policy/protocols/rtp n'existe PAS dans Zeek 6.x (base ni policy).
# Les métriques sont approximées depuis conn.log UDP dans les plages de ports RTP :
#   - 16384-32767  (plage RTP RFC 3550 / RFC 4961 standard)
#   - 10000-20000  (plage alternative Cisco/Avaya/SIP endpoints)
#
# Formule E-model G.107 simplifiée :
#   Id  = 0.024 * latency_ms + 0.11 * max(0, latency_ms - 177.3)
#   Ie  = 30 * packet_loss_pct / 100
#   R   = clamp(93.2 - Id - Ie, 0, 100)
#   MOS = clamp(1 + 0.035*R + R*(R-60)*(100-R)*7e-6, 1.0, 5.0)
#
# Output : voip.log

module VOIP_MOS;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:               time    &log;
        uid:              string  &log;
        src_ip:           addr    &log;
        dst_ip:           addr    &log;
        duration_s:       double  &log;
        jitter_ms:        double  &log;
        packet_loss_pct:  double  &log;
        latency_ms:       double  &log;
        mos_score:        double  &log;
        mos_level:        string  &log;
        call_id:          string  &log &optional;
    };
}

# Table de corrélation SIP : (src_ip, dst_ip) → call_id
# Expire après 5 min d'inactivité (durée max d'un appel typique en tracking)
global sip_call_ids: table[addr, addr] of string &read_expire=5min;

# ─────────────────────────────────────────────────────────────────────────────
# Fonctions
# ─────────────────────────────────────────────────────────────────────────────

# calc_mos : E-model G.107 simplifié
# Entrée : latency_ms (one-way), packet_loss_pct (0-100)
# Sortie : MOS score [1.0, 5.0]
function calc_mos(latency_ms: double, packet_loss_pct: double): double
{
    local delay_factor: double = latency_ms - 177.3;
    if (delay_factor < 0.0) delay_factor = 0.0;

    local Id: double = 0.024 * latency_ms + 0.11 * delay_factor;
    local Ie: double = 30.0 * packet_loss_pct / 100.0;
    local R:  double = 93.2 - Id - Ie;

    if (R < 0.0)   R = 0.0;
    if (R > 100.0) R = 100.0;

    local mos: double = 1.0 + 0.035 * R + R * (R - 60.0) * (100.0 - R) * 7e-6;

    if (mos < 1.0) mos = 1.0;
    if (mos > 5.0) mos = 5.0;

    return mos;
}

# mos_label : convertit le score MOS en niveau lisible (ITU-T P.800.1)
function mos_label(mos: double): string
{
    if (mos >= 4.3) return "excellent";
    if (mos >= 4.0) return "good";
    if (mos >= 3.6) return "fair";
    if (mos >= 3.1) return "poor";
    return "bad";
}

# ─────────────────────────────────────────────────────────────────────────────
# Initialisation
# ─────────────────────────────────────────────────────────────────────────────

event zeek_init()
{
    Log::create_stream(VOIP_MOS::LOG, [$columns=Info, $path="voip"]);
    Reporter::info("VOIP_MOS: stream 'voip.log' initialisé (E-model G.107, approximation conn.log UDP)");
}

# ─────────────────────────────────────────────────────────────────────────────
# Corrélation SIP — capture call_id pour les connexions UDP RTP associées
# Nécessite : @load policy/protocols/sip (chargé dans local.zeek)
# ─────────────────────────────────────────────────────────────────────────────

event sip_request(c: connection, method: string, original_URI: string, version: string)
{
    # Stocker le call_id SIP indexé par paire d'adresses IP
    # Permet la corrélation avec les flux RTP UDP ultérieurs
    if (c?$sip && c$sip?$call_id && c$sip$call_id != "")
    {
        sip_call_ids[c$id$orig_h, c$id$resp_h] = c$sip$call_id;
        sip_call_ids[c$id$resp_h, c$id$orig_h] = c$sip$call_id;
    }
}

event sip_reply(c: connection, version: string, code: count, reason: string)
{
    if (c?$sip && c$sip?$call_id && c$sip$call_id != "")
    {
        sip_call_ids[c$id$orig_h, c$id$resp_h] = c$sip$call_id;
        sip_call_ids[c$id$resp_h, c$id$orig_h] = c$sip$call_id;
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Analyse des flux UDP dans les plages de ports RTP
# ─────────────────────────────────────────────────────────────────────────────

event connection_state_remove(c: connection)
{
    # Filtrer UDP uniquement
    if (get_port_transport_proto(c$id$orig_p) != udp)
        return;

    # Vérifier que le port destination ou source est dans une plage RTP
    # En Zeek, les ports incluent le protocole de transport → comparaison directe avec /udp
    local dp = c$id$resp_p;
    local sp = c$id$orig_p;

    local in_rtp: bool = (dp >= 16384/udp && dp <= 32767/udp)
                      || (dp >= 10000/udp && dp <= 20000/udp)
                      || (sp >= 16384/udp && sp <= 32767/udp)
                      || (sp >= 10000/udp && sp <= 20000/udp);

    if (!in_rtp)
        return;

    # Ignorer les connexions trop courtes (< 1s) — probablement pas de la VoIP
    if (!c?$duration)
        return;

    local dur_s: double = interval_to_double(c$duration);
    if (dur_s < 1.0)
        return;

    # ── Estimation packet loss ──────────────────────────────────────────────
    # G.711 / G.729 : ~50 paquets/s par direction (20 ms par paquet)
    # Paquets attendus = durée_s × 50 pps
    local pps_expected: double    = 50.0;
    local expected_pkts: double   = dur_s * pps_expected;
    local actual_pkts: double     = c$orig$num_pkts + 0.0;

    local loss_pct: double = 0.0;
    if (expected_pkts > 0.0 && actual_pkts < expected_pkts)
        loss_pct = (expected_pkts - actual_pkts) / expected_pkts * 100.0;
    if (loss_pct > 100.0) loss_pct = 100.0;
    if (loss_pct < 0.0)   loss_pct = 0.0;

    # ── Estimation latence (one-way) ────────────────────────────────────────
    # conn.log expose c$conn$rtt pour les connexions TCP uniquement.
    # Pour UDP : défaut 20 ms (latence LAN typique).
    # Si RTT disponible (rare pour UDP), RTT/2 = one-way delay.
    local lat_ms: double = 20.0;
    if (c$conn?$rtt)
        lat_ms = interval_to_double(c$conn$rtt) / 2.0 * 1000.0;

    # ── Estimation jitter ───────────────────────────────────────────────────
    # Sans analyzer RTP natif, Zeek ne expose pas les timestamps inter-paquets UDP.
    # Approximation : jitter_ms = 2 ms (baseline LAN) + 0.5 ms par % de perte
    # (cohérent avec le modèle E : les pertes corrèlent avec la variation de délai).
    local jitter_ms: double = 2.0 + loss_pct * 0.5;
    if (jitter_ms > 150.0) jitter_ms = 150.0;

    # ── Calcul MOS ──────────────────────────────────────────────────────────
    local mos:   double = calc_mos(lat_ms, loss_pct);
    local level: string = mos_label(mos);

    # ── Construction de l'enregistrement ────────────────────────────────────
    local info: Info;
    info$ts              = c$start_time;
    info$uid             = c$uid;
    info$src_ip          = c$id$orig_h;
    info$dst_ip          = c$id$resp_h;
    info$duration_s      = dur_s;
    info$jitter_ms       = jitter_ms;
    info$packet_loss_pct = loss_pct;
    info$latency_ms      = lat_ms;
    info$mos_score       = mos;
    info$mos_level       = level;

    # Corrélation SIP call_id (si disponible)
    if ([c$id$orig_h, c$id$resp_h] in sip_call_ids)
        info$call_id = sip_call_ids[c$id$orig_h, c$id$resp_h];
    else if ([c$id$resp_h, c$id$orig_h] in sip_call_ids)
        info$call_id = sip_call_ids[c$id$resp_h, c$id$orig_h];

    Log::write(VOIP_MOS::LOG, info);
}
