#!/usr/bin/env python3
"""
NetWatch — analyse TCP par conversation à partir de PCAP (façon Allegro Network Multimeter).

Chaque fichier PCAP est traité comme un "point d'écoute" distinct (nom = nom de
fichier) — architecture pensée pour accueillir plus tard plusieurs points
d'écoute réels sur différents flux de transmission, pas juste des fichiers
PCAP rejoués.

Pour chaque conversation TCP (tcp.stream), calcule : temps de handshake
(client/serveur, avec notation qualitative), temps de réponse (RTT ACK
min/moy/max), retransmissions, paquets hors-ordre, ACKs dupliqués, taille de
fenêtre annoncée (min/max), octets en vol estimés, taux d'usage de fenêtre,
MSS, compteurs SYN/SYN-ACK/FIN/RST, DSCP, MTU observé.

Ces calculs sont une approximation "best effort" reproduisant la logique
d'outils comme Wireshark/Allegro — pas une resynchronisation d'horloge
matérielle, donc les métriques de latence "two-way"/"one-way" ne sont pas
calculables depuis un seul point de capture (comme dans Allegro lui-même,
qui les affiche "n/a" en mono-point).

Nécessite tshark (paquet `tshark`, apt install tshark).
"""
from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import io
import json
import logging
import os
import subprocess
import sys
from collections import defaultdict

logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)

FIELDS = [
    "frame.number", "frame.time_epoch", "frame.len",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "tcp.stream",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset",
    "tcp.analysis.retransmission", "tcp.analysis.duplicate_ack",
    "tcp.analysis.out_of_order", "tcp.analysis.zero_window",
    "tcp.analysis.ack_rtt",
    "tcp.window_size", "tcp.options.mss_val", "tcp.options.wscale.shift",
    "tcp.len", "tcp.seq", "tcp.ack",
    "ip.dsfield.dscp", "ipv6.tclass.dscp",
    "vlan.id",
]

# RFC 4594 / IANA — noms usuels des points de code DSCP (Differentiated Services).
_DSCP_NAMES = {
    0: "CS0 (Best Effort)", 8: "CS1 (Scavenger)", 10: "AF11", 12: "AF12", 14: "AF13",
    16: "CS2 (OAM)", 18: "AF21", 20: "AF22", 22: "AF23",
    24: "CS3 (Signaling)", 26: "AF31", 28: "AF32", 30: "AF33",
    32: "CS4 (Realtime)", 34: "AF41", 36: "AF42", 38: "AF43",
    40: "CS5 (Broadcast Video)", 46: "EF (Voice/Video)",
    48: "CS6 (Network Control)", 56: "CS7 (Reserved)",
}


def _dscp_name(value):
    if value is None:
        return None
    return _DSCP_NAMES.get(value, f"DSCP {value}")

# Nombre max de paquets lus par tshark avant coupure (garde-fou pour éviter
# qu'un pcap pathologique ne bloque indéfiniment ; ajustable via --max-packets).
# Volontairement haut : un plafond bas tronquerait la lecture chronologique
# et biaiserait l'analyse vers les conversations les plus anciennes.
DEFAULT_MAX_PACKETS = 3_000_000

# Nombre de tranches temporelles pour le graphe de chronologie (zoom) par conversation.
TIMELINE_BUCKETS = 60


def _handshake_rating(ms):
    """Notation qualitative 1-5, esprit Allegro (EXCELLENT..POOR)."""
    if ms is None:
        return None, None
    if ms < 10:
        return "EXCELLENT", 5
    if ms < 30:
        return "GOOD", 4
    if ms < 100:
        return "NORMAL", 3
    if ms < 300:
        return "DEGRADED", 2
    return "POOR", 1


def run_tshark(pcap_path, max_packets):
    fields_args = []
    for f in FIELDS:
        fields_args += ["-e", f]
    cmd = [
        "tshark", "-r", pcap_path, "-Y", "tcp",
        "-T", "fields", "-E", "separator=\t", "-E", "header=y", "-E", "occurrence=f",
        "-c", str(max_packets),
    ] + fields_args
    log.info("tshark: %s (max %d paquets)", os.path.basename(pcap_path), max_packets)
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"tshark a échoué sur {pcap_path}: {result.stderr[:400]}")
    return result.stdout


def _f(row, key, cast=float):
    v = row.get(key, "")
    if not v:
        return None
    v = v.split(",")[0]  # certains champs peuvent être répétés sur une ligne
    try:
        return cast(v)
    except ValueError:
        return None


def analyze_pcap(pcap_path, max_packets, top_n):
    raw = run_tshark(pcap_path, max_packets)
    reader = csv.DictReader(io.StringIO(raw), delimiter="\t")

    streams = defaultdict(lambda: {
        "packets": [],
    })

    for row in reader:
        stream_id = row.get("tcp.stream", "")
        if stream_id == "":
            continue
        streams[stream_id]["packets"].append(row)

    conversations = []
    for stream_id, s in streams.items():
        pkts = s["packets"]
        if not pkts:
            continue
        pkts.sort(key=lambda r: _f(r, "frame.time_epoch") or 0)

        src0 = pkts[0].get("ip.src") or pkts[0].get("ipv6.src") or "?"
        dst0 = pkts[0].get("ip.dst") or pkts[0].get("ipv6.dst") or "?"
        sport0, dport0 = pkts[0].get("tcp.srcport", ""), pkts[0].get("tcp.dstport", "")

        # Client = émetteur du 1er SYN pur (sans ACK) si trouvé, sinon 1er paquet observé.
        client_ip, client_port, server_ip, server_port = src0, sport0, dst0, dport0
        for r in pkts:
            if r.get("tcp.flags.syn") == "1" and r.get("tcp.flags.ack") == "0":
                client_ip = r.get("ip.src") or r.get("ipv6.src") or client_ip
                client_port = r.get("tcp.srcport", client_port)
                server_ip = r.get("ip.dst") or r.get("ipv6.dst") or server_ip
                server_port = r.get("tcp.dstport", server_port)
                break

        def is_c2s(r):
            return (r.get("ip.src") or r.get("ipv6.src")) == client_ip and r.get("tcp.srcport") == client_port

        agg = {
            "frames": {"c2s": 0, "s2c": 0}, "bytes": {"c2s": 0, "s2c": 0},
            "mtu": {"c2s": 0, "s2c": 0},
            "retrans": {"c2s": 0, "s2c": 0}, "retrans_bytes": {"c2s": 0, "s2c": 0},
            "ooo": {"c2s": 0, "s2c": 0}, "dupack": {"c2s": 0, "s2c": 0},
            "zero_win": {"c2s": 0, "s2c": 0},
            "syn": {"c2s": 0, "s2c": 0}, "synack": {"c2s": 0, "s2c": 0},
            "fin": {"c2s": 0, "s2c": 0}, "rst": {"c2s": 0, "s2c": 0},
            "win": {"c2s": [], "s2c": []},
            "mss": {"c2s": None, "s2c": None},
            "dscp": {"c2s": None, "s2c": None},
            "vlan": {"c2s": None, "s2c": None},
            "wscale": {"c2s": None, "s2c": None},
            "ack_rtts": [],
        }
        # Suivi octets-en-vol : max(seq+len) émis - max(ack) reçu du pair, par direction.
        max_seq_sent = {"c2s": 0, "s2c": 0}
        max_ack_recv = {"c2s": 0, "s2c": 0}
        max_inflight = {"c2s": 0, "s2c": 0}

        syn_time = synack_time = final_ack_time = None
        t_first = _f(pkts[0], "frame.time_epoch")
        t_last = _f(pkts[-1], "frame.time_epoch")

        # Chronologie — bucketise la conversation en N tranches égales pour le
        # graphe de sélection temporelle (zoom) côté portail. Calculé dans la
        # même passe, pas de coût supplémentaire de lecture du pcap.
        n_buckets = min(TIMELINE_BUCKETS, max(1, len(pkts)))
        span = (t_last - t_first) if (t_first is not None and t_last is not None and t_last > t_first) else 1.0
        bucket_w = span / n_buckets
        timeline = [
            {"t": round(t_first + i * bucket_w - t_first, 3) if t_first else 0,
             "bytes_c2s": 0, "bytes_s2c": 0, "retrans_c2s": 0, "retrans_s2c": 0}
            for i in range(n_buckets)
        ]

        def _bucket_idx(ts):
            if t_first is None or bucket_w <= 0:
                return 0
            idx = int((ts - t_first) / bucket_w)
            return max(0, min(n_buckets - 1, idx))

        for r in pkts:
            d = "c2s" if is_c2s(r) else "s2c"
            other = "s2c" if d == "c2s" else "c2s"
            flen = _f(r, "frame.len", int) or 0
            tlen = _f(r, "tcp.len", int) or 0
            agg["frames"][d] += 1
            agg["bytes"][d] += flen
            agg["mtu"][d] = max(agg["mtu"][d], flen)

            r_time = _f(r, "frame.time_epoch")
            bi = _bucket_idx(r_time) if r_time is not None else 0
            timeline[bi]["bytes_" + d] += flen

            if r.get("tcp.analysis.retransmission") == "1":
                agg["retrans"][d] += 1
                agg["retrans_bytes"][d] += tlen
                timeline[bi]["retrans_" + d] += 1
            if r.get("tcp.analysis.out_of_order") == "1":
                agg["ooo"][d] += 1
            if r.get("tcp.analysis.duplicate_ack") == "1":
                agg["dupack"][d] += 1
            if r.get("tcp.analysis.zero_window") == "1":
                agg["zero_win"][d] += 1

            is_syn, is_ack = r.get("tcp.flags.syn") == "1", r.get("tcp.flags.ack") == "1"
            if is_syn and not is_ack:
                agg["syn"][d] += 1
                if syn_time is None:
                    syn_time = _f(r, "frame.time_epoch")
            elif is_syn and is_ack:
                agg["synack"][d] += 1
                if synack_time is None:
                    synack_time = _f(r, "frame.time_epoch")
            elif is_ack and synack_time is not None and final_ack_time is None and d == "c2s" \
                    and (_f(r, "frame.time_epoch") or 0) > synack_time:
                final_ack_time = _f(r, "frame.time_epoch")
            if r.get("tcp.flags.fin") == "1":
                agg["fin"][d] += 1
            if r.get("tcp.flags.reset") == "1":
                agg["rst"][d] += 1

            win = _f(r, "tcp.window_size", int)
            if win is not None:
                agg["win"][d].append(win)
            mss = _f(r, "tcp.options.mss_val", int)
            if mss is not None and agg["mss"][d] is None:
                agg["mss"][d] = mss
            wscale = _f(r, "tcp.options.wscale.shift", int)
            if wscale is not None and agg["wscale"][d] is None:
                agg["wscale"][d] = wscale
            dscp = _f(r, "ip.dsfield.dscp", int)
            if dscp is None:
                dscp = _f(r, "ipv6.tclass.dscp", int)
            if dscp is not None and agg["dscp"][d] is None:
                agg["dscp"][d] = dscp
            vlan_id = _f(r, "vlan.id", int)
            if vlan_id is not None and agg["vlan"][d] is None:
                agg["vlan"][d] = vlan_id
            rtt = _f(r, "tcp.analysis.ack_rtt")
            if rtt is not None:
                agg["ack_rtts"].append(rtt * 1000.0)

            seq, ack, tlen = _f(r, "tcp.seq", int), _f(r, "tcp.ack", int), tlen
            if seq is not None:
                max_seq_sent[d] = max(max_seq_sent[d], seq + tlen)
            if ack is not None:
                max_ack_recv[other] = max(max_ack_recv[other], ack)
            inflight = max_seq_sent[d] - max_ack_recv[d]
            if inflight > max_inflight[d]:
                max_inflight[d] = inflight

        duration_s = (t_last - t_first) if (t_first and t_last) else 0
        total_bytes = agg["bytes"]["c2s"] + agg["bytes"]["s2c"]

        hs_server_ms = (synack_time - syn_time) * 1000 if (syn_time and synack_time) else None
        hs_client_ms = (final_ack_time - synack_time) * 1000 if (synack_time and final_ack_time) else None
        hs_server_label, hs_server_score = _handshake_rating(hs_server_ms)
        hs_client_label, hs_client_score = _handshake_rating(hs_client_ms)

        def pct(n, total):
            return round(100.0 * n / total, 2) if total else 0.0

        # Identifiant stable (5-tuple + fenêtre de 60s) — pas utilisé pour dédupliquer
        # aujourd'hui (un seul point d'écoute réel), mais prépare un futur croisement
        # entre plusieurs points sans avoir à retoucher le schéma de données.
        conv_key = f"{client_ip}:{client_port}-{server_ip}:{server_port}-{int((t_first or 0) // 60)}"
        conversation_id = hashlib.sha1(conv_key.encode()).hexdigest()[:12]

        conv = {
            "stream_id": stream_id,
            "conversation_id": conversation_id,
            "client_ip": client_ip, "client_port": client_port,
            "server_ip": server_ip, "server_port": server_port,
            "protocol": "TCP",
            "start_time_epoch": t_first,
            "last_seen_epoch": t_last,
            "duration_s": round(duration_s, 3),
            "frames": agg["frames"], "bytes": agg["bytes"],
            "total_bytes": total_bytes,
            "pps": {d: round(agg["frames"][d] / duration_s, 1) if duration_s else 0 for d in ("c2s", "s2c")},
            "bps": {d: round(agg["bytes"][d] * 8 / duration_s, 0) if duration_s else 0 for d in ("c2s", "s2c")},
            "mtu": agg["mtu"],
            "handshake_ms": {"server": hs_server_ms and round(hs_server_ms, 3),
                              "client": hs_client_ms and round(hs_client_ms, 3)},
            "handshake_rating": {"server": {"label": hs_server_label, "score": hs_server_score},
                                  "client": {"label": hs_client_label, "score": hs_client_score}},
            "response_time_ms": {
                "max": round(max(agg["ack_rtts"]), 3) if agg["ack_rtts"] else None,
                "avg": round(sum(agg["ack_rtts"]) / len(agg["ack_rtts"]), 3) if agg["ack_rtts"] else None,
            },
            "retransmissions": agg["retrans"],
            "retransmissions_pct": {d: pct(agg["retrans_bytes"][d], agg["bytes"][d]) for d in ("c2s", "s2c")},
            "out_of_order": agg["ooo"],
            "duplicate_acks": agg["dupack"],
            "zero_window": agg["zero_win"],
            "syn": agg["syn"], "synack": agg["synack"], "fin": agg["fin"], "rst": agg["rst"],
            "mss": agg["mss"],
            "window_scale": agg["wscale"],
            "window_size": {
                "max": {d: (max(agg["win"][d]) if agg["win"][d] else None) for d in ("c2s", "s2c")},
                "min": {d: (min(agg["win"][d]) if agg["win"][d] else None) for d in ("c2s", "s2c")},
            },
            "bytes_in_flight_max": max_inflight,
            "window_usage_pct": {
                d: (round(100.0 * max_inflight[d] / max(agg["win"][d]), 1)
                    if agg["win"][d] and max(agg["win"][d]) else 0.0)
                for d in ("c2s", "s2c")
            },
            "dscp": agg["dscp"],
            "dscp_name": {d: _dscp_name(agg["dscp"][d]) for d in ("c2s", "s2c")},
            "vlan_id": agg["vlan"],
            "timeline": timeline,
        }
        conversations.append(conv)

    conversations.sort(key=lambda c: c["total_bytes"], reverse=True)
    return conversations[:top_n]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyse TCP par conversation depuis un ou plusieurs PCAP (façon Allegro Network Multimeter)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 pcap-tcp-analysis.py --pcap-dir pcap/ --output scripts/security/pcap-analysis.json
  python3 pcap-tcp-analysis.py --pcap pcap/capture.pcapng --top 20
""",
    )
    parser.add_argument("--pcap-dir", default="pcap", help="Dossier contenant les PCAP à analyser (défaut: pcap/)")
    parser.add_argument("--pcap", default="", help="Analyser un seul fichier PCAP (ignore --pcap-dir)")
    parser.add_argument("--output", "-o", default="scripts/security/pcap-analysis.json", help="Fichier JSON de sortie")
    parser.add_argument("--top", type=int, default=50, help="Nombre max de conversations conservées par PCAP (défaut: 50)")
    parser.add_argument("--max-packets", type=int, default=DEFAULT_MAX_PACKETS,
                         help=f"Paquets max lus par tshark par fichier (défaut: {DEFAULT_MAX_PACKETS})")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    if args.pcap:
        pcap_files = [args.pcap]
    else:
        pcap_files = sorted(
            glob.glob(os.path.join(args.pcap_dir, "*.pcap"))
            + glob.glob(os.path.join(args.pcap_dir, "*.pcapng"))
        )

    if not pcap_files:
        log.warning("Aucun fichier PCAP trouvé.")
        result = {"listening_points": [], "generated_at": None}
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        return 0

    listening_points = []
    for pcap_path in pcap_files:
        name = os.path.splitext(os.path.basename(pcap_path))[0]
        try:
            conversations = analyze_pcap(pcap_path, args.max_packets, args.top)
        except Exception as exc:
            log.error("Echec analyse %s : %s", pcap_path, exc)
            listening_points.append({"name": name, "source": pcap_path, "error": str(exc), "conversations": []})
            continue
        listening_points.append({
            "name": name,
            "source": pcap_path,
            "conversation_count": len(conversations),
            "conversations": conversations,
        })
        log.info("%s : %d conversations (top %d conservées)", name, len(conversations), args.top)

    import time
    result = {"listening_points": listening_points, "generated_at": time.time()}
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    log.info("Ecrit : %s", args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
