# NetWatch — Détection de mouvement latéral
# Basé sur le skill : detecting-lateral-movement-with-zeek
# Surveille : SMB (445), DCE/RPC (135), WinRM (5985/5986), RDP (3389), NetBIOS (139)
# Déclenche une Notice si une IP interne accède à plusieurs hôtes internes via ces ports

module LateralMovement;

export {
    redef enum Notice::Type += {
        Lateral_SMB_Access,
        Lateral_RDP_Access,
        Lateral_DCE_RPC_Access,
        Lateral_WinRM_Access,
        Lateral_Spread_Detected
    };

    # Nombre d'hôtes distincts atteints avant d'alerter
    const smb_spread_threshold:   count = 3 &redef;
    const rdp_spread_threshold:   count = 2 &redef;
    const winrm_spread_threshold: count = 2 &redef;
    const dce_spread_threshold:   count = 3 &redef;

    # Fenêtre temporelle d'observation
    const lateral_window: interval = 5min &redef;
}

# Tables : src → set de destinations, expire automatiquement
global smb_targets:   table[addr] of set[addr] &create_expire=lateral_window;
global rdp_targets:   table[addr] of set[addr] &create_expire=lateral_window;
global winrm_targets: table[addr] of set[addr] &create_expire=lateral_window;
global dce_targets:   table[addr] of set[addr] &create_expire=lateral_window;

function track_lateral(c: connection, src: addr, dst: addr,
                        targets: table[addr] of set[addr],
                        threshold: count,
                        proto_name: string,
                        notice_type: Notice::Type)
{
    if (src !in targets)
        targets[src] = set();

    add targets[src][dst];

    if (|targets[src]| >= threshold)
    {
        NOTICE([$note=notice_type,
                $conn=c,
                $msg=fmt("Mouvement latéral %s : %s -> %d hôtes distincts en %s",
                         proto_name, src, |targets[src]|, lateral_window),
                $identifier=cat(src, "-", proto_name)]);
    }
}

event new_connection(c: connection)
{
    local src  = c$id$orig_h;
    local dst  = c$id$resp_h;
    local dport = c$id$resp_p;

    # Filtrer : seulement trafic interne -> interne
    if (!Site::is_local_addr(src) || !Site::is_local_addr(dst))
        return;

    # Exclure src == dst (loopback)
    if (src == dst)
        return;

    if (dport == 445/tcp || dport == 139/tcp)
    {
        track_lateral(c, src, dst, smb_targets, smb_spread_threshold,
                      "SMB", Lateral_SMB_Access);
    }
    else if (dport == 3389/tcp)
    {
        track_lateral(c, src, dst, rdp_targets, rdp_spread_threshold,
                      "RDP", Lateral_RDP_Access);
    }
    else if (dport == 5985/tcp || dport == 5986/tcp)
    {
        track_lateral(c, src, dst, winrm_targets, winrm_spread_threshold,
                      "WinRM", Lateral_WinRM_Access);
    }
    else if (dport == 135/tcp)
    {
        track_lateral(c, src, dst, dce_targets, dce_spread_threshold,
                      "DCE/RPC", Lateral_DCE_RPC_Access);
    }
}
