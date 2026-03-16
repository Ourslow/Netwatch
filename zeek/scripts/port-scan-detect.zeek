# NetWatch — Détection de scan de ports
# Seuil : >50 ports distincts en 60s depuis une même IP source

module PortScan;

export {
    redef enum Notice::Type += { Port_Scan_Detected };
    const scan_threshold: count = 50 &redef;
    const scan_window: interval = 60sec &redef;
}

global port_table: table[addr] of set[port] &create_expire=scan_window;

event new_connection(c: connection)
{
    local src = c$id$orig_h;
    local dst_port = c$id$resp_p;

    if (src !in port_table)
        port_table[src] = set();

    add port_table[src][dst_port];

    if (|port_table[src]| > scan_threshold)
    {
        NOTICE([$note=Port_Scan_Detected,
                $conn=c,
                $msg=fmt("Port scan depuis %s : %d ports en %s",
                         src, |port_table[src]|, scan_window),
                $identifier=cat(src)]);
    }
}
