# NetWatch — Détection DNS par entropie (DGA)
# Seuil : entropie de Shannon > 3.5 sur le label principal du domaine

module DNSEntropy;

export {
    redef enum Notice::Type += { High_Entropy_DNS };
    const entropy_threshold: double = 3.5 &redef;
}

function shannon_entropy(s: string): double
{
    local freq: table[string] of count;
    local len = |s|;
    if (len == 0) return 0.0;

    for (i in s)
    {
        local c = s[i];
        if (c !in freq) freq[c] = 0;
        freq[c] += 1;
    }

    local entropy = 0.0;
    for (c in freq)
    {
        local p = freq[c] / (len * 1.0);
        entropy -= p * log2(p);
    }
    return entropy;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if (|query| == 0) return;

    local parts = split_string(query, /\./);
    if (|parts| == 0) return;

    local label = parts[0];
    local e = shannon_entropy(label);

    if (e > entropy_threshold)
    {
        NOTICE([$note=High_Entropy_DNS,
                $conn=c,
                $msg=fmt("Domaine suspect (entropie=%.2f) : %s", e, query),
                $identifier=query]);
    }
}
