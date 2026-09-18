from datetime import datetime, timedelta, timezone

from netwatch import incidents


def _alert(minutes_ago, severity=3, engine="suricata", src="10.0.0.1", dst="8.8.8.8",
           signature="ET TEST", tactic=None, tech=None, naive=False):
    ts = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    ts_str = ts.replace(tzinfo=None).isoformat() if naive else ts.isoformat()
    return {"timestamp": ts_str, "severity": severity, "engine": engine,
            "src_ip": src, "dest_ip": dst, "signature": signature,
            "mitre_tactic": tactic, "mitre_tech": tech}


def test_empty():
    assert incidents.build_incidents([]) == []


def test_alerts_within_window_are_one_incident():
    alerts = [_alert(0), _alert(3), _alert(6)]
    out = incidents.build_incidents(alerts, window_minutes=5)
    assert len(out) == 1
    assert out[0]["count"] == 3


def test_window_slides_from_last_alert_not_anchor():
    # 4 min gaps with a 5 min window: continuous burst → single incident even
    # though total span (12 min) exceeds the window.
    alerts = [_alert(0), _alert(4), _alert(8), _alert(12)]
    assert len(incidents.build_incidents(alerts, window_minutes=5)) == 1


def test_gap_larger_than_window_splits():
    alerts = [_alert(0), _alert(2), _alert(30), _alert(31)]
    out = incidents.build_incidents(alerts, window_minutes=5)
    assert [i["count"] for i in out] == [2, 2]
    assert out[0]["start"] > out[1]["start"]


def test_severity_counts_and_max():
    alerts = [_alert(0, severity=3), _alert(1, severity=1), _alert(2, severity=2)]
    inc = incidents.build_incidents(alerts)[0]
    assert (inc["critical"], inc["medium"], inc["low"]) == (1, 1, 1)
    assert inc["max_severity"] == 1


def test_engines_ips_and_top_signature():
    alerts = [_alert(0, engine="snort", src="10.0.0.1", dst="—", signature="A"),
              _alert(1, engine="suricata", src="10.0.0.2", dst="1.1.1.1", signature="A"),
              _alert(2, engine="suricata", src="10.0.0.1", dst="1.1.1.1", signature="B")]
    inc = incidents.build_incidents(alerts)[0]
    assert inc["engines"] == ["snort", "suricata"]
    assert inc["src_ips"] == ["10.0.0.1", "10.0.0.2"]
    assert inc["dest_ips"] == ["1.1.1.1"]
    assert inc["top_signature"] == "A"


def test_status_by_age():
    assert incidents.build_incidents([_alert(10)])[0]["status"] == "nouveau"
    assert incidents.build_incidents([_alert(120)])[0]["status"] == "en cours"
    assert incidents.build_incidents([_alert(60 * 30)])[0]["status"] == "clôturé"


def test_kill_chain_is_in_attack_order_and_counts_unmapped():
    alerts = [_alert(0, tactic="Exfiltration", tech="T1041"),
              _alert(1, tactic="Reconnaissance", tech="T1595"),
              _alert(2, tactic="Reconnaissance", tech="T1046"),
              _alert(3, engine="snort")]
    inc = incidents.build_incidents(alerts)[0]
    assert [s["tactic"] for s in inc["kill_chain"]] == ["Reconnaissance", "Exfiltration"]
    assert inc["kill_chain"][0]["count"] == 2
    assert inc["kill_chain"][0]["techniques"] == ["T1046", "T1595"]
    assert inc["kill_chain_unmapped"] == 1


def test_naive_and_invalid_timestamps():
    alerts = [_alert(0, naive=True), {"timestamp": "garbage"}, {"timestamp": None}]
    out = incidents.build_incidents(alerts)
    assert len(out) == 1 and out[0]["count"] == 1
