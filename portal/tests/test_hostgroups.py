from netwatch import hostgroups as hg


def _ip(s):
    import ipaddress
    return int(ipaddress.ip_address(s))


class TestParseHostToken:
    def test_single_ip(self):
        assert hg._parse_host_token("10.0.0.1") == [_ip("10.0.0.1"), _ip("10.0.0.1"), 4]

    def test_cidr(self):
        start, end, v = hg._parse_host_token("192.168.1.0/24")
        assert (start, end, v) == (_ip("192.168.1.0"), _ip("192.168.1.255"), 4)

    def test_cidr_non_strict(self):
        assert hg._parse_host_token("192.168.1.42/24")[0] == _ip("192.168.1.0")

    def test_range(self):
        assert hg._parse_host_token(" 10.0.0.10 - 10.0.0.20 ") == [_ip("10.0.0.10"), _ip("10.0.0.20"), 4]

    def test_inverted_range_rejected(self):
        assert hg._parse_host_token("10.0.0.50-10.0.0.10") is None

    def test_mixed_versions_rejected(self):
        assert hg._parse_host_token("10.0.0.1-::1") is None

    def test_ipv6(self):
        assert hg._parse_host_token("2001:db8::/64")[2] == 6

    def test_garbage(self):
        assert hg._parse_host_token("") is None
        assert hg._parse_host_token("not-an-ip") is None
        assert hg._parse_host_token("10.0.0.256") is None


NETSCOUT_CSV = """#Version,1.0
#Data Type,Hostgroups
Name,Description,Enabled,Bandwidth In,Bandwidth Out,Hosts,Member hostgroups,Tags
Siege,Site principal,TRUE,,,"10.0.0.0/24, 10.0.1.5",,prod
Agences,,FALSE,,,"172.16.0.1-172.16.0.50, garbage",,
Tout,Groupe parent,TRUE,,,,"Siege, Agences",
,ligne sans nom,TRUE,,,10.9.9.9,,
"""


class TestParseCsv:
    def test_parses_netscout_export_with_bom(self):
        groups = hg.parse_csv(b"\xef\xbb\xbf" + NETSCOUT_CSV.encode("utf-8"))
        assert set(groups) == {"Siege", "Agences", "Tout"}
        assert groups["Siege"]["description"] == "Site principal"
        assert groups["Siege"]["tags"] == "prod"
        assert len(groups["Siege"]["ranges"]) == 2

    def test_enabled_flag_and_invalid_tokens_skipped(self):
        groups = hg.parse_csv(NETSCOUT_CSV)
        assert groups["Agences"]["enabled"] is False
        assert len(groups["Agences"]["ranges"]) == 1

    def test_member_groups(self):
        groups = hg.parse_csv(NETSCOUT_CSV)
        assert groups["Tout"]["member_groups"] == ["Siege", "Agences"]
        assert groups["Tout"]["ranges"] == []

    def test_empty_input(self):
        assert hg.parse_csv("") == {}


class TestResolveAndMatch:
    def _groups(self):
        return hg.parse_csv(NETSCOUT_CSV)

    def test_resolve_recursive(self):
        ranges = hg.resolve_ranges("Tout", self._groups())
        assert len(ranges) == 3

    def test_resolve_cycle_does_not_recurse_forever(self):
        groups = {
            "A": {"ranges": [[1, 2, 4]], "member_groups": ["B"]},
            "B": {"ranges": [[3, 4, 4]], "member_groups": ["A"]},
        }
        assert hg.resolve_ranges("A", groups) == [[1, 2, 4], [3, 4, 4]]

    def test_resolve_unknown(self):
        assert hg.resolve_ranges("nope", self._groups()) == []

    def test_ip_in_ranges(self):
        ranges = hg.resolve_ranges("Siege", self._groups())
        assert hg.ip_in_ranges("10.0.0.200", ranges)
        assert hg.ip_in_ranges("10.0.1.5", ranges)
        assert not hg.ip_in_ranges("10.0.1.6", ranges)
        assert not hg.ip_in_ranges("—", ranges)
        assert not hg.ip_in_ranges("junk", ranges)

    def test_ipv6_does_not_match_ipv4_range(self):
        ranges = [[0, 2**32 - 1, 4]]
        assert not hg.ip_in_ranges("::1", ranges)

    def test_make_matcher(self):
        groups = self._groups()
        assert hg.make_matcher("", groups) is None
        assert hg.make_matcher("absent", groups) is None
        assert hg.make_matcher("Siege", groups)("10.0.0.1")


class TestStoreAndList:
    def test_save_load_roundtrip(self):
        hg.save(hg.parse_csv(NETSCOUT_CSV))
        assert set(hg.load()) == {"Siege", "Agences", "Tout"}

    def test_load_missing_or_corrupt(self, data_dir):
        assert hg.load() == {}
        (data_dir / "hostgroups.json").write_text("{not json")
        assert hg.load() == {}

    def test_list_groups_counts_real_hosts_and_sorts(self):
        hg.save(hg.parse_csv(NETSCOUT_CSV))
        out = hg.list_groups()
        assert [g["name"] for g in out] == ["Agences", "Siege", "Tout"]
        by_name = {g["name"]: g for g in out}
        assert by_name["Siege"]["host_count"] == 256 + 1
        assert by_name["Agences"]["host_count"] == 50
        assert by_name["Tout"]["host_count"] == 0

    def test_filter_items_by_group(self):
        hg.save(hg.parse_csv(NETSCOUT_CSV))
        items = [{"src_ip": "10.0.0.7", "dest_ip": "8.8.8.8"},
                 {"src_ip": "1.1.1.1", "dest_ip": "10.0.1.5"},
                 {"src_ip": "1.1.1.1", "dest_ip": "9.9.9.9"}]
        assert hg.filter_items_by_group(items, "", ["src_ip"]) == items
        assert len(hg.filter_items_by_group(items, "Siege", ["src_ip", "dest_ip"])) == 2
        assert hg.filter_items_by_group(items, "inconnu", ["src_ip"]) == []
