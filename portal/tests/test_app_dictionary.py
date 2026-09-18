from netwatch.experience import app_dictionary as ad


def test_exact_and_subdomain_match():
    assert ad._match("office.com") == ("Microsoft 365", "Productivité")
    assert ad._match("outlook.office.com") == ("Microsoft 365", "Productivité")


def test_no_partial_suffix_match():
    assert ad._match("notoffice.com") == (None, None)
    assert ad._match("office.com.evil.net") == (None, None)


def test_case_and_trailing_dot():
    assert ad._match("Outlook.Office.COM.") == ("Microsoft 365", "Productivité")


def test_empty_or_unknown():
    assert ad._match("") == (None, None)
    assert ad._match(None) == (None, None)
    assert ad._match("example.invalid") == (None, None)


def test_catalog_is_well_formed():
    names = [a["name"] for a in ad._CATALOG]
    assert len(names) == len(set(names)), "noms d'applications dupliqués"
    for app in ad._CATALOG:
        assert app["name"] and app["category"] and app["domains"], app
        for d in app["domains"]:
            assert d == d.lower().strip() and not d.startswith(".") and not d.endswith("."), d
