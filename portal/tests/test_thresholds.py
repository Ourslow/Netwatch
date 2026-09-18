import pytest

from netwatch import thresholds as th
from netwatch.experience import app_dictionary


def _scores(**by_app):
    """{app: {score, avg_rtt_ms, ...}} → format de get_app_health_scores."""
    return [{"name": name, **fields} for name, fields in by_app.items()]


@pytest.fixture
def scores(monkeypatch):
    holder = {"value": ([], None)}
    monkeypatch.setattr(app_dictionary, "get_app_health_scores",
                        lambda days=1, hostgroup=None: holder["value"])
    return holder


@pytest.fixture
def notifications(monkeypatch):
    sent = []
    monkeypatch.setattr(th, "_log_event", lambda kind, rule, app, current: sent.append(("log", kind, app)))
    monkeypatch.setattr(th, "_notify_webhook", lambda kind, rule, app, current: sent.append(("hook", kind, app)))
    return sent


class TestRules:
    def test_add_and_list(self):
        r = th.add_rule("avg_rtt_ms", "", ">", "150", "critical")
        assert r["scope"] == "global" and r["value"] == 150.0 and r["severity"] == "critical"
        assert r["enabled"] is True
        assert [x["id"] for x in th.list_rules()] == [r["id"]]

    def test_unknown_metric_or_operator(self):
        with pytest.raises(ValueError):
            th.add_rule("nope", "global", ">", 1, "warning")
        with pytest.raises(ValueError):
            th.add_rule("avg_rtt_ms", "global", "=", 1, "warning")
        with pytest.raises(ValueError):
            th.add_rule("avg_rtt_ms", "global", ">", "abc", "warning")

    def test_bad_severity_falls_back_to_warning(self):
        assert th.add_rule("conns", "global", "<", 1, "urgent")["severity"] == "warning"

    def test_toggle_and_delete(self):
        r = th.add_rule("conns", "global", "<", 1, "warning")
        th.toggle_rule(r["id"], False)
        assert th.list_rules()[0]["enabled"] is False
        th.toggle_rule("missing", True)
        th.delete_rule(r["id"])
        th.delete_rule("missing")
        assert th.list_rules() == []


class TestEvaluate:
    def test_no_rules_short_circuits(self, scores):
        assert th.evaluate() == ([], None)

    def test_es_error_propagates(self, scores):
        th.add_rule("avg_rtt_ms", "global", ">", 100, "warning")
        scores["value"] = ([], "Elasticsearch non joignable")
        assert th.evaluate() == ([], "Elasticsearch non joignable")

    def test_global_rule_checks_every_app(self, scores):
        th.add_rule("avg_rtt_ms", "global", ">", 100, "warning")
        scores["value"] = (_scores(M365={"avg_rtt_ms": 250}, Slack={"avg_rtt_ms": 20}), None)
        breaches, err = th.evaluate()
        assert err is None
        assert [b["app"] for b in breaches] == ["M365"]
        assert breaches[0]["current"] == 250

    def test_scoped_rule_and_health_score_field_mapping(self, scores):
        th.add_rule("health_score", "Slack", "<", 70, "critical")
        scores["value"] = (_scores(M365={"score": 10}, Slack={"score": 55}), None)
        breaches, _ = th.evaluate()
        assert [(b["app"], b["current"]) for b in breaches] == [("Slack", 55)]

    def test_scope_without_data_and_missing_metric(self, scores):
        th.add_rule("avg_rtt_ms", "Absent", ">", 1, "warning")
        th.add_rule("zero_window_pct", "global", ">", 1, "warning")
        scores["value"] = (_scores(M365={"avg_rtt_ms": 999}), None)
        assert th.evaluate()[0] == []

    def test_disabled_rule_ignored(self, scores):
        r = th.add_rule("avg_rtt_ms", "global", ">", 1, "warning")
        th.toggle_rule(r["id"], False)
        scores["value"] = (_scores(M365={"avg_rtt_ms": 999}), None)
        assert th.evaluate()[0] == []


class TestCheckAndNotify:
    def test_notifies_only_on_transitions(self, scores, notifications):
        th.add_rule("avg_rtt_ms", "global", ">", 100, "warning")
        scores["value"] = (_scores(M365={"avg_rtt_ms": 250}), None)

        th.check_and_notify()
        assert notifications == [("log", "breach", "M365"), ("hook", "breach", "M365")]

        th.check_and_notify()   # état inchangé → silence
        assert len(notifications) == 2

        scores["value"] = (_scores(M365={"avg_rtt_ms": 20}), None)
        th.check_and_notify()
        assert notifications[2:] == [("log", "resolved", "M365"), ("hook", "resolved", "M365")]

        th.check_and_notify()
        assert len(notifications) == 4

    def test_es_error_leaves_state_untouched(self, scores, notifications):
        th.add_rule("avg_rtt_ms", "global", ">", 100, "warning")
        scores["value"] = (_scores(M365={"avg_rtt_ms": 250}), None)
        th.check_and_notify()
        scores["value"] = ([], "ES down")
        th.check_and_notify()
        assert [n for n in notifications if n[1] == "resolved"] == []

    def test_webhook_failure_is_swallowed(self, monkeypatch):
        import config
        monkeypatch.setattr(config, "THRESHOLD_WEBHOOK_URL", "http://127.0.0.1:9/hook")
        rule = {"id": "x", "metric": "avg_rtt_ms", "scope": "global", "operator": ">", "value": 1, "severity": "warning"}
        th._notify_webhook("breach", rule, "M365", 5)
