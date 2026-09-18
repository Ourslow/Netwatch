from netwatch import dashboard_layout as dl


def test_default_when_missing_or_corrupt(data_dir):
    assert dl.load() == dl.DEFAULT_LAYOUT
    (data_dir / "dashboard_layout.json").write_text("[")
    assert dl.load() == dl.DEFAULT_LAYOUT
    (data_dir / "dashboard_layout.json").write_text("[]")
    assert dl.load() == dl.DEFAULT_LAYOUT


def test_save_filters_unknown_widgets_and_sizes():
    clean = dl.save([
        {"id": "a", "type": "alert_stats", "size": "lg"},
        {"id": "b", "type": "unknown_widget", "size": "md"},
        {"id": "c", "type": "top_apps", "size": "xl"},
        {"type": "geo_top"},
        "not a dict",
    ])
    assert clean == [
        {"id": "a", "type": "alert_stats", "size": "lg"},
        {"id": "geo_top", "type": "geo_top", "size": "md"},
    ]
    assert dl.load() == clean


def test_reset_restores_default():
    dl.save([{"id": "a", "type": "alert_stats", "size": "sm"}])
    assert dl.reset() == dl.DEFAULT_LAYOUT
    assert dl.load() == dl.DEFAULT_LAYOUT
    assert dl.reset() == dl.DEFAULT_LAYOUT
