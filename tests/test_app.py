from oneconfig.app import selfcheck


def test_the_apps_selfcheck_passes_from_source(capsys):
    """The same check the built app runs (OneConfig --selfcheck); here it guards the check itself."""
    assert selfcheck() == 0, capsys.readouterr().out
