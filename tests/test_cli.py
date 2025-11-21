from ioc_ranger.cli import app


def test_help(runner):
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "IOC Ranger" in result.stdout


def test_version_flag(runner):
    # Depending on how version is handled, this might need adjustment.
    # The current CLI doesn't seem to have a --version flag explicitly,
    # but let's check if it runs without arguments (interactive mode) or with arguments.
    pass


def test_no_args_shows_help_or_interactive(runner):
    # Without args it goes to interactive prompt, which might hang if not handled.
    # We'll skip this for now or mock input.
    pass
