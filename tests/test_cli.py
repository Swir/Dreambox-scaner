from dreambox_scanner import cli


def _state_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))


def test_cli_requires_authorization(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    assert cli.main(["192.168.1.10"]) == 2


def test_cli_rejects_public_target(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    assert cli.main(["8.8.8.8", "--authorized"]) == 2


def test_cli_validates_worker_limit(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    assert cli.main(["192.168.1.10", "--authorized", "--workers", "129"]) == 2


def test_cli_smoke_without_network(monkeypatch, tmp_path):
    _state_dir(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "scan_targets", lambda *args, **kwargs: [])
    assert cli.main(["192.168.1.10", "--authorized", "--max-hosts", "10"]) == 0
