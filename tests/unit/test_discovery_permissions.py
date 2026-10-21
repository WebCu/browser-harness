import json
import subprocess
import urllib.error
from pathlib import Path

import pytest

from browser_harness import admin, daemon


@pytest.fixture
def discovery(monkeypatch, tmp_path):
    monkeypatch.delenv("BU_CDP_WS", raising=False)
    monkeypatch.delenv("BU_CDP_URL", raising=False)
    monkeypatch.setattr(daemon, "PROFILES", [tmp_path])
    return tmp_path


def deny_port_file(monkeypatch, profile):
    original = Path.read_text

    def read(path, *args, **kwargs):
        if path == profile / "DevToolsActivePort":
            raise PermissionError("synthetic access denial")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)


def http_error(code):
    def urlopen(url, **kwargs):
        raise urllib.error.HTTPError(url, code, "synthetic response", {}, None)

    return urlopen


@pytest.mark.parametrize("explicit_http", [False, True])
def test_discovery_reports_profile_access_denial(monkeypatch, discovery, explicit_http):
    deny_port_file(monkeypatch, discovery)
    monkeypatch.setattr(daemon.urllib.request, "urlopen", http_error(404))
    if explicit_http:
        monkeypatch.setenv("BU_CDP_URL", "http://127.0.0.1:9222")
    with pytest.raises(RuntimeError, match="profile-access-denied") as error:
        daemon.get_ws_url()
    assert "BU_CDP_WS" in str(error.value)
    assert "chrome-not-running" not in str(error.value)


def test_explicit_websocket_skips_protected_profile_files(monkeypatch, discovery):
    deny_port_file(monkeypatch, discovery)
    monkeypatch.setenv("BU_CDP_WS", "ws://127.0.0.1:9222/devtools/browser/synthetic")
    assert daemon.get_ws_url() == "ws://127.0.0.1:9222/devtools/browser/synthetic"


@pytest.mark.parametrize("explicit_http", [False, True])
def test_discovery_uses_readable_profile_after_inaccessible_one(monkeypatch, discovery, explicit_http):
    deny_port_file(monkeypatch, discovery)
    readable = discovery / "readable"
    readable.mkdir()
    (readable / "DevToolsActivePort").write_text("9222\n/devtools/browser/synthetic\n")
    monkeypatch.setattr(daemon, "PROFILES", [discovery, readable])
    monkeypatch.setattr(daemon.urllib.request, "urlopen", http_error(404))
    if explicit_http:
        monkeypatch.setenv("BU_CDP_URL", "http://127.0.0.1:9222")
    assert daemon.get_ws_url() == "ws://127.0.0.1:9222/devtools/browser/synthetic"


def test_access_denial_does_not_block_working_http_discovery(monkeypatch, discovery):
    deny_port_file(monkeypatch, discovery)
    endpoint = "ws://127.0.0.1:9222/devtools/browser/synthetic"

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return json.dumps({"webSocketDebuggerUrl": endpoint}).encode()

    monkeypatch.setattr(daemon.urllib.request, "urlopen", lambda *args, **kwargs: Response())
    assert daemon.get_ws_url() == endpoint


def test_missing_browser_still_has_distinct_diagnostic(monkeypatch, discovery):
    monkeypatch.setattr(daemon, "supported_browser_running", lambda: False)
    with pytest.raises(RuntimeError, match="chrome-not-running"):
        daemon.get_ws_url()


def test_disabled_debugging_still_has_distinct_diagnostic(monkeypatch, discovery):
    monkeypatch.setattr(daemon, "supported_browser_running", lambda: True)
    monkeypatch.setattr(daemon, "remote_debugging_toggle_profiles", lambda: [])
    monkeypatch.setattr(daemon, "remote_debugging_user_enabled", lambda: False)
    monkeypatch.setattr(daemon, "NO_TOGGLE_GRACE", -1)
    monkeypatch.setattr(daemon.urllib.request, "urlopen", http_error(404))
    with pytest.raises(RuntimeError, match="remote debugging is turned off"):
        daemon.get_ws_url()


def test_http_approval_failure_is_not_profile_access_denial(monkeypatch, discovery):
    monkeypatch.setenv("BU_CDP_URL", "http://127.0.0.1:9222")
    monkeypatch.setattr(daemon.urllib.request, "urlopen", http_error(403))
    with pytest.raises(RuntimeError, match="permission-blocked"):
        daemon.get_ws_url()


def test_process_inspection_failure_is_unknown_not_browser_absent(monkeypatch):
    def blocked(*args, **kwargs):
        raise PermissionError("synthetic process inspection denial")

    monkeypatch.setattr(subprocess, "check_output", blocked)
    assert admin._chrome_running() is None


def test_doctor_reports_unknown_process_state_without_start_browser_advice(monkeypatch, capsys):
    monkeypatch.setattr(admin, "_chrome_running", lambda: None)
    monkeypatch.setattr(admin, "_version", lambda: "0.1.13")
    monkeypatch.setattr(admin, "_install_mode", lambda: "pypi")
    monkeypatch.setattr(admin, "_latest_release_tag", lambda: None)
    monkeypatch.setattr(admin, "daemon_alive", lambda: False)
    monkeypatch.setattr(admin, "browser_connections", lambda: [])
    monkeypatch.setattr(admin.auth, "auth_status", lambda: {"status": "missing"})
    monkeypatch.setattr(admin, "_doctor_probe_chrome_binary_for_snap", lambda: (None, None))
    assert admin.run_doctor() == 1
    output = capsys.readouterr().out
    assert "[UNKNOWN] chrome running" in output
    assert "start chrome/edge" not in output


def test_json_doctor_keeps_health_boolean_when_browser_state_is_unknown(monkeypatch, capsys):
    monkeypatch.setattr(admin, "_chrome_running", lambda: None)
    monkeypatch.setattr(admin, "daemon_browser_ready", lambda name: False)
    monkeypatch.setattr(admin, "daemon_alive", lambda name: True)
    assert admin.run_doctor_json() == 1
    report = json.loads(capsys.readouterr().out)
    assert report["chrome_running"] is None
    assert report["healthy"] is False
