from __future__ import annotations

import json
from pathlib import Path

import pytest

from link_safety_inspector import cli

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def run(capfd):
    def _run(*argv):
        code = cli.main(list(argv))
        out, err = capfd.readouterr()
        return code, out, err

    return _run


class TestSingleLink:
    def test_safe_link(self, run):
        code, out, _ = run("https://github.com/dylanasdale")
        assert code == 0
        assert "Probably fine" in out
        assert "Hesitations" in out

    def test_scam_link(self, run):
        code, out, _ = run("https://paypa1-secure.com/verify/login")
        assert code == 0
        assert "Danger - do not click" in out
        assert "Lookalike" in out or "lookalike" in out

    def test_json_output(self, run):
        code, out, _ = run("https://bit.ly/8xJzQw", "--json")
        assert code == 0
        payload = json.loads(out)
        assert payload["url"] == "https://bit.ly/8xJzQw"
        assert payload["score"] > 0
        assert payload["hesitations"]

    def test_no_network_request_flagged_values_only(self, run):
        code, out, _ = run("not a link at all")
        assert code == 0
        assert "malformed" in out.lower()


class TestEmailMode:
    def test_scam_fixture_full(self, run):
        code, out, _ = run("email", str(FIXTURES / "scam_email_1.txt"))
        assert code == 0
        assert "Checked 1 link(s)" in out
        assert "paypa1-secure.com" in out
        assert "Danger - do not click" in out
        assert "Overall for this file" in out

    def test_second_scam_fixture(self, run):
        code, out, _ = run(str(FIXTURES / "scam_email_2.txt"))
        assert code == 0
        assert "Danger - do not click" in out
        assert "program file" in out

    def test_legit_fixture(self, run):
        code, out, _ = run(str(FIXTURES / "legit_email.txt"))
        assert code == 0
        assert "Checked 2 link(s)" in out
        assert "No hesitations from the offline checks" in out

    def test_email_json(self, run):
        code, out, _ = run("email", str(FIXTURES / "scam_email_2.txt"), "--json")
        payload = json.loads(out)
        assert payload["links_checked"] == 2
        assert payload["worst_verdict"] == "Danger - do not click"
        codes = {h["code"] for r in payload["reports"] for h in r["hesitations"]}
        assert {"bare_ip", "executable_download", "shortener"} <= codes

    def test_no_links_message(self, run):
        empty = FIXTURES / "_no_links.txt"
        empty.write_text("no links in here at all\n")
        try:
            code, out, _ = run("email", str(empty))
            assert code == 1
            assert "No links found" in out
        finally:
            empty.unlink()

    def test_missing_file(self, run, tmp_path):
        code, _, err = run("email", str(tmp_path / "missing.txt"))
        assert code == 2
        assert "File not found" in err


class TestBatchMode:
    def test_fixture_full_report(self, run):
        code, out, _ = run("batch", str(FIXTURES / "batch_urls.txt"))
        assert code == 0
        assert "BATCH REPORT" in out
        assert "link(s) checked" in out
        assert "Batch summary:" in out
        assert out.count("Verdict:") == 5

    def test_fixture_summary(self, run):
        code, out, _ = run("batch", str(FIXTURES / "batch_urls.txt"), "--format", "summary")
        assert code == 0
        assert "Links checked: 5" in out
        assert "Worst link:" in out

    def test_fixture_json(self, run):
        code, out, _ = run("batch", str(FIXTURES / "batch_urls.txt"), "--json")
        payload = json.loads(out)
        assert payload["links_checked"] == 5
        assert payload["verdict_counts"]["Danger - do not click"] >= 2
        assert "verdict_counts" in payload

    def test_bare_shortener_line(self, run, tmp_path):
        batch = tmp_path / "b.txt"
        batch.write_text("t.co/abc123\n")
        code, out, _ = run("batch", str(batch))
        assert code == 0
        assert "shortener" in out


class TestVerdictFiltering:
    def test_flags_never_stay_silent(self, run):
        for fixture in ("scam_email_1.txt", "scam_email_2.txt"):
            code, out, _ = run(str(FIXTURES / fixture))
            assert "no problems" not in out
            assert code == 0
