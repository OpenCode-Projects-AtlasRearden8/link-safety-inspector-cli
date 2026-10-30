from __future__ import annotations

import pytest

from link_safety_inspector.analyzer import analyze, _levenshtein, _registrable


def codes(report):
    return {h.code for h in report.hesitations}


class TestHelpers:
    def test_levenshtein_basic(self):
        assert _levenshtein("paypal", "paypal") == 0
        assert _levenshtein("paypa1", "paypal") == 1
        assert _levenshtein("goqgle", "google") == 1
        assert _levenshtein("apple", "microsoft") >= 3

    def test_registrable_handles_co_uk(self):
        assert _registrable("mail.google.co.uk") == "google.co.uk"
        assert _registrable("news.bbc.co.uk") == "bbc.co.uk"
        assert _registrable("a.b.example.com") == "example.com"


class TestLegitUrls:
    @pytest.mark.parametrize(
        "url",
        [
            "https://github.com/dylanasdale",
            "https://www.google.com/",
            "https://mail.google.com/mail/u/0",
            "https://docs.microsoft.com/en-us/",
            "https://store.apple.com/us",
            "https://www.paypal.com/signin",
            "https://outlook.office.com/mail",
            "https://dylanasdale.github.io/",
            "https://example.com/news/june-update",
            "https://calendar.google.com/calendar/u/0/r/eventedit",
        ],
    )
    def test_legit_urls_score_low(self, url):
        report = analyze(url)
        assert report.score <= 2, report.as_dict()
        assert report.verdict.startswith("Probably fine")

    def test_legit_report_shape(self):
        report = analyze("https://github.com/dylanasdale")
        assert report.hesitations == []
        assert report.plain


class TestLookalikeDomains:
    @pytest.mark.parametrize(
        "url",
        [
            "https://paypa1.com/account",
            "https://paypal-secure.com/login",
            "https://www-goqgle.com/search",
            "https://nota-real-run.paypal.com.evil.io/",
            "https://secure-paypal.account-verify.xyz/step1",
            "https://ww-wellsfargo.com/secure-login",
        ],
    )
    def test_lookalike_flags(self, url):
        report = analyze(url)
        assert any(
            h.code.startswith("lookalike") for h in report.hesitations
        ), report.as_dict()
        assert report.score >= 4


class TestPunycodeAndUnicode:
    def test_punycode_flagged(self):
        report = analyze("https://xn--pple-43d.com/login")
        assert "punycode" in codes(report)
        assert "credential_bait" in codes(report)

    def test_cyrillic_homoglyphs(self):
        spoofed = "https://аpple.com/login"
        report = analyze(spoofed)
        assert {"mixed_script"} & codes(report)
        assert {"lookalike_wrong_ending", "lookalike_dashname", "lookalike_typo"} & codes(report)

    def test_plain_ascii_not_flagged(self):
        assert not ({"punycode", "mixed_script"} & codes(analyze("https://apple.com")))


class TestRedirectsAndShorteners:
    def test_wrapped_url_flagged(self):
        report = analyze("https://click.tracker.com/u?url=https://example.com/news")
        assert "redirect_layer" in codes(report)

    def test_shortener_flagged(self):
        report = analyze("https://bit.ly/3xYzAbC")
        assert "shortener" in codes(report)

    def test_shorten_chain(self):
        report = analyze("https://bit.ly/3xY?url=https://tinyurl.com/zzzz")
        assert "shorten_chain" in codes(report)
        assert "redirect_layer" in codes(report)

    def test_no_false_nested_for_plain_query(self):
        report = analyze("https://example.com/search?q=github+oauth")
        assert "redirect_layer" not in codes(report)


class TestHttpAndInfra:
    def test_http_page_flagged(self):
        report = analyze("http://newsletter.example.com/october")
        assert "http_only" in codes(report)

    def test_https_not_flagged(self):
        assert "http_only" not in codes(analyze("https://newsletter.example.com/october"))

    def test_bare_ip_flagged(self):
        report = analyze("http://198.51.100.7/account")
        assert "bare_ip" in codes(report)

    def test_odd_port_flagged(self):
        report = analyze("https://shop.example.net:8443/cart")
        assert "odd_port" in codes(report)

    def test_userinfo_trick_flagged(self):
        report = analyze("https://accounts.google.com@evil-example.net/signin")
        assert "userinfo_trick" in codes(report)
        assert report.score >= 6


class TestCredentialBait:
    def test_login_like_path_unpackaged(self):
        report = analyze("https://verify-account-help.xyz/login/step2")
        assert "credential_bait" in codes(report)

    def test_trusted_signin_not_baited(self):
        report = analyze("https://www.paypal.com/signin")
        assert report.score <= 2


class TestDownloadsAndMalformed:
    def test_executable_flagged(self):
        report = analyze("http://delivery-update.example.ru/parcel.exe")
        assert "executable_download" in codes(report)
        assert report.score >= 6

    def test_malformed_flagged(self):
        report = analyze("not a link at all")
        assert report.verdict in ("Danger - do not click", "Be careful")
        assert any("parse" in h.message.lower() for h in report.hesitations)

    def test_scheme_assumed_https(self):
        report = analyze("github.com/dylanasdale")
        assert report.final_url.startswith("https://")
        assert report.score == 0


class TestVerdictBands:
    def test_band_boundaries(self):
        clean = analyze("https://github.com/")
        assert clean.score == 0
        assert clean.verdict == "Probably fine"

        mild = analyze("http://simple-blog.example.com/post/1")
        assert 0 < mild.score <= 2
        assert mild.verdict == "Probably fine, stay sharp"

        careful = analyze("http://account-verify-check.info/confirm-otp")
        assert 3 <= careful.score <= 4
        assert careful.verdict == "Be careful"

        danger = analyze("https://paypa1-secure.com/verify/login?next=http://bit.ly/2as")
        assert danger.score >= 5
        assert danger.verdict == "Danger - do not click"
