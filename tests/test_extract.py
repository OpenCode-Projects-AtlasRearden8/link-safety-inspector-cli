from __future__ import annotations

import pytest

from link_safety_inspector.extract import batch_urls, extract_urls


class TestExtractUrls:
    def test_plain_text_links(self):
        text = "Visit https://example.com/page or www.github.com/explore soon."
        assert extract_urls(text) == [
            "https://example.com/page",
            "https://www.github.com/explore",
        ]

    def test_angle_bracket_and_markdown(self):
        text = "See <https://docs.python.org/3/> and [guide](https://example.com/guide)."
        urls = extract_urls(text)
        assert "https://docs.python.org/3/" in urls
        assert "https://example.com/guide" in urls

    def test_query_and_fragment(self):
        text = "https://example.com/search?q=abc&safe=1#top"
        assert extract_urls(text) == [text]

    def test_trailing_punctuation_stripped(self):
        text = "Go to https://example.com/page, then read."
        assert extract_urls(text) == ["https://example.com/page"]

    def test_dedupes_case_insensitive(self):
        text = "https://EXAMPLE.com/a and https://example.com/a"
        assert len(extract_urls(text)) == 1

    def test_no_links(self):
        assert extract_urls("Just a friendly note with no links at all.") == []

    def test_email_fixture(self):
        text = (
            "Reply via:\nhttps://github.com/dylanasdale/link-safety-inspector/pr/14\n"
        )
        assert extract_urls(text) == [
            "https://github.com/dylanasdale/link-safety-inspector/pr/14"
        ]


class TestBatchUrls:
    def test_one_per_line(self):
        text = "https://a.example.com/1\nbit.ly/9k\n# comment\n\nb.example.net/page"
        assert batch_urls(text) == [
            "https://a.example.com/1",
            "https://bit.ly/9k",
            "https://b.example.net/page",
        ]

    def test_comments_and_blanks_skipped(self):
        assert batch_urls("# just comments\n\n") == []

    def test_two_per_line_takes_first(self):
        assert batch_urls("https://a.example.com/1 https://b.example.com/2") == [
            "https://a.example.com/1"
        ]

    def test_punctuation_numbers_ignored(self):
        assert batch_urls("1. 2. 3. nothing here") == []
