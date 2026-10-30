from __future__ import annotations

import re
import textwrap

_URL_RE = re.compile(
    r"""(?:https?://|www\.)[^\s<>"'`\[\]{}\\^\x00-\x20]+""",
    re.IGNORECASE,
)

_ALPHA_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_PLAIN_DOMAIN_RE = re.compile(
    r"^(?:[\w-]+\.)+[a-z]{2,}$",
    re.IGNORECASE,
)

_BATCH_DOMAIN_RE = re.compile(
    r"^(?:[\w-]+\.)+[a-z]{2,}(?:/\S*)?$",
    re.IGNORECASE,
)


def _dedupe_key(url: str) -> str:
    return url.lower()


def _trim(token: str) -> str:
    token = token.rstrip(".,;:!?'\"\u201d\u2019)]}>")
    if token.count("(") > token.count(")"):
        token = token[token.rfind("(") + 1 :]
    if token.count("<") > token.count(">"):
        token = token[: token.rfind("<")]
    return token.rstrip(".,;:!?'\"")


def _clean(token: str) -> str:
    token = _trim(token)
    if token.lower().startswith("www."):
        token = "https://" + token
    elif not _ALPHA_SCHEME_RE.match(token):
        token = "https://" + token
    return token


def extract_urls(text: str) -> list[str]:
    token = textwrap.dedent(text)
    found: list[str] = []
    seen: set[str] = set()
    for match in _URL_RE.finditer(token):
        cleaned = _clean(match.group(0))
        key = _dedupe_key(cleaned)
        if key not in seen:
            seen.add(key)
            found.append(cleaned)
    return found


def batch_urls(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _URL_RE.search(stripped)
        if match:
            candidate = _clean(_trim(match.group(0)))
        elif _BATCH_DOMAIN_RE.match(stripped):
            candidate = _clean(stripped)
        else:
            continue
        if candidate not in seen:
            seen.add(candidate)
            found.append(candidate)
    return found
