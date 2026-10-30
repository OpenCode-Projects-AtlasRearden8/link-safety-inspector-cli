from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse

from .domains import (
    ABUSED_TLDS,
    CREDENTIAL_WORDS,
    CONFUSABLES,
    EXECUTABLE_EXTENSIONS,
    REDIRECT_PARAMS,
    SHORTENERS,
    TRUSTED_BRANDS,
    TWO_PART_SUFFIXES,
)

MAX_URL_LENGTH = 140

_I18N_HOST_RE = re.compile(r"[^\x00-\x7f]")
_PUNYCODE_RE = re.compile(r"(?:^|\.)xn--")

_SHORTENER_LABELS = frozenset(SHORTENERS)


@dataclass
class Hesitation:
    code: str
    weight: int
    message: str

    def as_dict(self) -> dict:
        return {"code": self.code, "weight": self.weight, "message": self.message}


@dataclass
class Report:
    url: str
    final_url: str
    score: int
    verdict: str
    plain: str
    hesitations: list[Hesitation] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "checked": self.final_url,
            "score": self.score,
            "verdict": self.verdict,
            "plain": self.plain,
            "hesitations": [h.as_dict() for h in self.hesitations],
        }


def _levenshtein(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def _registrable(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3:
        two_part = ".".join(labels[-2:])
        if two_part in TWO_PART_SUFFIXES:
            return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _core(host: str) -> str:
    reg_labels = _registrable(host).split(".")
    suffix_labels = 1
    if len(reg_labels) >= 3 and ".".join(reg_labels[-2:]) in TWO_PART_SUFFIXES:
        suffix_labels = 2
    return ".".join(reg_labels[:-suffix_labels])


def _normalize_label(label: str) -> str:
    if label.startswith("xn--"):
        try:
            label = label.encode("ascii").decode("idna") or label
        except (UnicodeError, ValueError):
            return label.lower()
    return "".join(CONFUSABLES.get(ch, ch) for ch in label.lower())


def _normalize_host(host: str) -> str:
    return ".".join(_normalize_label(label) for label in host.split("."))


def _safe_redirect_values(query: str) -> list[str]:
    values = []
    for key, vals in parse_qs(query, keep_blank_values=True).items():
        if key.lower() in REDIRECT_PARAMS:
            values.extend(v for v in vals if v and re.match(r"^https?://\S+", v, re.I))
    return values


def _brand_lookalike_message(core: str, brand_core: str, brand: str) -> str:
    if brand_core in core and core != brand_core:
        return (
            f'The name "{brand_core}" is buried inside "{core}" — the real site '
            f'would just be "{brand}". Lookalike domain.'
        )
    return (
        f'"{core}" is one or two letters away from the well-known site "{brand}". '
        "Lookalike domains are a classic phishing trick."
    )


def _subdomain_labels(host: str) -> list[str]:
    reg_labels = len(_registrable(host).split("."))
    labels = host.split(".")
    return [label for label in labels[: len(labels) - reg_labels] if label]


def _strip_www_prefix(core: str) -> str:
    return re.sub(r"^www[-.]", "", core)


def _match_trusted_brand(host: str, normalized: str) -> Hesitation | None:
    candidates = [host, normalized]
    for base in (host, normalized):
        stripped = _strip_www_prefix(base)
        if stripped != base:
            candidates.append(stripped)
    for brand in TRUSTED_BRANDS:
        reg = _registrable(brand)
        brand_core = _core(brand)
        strong = len(brand_core) >= 4
        for candidate in candidates:
            cand_reg = _registrable(candidate)
            cand_core = _core(candidate)
            if cand_reg == reg:
                break
            if cand_core == brand_core:
                return Hesitation(
                    "lookalike_wrong_ending",
                    5,
                    _brand_lookalike_message(cand_core, brand_core, brand)
                    + f' This one ends in "{cand_reg}" instead of the real "{reg}".',
                )
            if strong and re.search(
                rf"(?:^|-){re.escape(brand_core)}(?:-|$)", cand_core
            ):
                return Hesitation(
                    "lookalike_dashname",
                    5,
                    _brand_lookalike_message(cand_core, brand_core, brand),
                )
            if strong and _levenshtein(cand_core, brand_core) == 1:
                return Hesitation(
                    "lookalike_typo",
                    5,
                    _brand_lookalike_message(cand_core, brand_core, brand),
                )
            if strong and _levenshtein(cand_core, brand_core) == 2 and len(cand_core) >= 8:
                return Hesitation(
                    "lookalike_close",
                    3,
                    _brand_lookalike_message(cand_core, brand_core, brand),
                )
            embedded = re.search(
                rf"(?:^|\.|-){re.escape(reg)}(?:\.|-|$)", candidate
            )
            if embedded and not candidate.endswith(reg):
                return Hesitation(
                    "lookalike_embedded",
                    5,
                    f'The real domain "{reg}" is tucked inside this address '
                    f'("{candidate}"), but the link does not actually end there — '
                    "it goes somewhere else entirely.",
                )
            if strong and cand_reg not in TRUSTED_BRANDS:
                for label in _subdomain_labels(candidate):
                    if label == brand_core:
                        return Hesitation(
                            "lookalike_subdomain",
                            4,
                            f'The name "{brand_core}" sits in front of the real '
                            f'site "{cand_reg}" — a subdomain of that site, not a '
                            f'page run by {brand.split(".")[0].title()}.',
                        )
                    if (
                        len(label) >= len(brand_core)
                        and _levenshtein(label, brand_core) == 1
                    ):
                        return Hesitation(
                            "lookalike_subdomain_typo",
                            4,
                            f'The front part "{label}" is one letter away from '
                            f'"{brand_core}", a classic lookalike subdomain trick.',
                        )
                    if re.search(rf"(?:^|-){re.escape(brand_core)}(?:-|$)", label):
                        return Hesitation(
                            "lookalike_subdomain_dashname",
                            4,
                            f'The name "{brand_core}" is buried in the front of '
                            f'"{cand_reg}" — the real {brand.split(".")[0].title()} '
                            "does not hand out addresses like that.",
                        )
    return None


def _credential_shape(path: str, query: str, host: str = "") -> bool:
    reg = _registrable(host)
    if reg and reg in TRUSTED_BRANDS:
        return False
    blob = f"{path} {query} ".lower()
    for word in CREDENTIAL_WORDS:
        if re.search(rf"(?:^|[\s/_.\-?=&@]){re.escape(word)}(?:$|[\s/_.\-?=&@])", blob):
            return True
    for word in CREDENTIAL_WORDS:
        for label in host.split("."):
            if re.search(rf"(?:^|-){re.escape(word)}(?:$|-)", label):
                return True
    return False


def _punycode_decoded(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return host


def analyze(url: str, depth: int = 0) -> Report:
    raw = url.strip().strip("<>").rstrip('.,;:!?"\'')
    if not re.match(r"^(?:https?://|www\.)", raw, re.I):
        raw = "https://" + raw

    hes: list[Hesitation] = []
    malformed = Report(
        url=url.strip(),
        final_url=raw,
        score=5,
        verdict="Danger - do not click",
        plain="This link is malformed. It is best not to click it at all.",
        hesitations=[],
    )
    try:
        parts = urlparse(raw)
        host = (parts.hostname or "").rstrip(".")
    except ValueError:
        parts = None
        host = ""

    if parts is None or not host or " " in host or "." not in host:
        malformed.hesitations = [
            Hesitation(
                "unparseable",
                5,
                "This does not parse as a normal web address, which itself is a "
                "warning sign. Scam links are often mangled on purpose.",
            )
        ]
        return malformed

    normalized = _normalize_host(host)

    if parts.scheme == "http":
        hes.append(
            Hesitation(
                "http_only",
                2,
                "This link goes to an unencrypted page (http, not https). Anything "
                "entered there could be read by anyone on the path.",
            )
        )

    if "@" in parts.netloc:
        hes.append(
            Hesitation(
                "userinfo_trick",
                4,
                "The address hides the real destination after an @ sign. Browsers "
                "ignore everything before the @, a well-known illusion trick.",
            )
        )

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        hes.append(
            Hesitation(
                "bare_ip",
                4,
                "This link uses a bare number address instead of a name "
                f'("{host}"). Legitimate companies almost never do this.',
            )
        )

    if _PUNYCODE_RE.search(host):
        hes.append(
            Hesitation(
                "punycode",
                4,
                "This link uses hidden lookalike characters (punycode). It may render "
                f'as "{_punycode_decoded(host)}" while being registered differently — '
                "a classic imitate-a-real-site trick.",
            )
        )

    if _I18N_HOST_RE.search(host):
        hes.append(
            Hesitation(
                "mixed_script",
                3,
                "The address contains non-standard characters that can mimic normal "
                "letters, so what you see may not be the site you expect.",
            )
        )

    lookalike = _match_trusted_brand(host, normalized)
    if lookalike:
        hes.append(lookalike)

    if _registrable(host) in _SHORTENER_LABELS:
        hes.append(
            Hesitation(
                "shortener",
                2,
                "This is a link shortener, so the real destination stays hidden "
                "until you click. Treat shortened links extra carefully.",
            )
        )

    nesting: list[Report] = []
    redirect_values = _safe_redirect_values(parts.query)
    if redirect_values:
        hes.append(
            Hesitation(
                "redirect_layer",
                2 if len(redirect_values) == 1 else 3,
                "This link wraps at least one other address inside itself (a "
                "redirect or tracking layer), so the site named in front is not "
                "necessarily where you land. Hiding a destination this way is a "
                "favorite scam trick.",
            )
        )
        shortener_chain = any(
            _registrable((urlparse(v).hostname or "")) in _SHORTENER_LABELS
            for v in redirect_values
        )
        if shortener_chain:
            hes.append(
                Hesitation(
                    "shorten_chain",
                    3,
                    "The hidden destination is itself a link shortener — a "
                    "shortener wrapped inside a redirect. That layering exists to "
                    "hide where a click finally ends up.",
                )
            )
        if depth < 2:
            for nested_url in redirect_values[:2]:
                nesting.append(analyze(nested_url, depth=depth + 1))
        for inner in nesting:
            hes.append(
                Hesitation(
                    "nested_destination",
                    1,
                    f'The hidden destination "{inner.final_url}" rates '
                    f'"{inner.verdict}" on its own checks.',
                )
            )

    tld = host.split(".")[-1].lower()
    if tld in ABUSED_TLDS:
        hes.append(
            Hesitation(
                "abused_tld",
                2,
                "This address ends in an unusual top-level domain (.{tld}) that is "
                "cheap to register and shows up in a lot of scam links. Not proof "
                "of anything by itself, just another reason to pause.".format(tld=tld),
            )
        )

    if _credential_shape(parts.path, parts.query, host):
        hes.append(
            Hesitation(
                "credential_bait",
                2,
                "The page is dressed up like a login, verification, or "
                "account-alert page. Fake sign-in pages are the most common "
                "password-stealing trick there is.",
            )
        )

    if len(host.split(".")) > 4:
        hes.append(
            Hesitation(
                "subdomain_pileup",
                1,
                "This address stacks lots of names in front of the real site, a "
                "common way to make a scam link look trustworthy.",
            )
        )

    if len(raw) > MAX_URL_LENGTH:
        hes.append(
            Hesitation(
                "long_url",
                1,
                "The link is unusually long, often a sign that details are being "
                "stuffed in to hide where it really goes.",
            )
        )

    if parts.port is not None and parts.port not in (80, 443):
        hes.append(
            Hesitation(
                "odd_port",
                1,
                "The link points to an unusual port number instead of a normal "
                "website port, which ordinary sites basically never do.",
            )
        )

    for ext in EXECUTABLE_EXTENSIONS:
        if parts.path.lower().endswith(ext):
            hes.append(
                Hesitation(
                    "executable_download",
                    4,
                    "This link points directly at a program file, not a web page. "
                    "Clicking it may install software on your computer.",
                )
            )
            break

    score = min(sum(h.weight for h in hes), 10)
    verdict, plain = _verdict(score)
    return Report(
        url=url.strip(),
        final_url=raw,
        score=score,
        verdict=verdict,
        plain=plain,
        hesitations=hes,
    )


def _verdict(score: int) -> tuple[str, str]:
    if score <= 0:
        return (
            "Probably fine",
            "No red flags from the offline checks. Still, only click links you "
            "actually expected to receive.",
        )
    if score <= 2:
        return (
            "Probably fine, stay sharp",
            "Nothing major, but pause for a second and make sure you expected this "
            "link from this sender.",
        )
    if score <= 4:
        return (
            "Be careful",
            "This link has real warning signs. If it claims to be your bank, a "
            "delivery, or a big brand, go to that company's site by typing the "
            "address yourself instead of clicking.",
        )
    return (
        "Danger - do not click",
        "This link shows strong scam signals. Do not click it. If it arrived by "
        "email or text, report it as phishing and delete it.",
    )
