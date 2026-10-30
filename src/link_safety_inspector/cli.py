from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from . import __version__
from .analyzer import Report, analyze
from .extract import batch_urls, extract_urls

DESCRIPTION = """Link Safety Inspector - pause before you click, offline.

Checks pasted links or saved email text files for suspicious patterns
(lookalike domains, punycode tricks, excess redirects, http-only pages,
shortener layers, fake login pages, program downloads) and prints a
plain-English verdict.

Everything runs on your own machine. No network fetches of page content,
nothing scored in the cloud.

Examples:
  %(prog)s https://paypal-secure.com/login
  %(prog)s saved-email.txt
  %(prog)s email newsletter.eml
  %(prog)s batch urls.txt --format summary
"""

_URLISH_RE = re.compile(r"^(?:https?|ftp)://|^www\.", re.I)


def _worst_verdict(reports: list[Report]) -> str | None:
    if not reports:
        return None
    top = max(reports, key=lambda r: r.score)
    return None if top.score <= 0 else top.verdict


def _print_link_report(report: Report, json_mode: bool) -> None:
    if json_mode:
        print(json.dumps(report.as_dict(), indent=2))
        return
    print(f"Link:  {report.final_url}")
    print(f"Verdict: {report.verdict} (score {report.score}/10)")
    print("Hesitations:")
    if report.hesitations:
        for h in sorted(report.hesitations, key=lambda x: -x.weight):
            print(f"  - {h.message}")
    else:
        print("  - none from the offline checks")
    print(f"In short: {report.plain}")


def _print_multi_report(reports: list[Report], json_mode: bool, source: str) -> None:
    worst = _worst_verdict(reports)
    if json_mode:
        print(
            json.dumps(
                {
                    "source": source,
                    "links_checked": len(reports),
                    "worst_verdict": worst,
                    "reports": [r.as_dict() for r in reports],
                },
                indent=2,
            )
        )
        return
    print(f"Checked {len(reports)} link(s) in {source}.\n")
    for i, report in enumerate(reports, 1):
        print(f"{i}. {report.final_url}")
        print(f"   Verdict: {report.verdict} (score {report.score}/10)")
        if report.hesitations:
            for h in sorted(report.hesitations, key=lambda x: -x.weight):
                print(f"   - {h.message}")
        else:
            print("   - No hesitations from the offline checks.")
        print()
    if worst:
        print(f"Overall for this file: {worst}")
        print(
            "Remember: no real bank, the IRS, or a big brand warns you in an "
            "email and then asks you to log in through a link."
        )
    else:
        print(
            "Overall for this file: no link problems found, but stay sharp if "
            "the wording around any link urges you to act fast."
        )


def _print_batch_report(reports: list[Report], json_mode: bool, summary_only: bool) -> None:
    counts: dict[str, int] = {}
    for r in reports:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    worst = max(reports, key=lambda r: r.score) if reports else None

    if json_mode:
        print(
            json.dumps(
                {
                    "links_checked": len(reports),
                    "verdict_counts": counts,
                    "worst": worst.as_dict() if worst else None,
                    "reports": [r.as_dict() for r in reports],
                },
                indent=2,
            )
        )
        return

    if summary_only:
        print(f"Links checked: {len(reports)}")
        for verdict, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            print(f"  {verdict}: {n}")
        if worst and worst.score > 0:
            print(
                f"Worst link: {worst.final_url} -> {worst.verdict} "
                f"(score {worst.score}/10)"
            )
            for h in sorted(worst.hesitations, key=lambda x: -x.weight):
                print(f"  - {h.message}")
        else:
            print("Batch summary: nothing scored worse than a heads-up.")
        return

    print(f"BATCH REPORT - {len(reports)} link(s) checked\n")
    for i, report in enumerate(reports, 1):
        print(f"{i}. {report.final_url}")
        print(f"   Verdict: {report.verdict} (score {report.score}/10)")
        if report.hesitations:
            for h in sorted(report.hesitations, key=lambda x: -x.weight):
                print(f"   - {h.message}")
        else:
            print("   - No hesitations from the offline checks.")
    print("\nBatch summary:")
    for verdict, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {verdict}: {n}")


def _read_targets(paths: list[str]) -> str:
    chunks = []
    for path in paths:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(path)
        chunks.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="link-safety-inspector",
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "--json", action="store_true", help="machine-readable JSON output"
    )
    parser.add_argument(
        "--format",
        choices=["full", "summary"],
        default="full",
        help="batch report style (default: full)",
    )
    parser.add_argument(
        "action",
        nargs="?",
        help="optional keyword: 'email' or 'batch'",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="a link (in quotes), or one or more saved text files",
    )
    args = parser.parse_args(argv)

    targets = args.targets
    if args.action not in (None, "email", "batch"):
        targets = [args.action, *targets]
        args.action = None

    if not targets:
        parser.print_help()
        return 2

    mode = args.action
    if mode is None:
        if len(targets) == 1 and _URLISH_RE.match(targets[0]):
            mode = "links"
        elif _URLISH_RE.match(targets[0]):
            mode = "links"
        elif all(Path(t).exists() for t in targets):
            mode = "email"
        else:
            mode = "links"

    try:
        if mode in ("email", "batch"):
            text = _read_targets(targets)
    except FileNotFoundError as exc:
        print(f"File not found: {exc.args[0]}", file=sys.stderr)
        return 2

    if mode == "email":
        reports = [analyze(u) for u in extract_urls(text)]
        if not reports:
            print(
                "No links found in that file. Save the email as plain text "
                "(.txt or .eml) and try again."
            )
            return 1
        _print_multi_report(reports, args.json, ", ".join(targets))
        return 0

    if mode == "batch":
        urls = batch_urls(text)
        if not urls:
            print("No links found in that file.", file=sys.stderr)
            return 1
        reports = [analyze(u) for u in urls]
        _print_batch_report(reports, args.json, args.format == "summary")
        return 0

    if len(targets) == 1:
        _print_link_report(analyze(targets[0]), args.json)
        return 0
    for target in targets:
        _print_link_report(analyze(target), args.json)
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
