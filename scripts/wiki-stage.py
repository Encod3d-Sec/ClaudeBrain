#!/usr/bin/env python3
"""wiki-stage.py - scaffold a wiki-promotion candidate under the active engagement.

Stages GENERIC, reusable knowledge (a default cred, a reusable API request, or a
technique note) to a review queue the moment it is confirmed:

    targets/<eng>/wiki-candidates/<slug>.md   (status: pending)

The body must be the generic form only (no client host/IP/domain); the promote
gate (scripts/wiki-promote.py) runs check-leaks.sh before anything reaches wiki/.

    python3 scripts/wiki-stage.py --kind default-cred --slug acme-router-default \\
        --body '| AcmeRouter | any | admin | admin | vendor | web UI |'
    python3 scripts/wiki-stage.py --kind technique --slug jwt-null-sig \\
        --target-page techniques/web/jwt-attacks.md    # scaffold body, edit after

Kinds: default-cred | api-pattern | technique. default-cred/api-pattern default their
target page to the matching cheatsheet; technique requires --target-page.
"""
import argparse
import os
import re
import sys
from datetime import date

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "skills", "hooks"))
import _engagement  # noqa: E402

KIND_PAGE = {
    "default-cred": "cheatsheets/default-credentials.md",
    "api-pattern": "cheatsheets/api-request-findings.md",
}
SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SCAFFOLD = {
    "default-cred":
        "| <product> | <version> | <username> | <password> | observed | <generic notes; NO client host> |",
    "api-pattern":
        "| <product/tech> | <endpoint> | <method> | <request / payload> | <auth> | <reveals / impact> |",
    "technique":
        "## <Heading>\n\n<generic technique steps; no client host/IP/domain>\n",
}


def build(kind, slug, target_page, source_eng, body, on_date):
    fm = (
        "---\n"
        "target_page: %s\n"
        "kind: %s\n"
        "slug: %s\n"
        "source_eng: %s\n"
        "date: %s\n"
        "status: pending\n"
        "---\n\n"
    ) % (target_page, kind, slug, source_eng, on_date)
    inner = body if body else SCAFFOLD[kind]
    return fm + inner.rstrip() + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Stage a wiki-promotion candidate.")
    ap.add_argument("--kind", required=True, choices=["default-cred", "api-pattern", "technique"])
    ap.add_argument("--slug", required=True)
    ap.add_argument("--target-page", default="")
    ap.add_argument("--body", default="")
    ap.add_argument("--eng", default="")
    ap.add_argument("--date", default="")
    args = ap.parse_args(argv)

    if not SLUG_RE.match(args.slug):
        print("bad slug %r: use kebab-case [a-z0-9-]" % args.slug, file=sys.stderr)
        return 2
    target_page = args.target_page or KIND_PAGE.get(args.kind, "")
    if not target_page:
        print("--target-page required for kind=technique (e.g. techniques/web/jwt-attacks.md)",
              file=sys.stderr)
        return 2

    d = os.path.join(_engagement.TARGETS, args.eng) if args.eng else _engagement.active_dir()
    if not d or not os.path.isdir(d):
        print("no active engagement (set targets/active.md or pass --eng)", file=sys.stderr)
        return 2

    inbox = os.path.join(d, "wiki-candidates")
    os.makedirs(inbox, exist_ok=True)
    dest = os.path.join(inbox, args.slug + ".md")
    if os.path.exists(dest):
        print("candidate already exists: %s" % dest, file=sys.stderr)
        return 2

    source_eng = args.eng or os.path.basename(os.path.normpath(d))
    on_date = args.date or date.today().isoformat()
    with open(dest, "w", encoding="utf-8") as fh:
        fh.write(build(args.kind, args.slug, target_page, source_eng, args.body, on_date))
    print(dest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
