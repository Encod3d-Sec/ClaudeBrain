#!/usr/bin/env python3
"""CVE drift oracle: flag playbook.json fingerprints that lag recent high/critical CVEs.

Read-only staleness DETECTOR (not a content pipeline). Diffs scripts/playbook.json
against a local nuclei-templates corpus (its cves.json metadata index) and reports,
per PRODUCT fingerprint, recent (>= MIN_YEAR) high/critical CVEs that are NOT already
cited in that fingerprint's tests[]. Emits CVE-ids + product only -- no template
bodies, no wiki content -- into a human-merge queue (docs/playbook-cve-queue.md).
Never edits playbook.json. See the 2026-06-17 catchup spec (amended) for why this is
a permitted signal and not "mining the corpus as a knowledge source".

  python3 scripts/cve_feed.py            # full report (stdout)
  python3 scripts/cve_feed.py -q         # one-line drift count (manual; not auto-wired)
  python3 scripts/cve_feed.py --write    # (re)write docs/playbook-cve-queue.md

Corpus path: $NUCLEI_TEMPLATES, else ~/nuclei-templates, else /root/nuclei-templates.
The corpus is host-local (it does NOT sync via Obsidian), so on a device without it
the oracle prints 'corpus not found' and exits 0 -- never an error.
"""
import json
import os
import re
import sys
from datetime import date

VAULT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
PLAYBOOK = os.path.join(VAULT, "scripts", "playbook.json")
QUEUE = os.path.join(VAULT, "docs", "playbook-cve-queue.md")
MIN_YEAR = 2024
SEVERITIES = {"critical", "high"}
MAX_PER_FP = 8
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

# Explicit product -> (keywords matched in CVE name+description, substring that
# identifies the playbook fingerprint key). PRODUCT fingerprints only -- generic
# tech classes (graphql/jwt/oauth/s3/k8s/...) have no meaningful per-product drift.
# Keyword match is word-boundaried + case-insensitive. Label != fingerprint key,
# so 'fp' is the unique key substring to associate the alias with the playbook entry.
ALIAS = {
    "Fortinet/Citrix/PAN/Pulse VPN": (
        ["fortinet", "fortios", "fortigate", "fortiproxy", "fortimanager", "citrix",
         "netscaler", "palo alto", "pan-os", "globalprotect", "pulse secure"], "fortigate"),
    "Ivanti Connect Secure": (["ivanti", "connect secure", "pulse connect"], "ivanti"),
    "Jenkins": (["jenkins"], "jenkins"),
    "Apache Tomcat": (["tomcat"], "tomcat"),
    "GitLab": (["gitlab"], "gitlab"),
    "Atlassian Confluence": (["confluence"], "confluence"),
    "Atlassian Jira": (["jira"], "jira"),
    "Drupal": (["drupal"], "drupal"),
    "Joomla": (["joomla"], "joomla"),
    "Magento/Adobe Commerce": (["magento", "adobe commerce"], "magento"),
    "WordPress core": (["wordpress"], "wordpress"),
    "Laravel": (["laravel"], "laravel"),
    "Next.js": (["next.js", "nextjs"], "next"),
    "Grafana": (["grafana"], "grafana"),
    "WebLogic/JBoss/WebSphere": (["weblogic", "jboss", "websphere"], "weblogic"),
    "Apache Struts": (["struts"], "struts"),
    "Microsoft Exchange": (["exchange server", "microsoft exchange", "proxyshell",
                            "proxylogon", "proxynotshell"], "owa"),
    "MOVEit Transfer": (["moveit"], "moveit"),
    "Microsoft SharePoint": (["sharepoint"], "sharepoint"),
    "Apache ActiveMQ": (["activemq"], "activemq"),
    "Adobe ColdFusion": (["coldfusion"], "coldfusion"),
    "PHP-CGI": (["php-cgi", "php cgi"], "php-cgi"),
    "VMware vCenter/ESXi": (["vcenter", "vsphere", "vmware", "esxi"], "vcenter"),
    "ScreenConnect/ConnectWise": (["screenconnect", "connectwise"], "screenconnect"),
    "PaperCut": (["papercut"], "papercut"),
    "Apache OFBiz": (["ofbiz"], "ofbiz"),
    "phpMyAdmin": (["phpmyadmin"], "phpmyadmin"),
    "Elasticsearch": (["elasticsearch"], "elasticsearch"),
    "InfluxDB": (["influxdb"], "influxdb"),
    "Spring": (["spring framework", "spring boot", "spring cloud", "spring security"], "spring"),
}


def corpus_dir():
    for c in (os.environ.get("NUCLEI_TEMPLATES"),
              os.path.expanduser("~/nuclei-templates"),
              "/root/nuclei-templates"):
        if c and os.path.isdir(c) and os.path.isfile(os.path.join(c, "cves.json")):
            return c
    return None


def _year(cid):
    m = re.match(r"CVE-(\d{4})-", cid)
    return int(m.group(1)) if m else 0


def load_recent_cves(corpus):
    """Recent high/critical CVEs from cves.json -> list of (id, sev, text)."""
    out = []
    p = os.path.join(corpus, "cves.json")
    for line in open(p, encoding="utf-8", errors="ignore"):
        line = line.strip().rstrip(",")
        if not line or line in "[]":
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        cid = o.get("ID", "")
        if not cid.startswith("CVE-") or _year(cid) < MIN_YEAR:
            continue
        info = o.get("Info", {}) or {}
        sev = (info.get("Severity", "") or "").lower()
        if sev not in SEVERITIES:
            continue
        text = (info.get("Name", "") + " " + info.get("Description", "")).lower()
        out.append((cid.upper(), sev, text))
    return out


def load_playbook():
    try:
        return json.load(open(PLAYBOOK, encoding="utf-8"))["fingerprints"]
    except Exception:
        return {}


def _kw_re(kw):
    return re.compile(r"\b" + re.escape(kw.lower()) + r"\b")


def _match_key(fp_sub, fps):
    """First playbook key where fp_sub appears as a whole (delimited) token, or None.
    Word-boundaried so 'next' binds to `next\\.js|nextjs`, not to a 'nextcloud'/'context' key."""
    rx = re.compile(r"(?<![a-z0-9])" + re.escape(fp_sub.lower()) + r"(?![a-z0-9])")
    return next((k for k in fps if rx.search(k.lower())), None)


def drift(corpus=None):
    """Return list of (label, fp_key, [missing CVE ids newest-first]) with drift."""
    corpus = corpus or corpus_dir()
    if not corpus:
        return None  # signal: no corpus on this device
    cves = load_recent_cves(corpus)
    fps = load_playbook()
    # map each alias to its actual playbook entry + the CVEs already cited there
    results = []
    for label, (keywords, fp_sub) in ALIAS.items():
        key = _match_key(fp_sub, fps)
        existing = set()
        if key is not None:
            existing = {c.upper() for c in CVE_RE.findall(json.dumps(fps[key]))}
        kwres = [_kw_re(k) for k in keywords]
        matched = []
        for cid, sev, text in cves:
            if any(r.search(text) for r in kwres):
                matched.append((cid, sev))
        missing = sorted({cid for cid, _ in matched} - existing,
                         key=lambda c: _year(c), reverse=True)
        if missing:
            results.append((label, key or "(no fingerprint)", missing[:MAX_PER_FP]))
    results.sort(key=lambda r: len(r[2]), reverse=True)
    return results


def corpus_stamp(corpus=None):
    corpus = corpus or corpus_dir()
    if not corpus:
        return ""
    try:
        return str(int(os.path.getmtime(os.path.join(corpus, "cves.json"))))
    except OSError:
        return ""


def _report_lines(results, corpus):
    try:
        when = date.today().isoformat()
    except Exception:
        when = "?"
    head = [
        "# Playbook CVE drift queue",
        "",
        f"Generated {when} from `{corpus}` (corpus mtime stamp {corpus_stamp(corpus)}).",
        "Read-only drift SIGNAL: recent high/critical CVEs whose product matches a "
        "playbook fingerprint but is not yet cited in its tests[]. Review each, then "
        "hand-merge the worthwhile ones into `scripts/playbook.json` (and set `prio`).",
        "This file lists CVE-ids only; no template content is copied here.",
        "",
    ]
    for label, key, missing in results:
        head.append(f"## {label}  (`{key}`)  -- {len(missing)} candidate(s)")
        head.append("- " + ", ".join(missing))
        head.append("")
    return "\n".join(head) + "\n"


def main():
    corpus = corpus_dir()
    if not corpus:
        if "-q" not in sys.argv:
            print("corpus not found (set NUCLEI_TEMPLATES or clone nuclei-templates); skipping.")
        return 0
    results = drift(corpus)
    n = len(results)
    if "-q" in sys.argv:
        if n:
            total = sum(len(m) for _, _, m in results)
            print(f"CVE drift: {n} fingerprint(s) lag {total} recent high/crit CVE(s) "
                  "(run scripts/cve_feed.py, queue: docs/playbook-cve-queue.md).")
        return 0
    if "--write" in sys.argv:
        os.makedirs(os.path.dirname(QUEUE), exist_ok=True)
        with open(QUEUE, "w", encoding="utf-8") as fh:
            fh.write(_report_lines(results, corpus))
        print(f"wrote {QUEUE} ({n} fingerprint(s) with drift)")
        return 0
    if not results:
        print("playbook current: no product fingerprint lags a recent high/crit CVE.")
        return 0
    print(_report_lines(results, corpus), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
