#!/usr/bin/env python3
"""
retag_iatt.py -- Fix tags and phase on IATT (InternalAllTheThings) imported wiki pages.

Problems addressed:
  - All pages share generic [ad, reference-import] or [cloud, reference-import] tags
    regardless of actual topic (AWS, Azure, Linux, Kerberos, CI/CD, MSSQL, etc.)
  - All pages have phase: exploitation even when they are enumeration / post-exploitation
  - 'ad' tag used instead of 'active-directory'
  - phase: reconnaissance used instead of the schema value 'enumeration'

Run from vault root:
  python3 scripts/retag_iatt.py [--dry-run]
"""

import re
import sys
from datetime import date
from pathlib import Path

TECHNIQUES = Path("/path/to/ClaudeBrain/wiki/techniques")
TODAY = date.today().isoformat()
DRY_RUN = "--dry-run" in sys.argv

# ---------------------------------------------------------------------------
# Explicit per-file mapping  { stem: ([tags], phase) }
# 'reference-import' is always appended automatically; don't include it here.
# ---------------------------------------------------------------------------
MAPPING = {
    # ── Active Directory ──────────────────────────────────────────────────
    "active-directory": (["active-directory", "windows", "enumeration"], "enumeration"),
    "active-directory---access-controls-aclace": (["active-directory", "windows", "acl", "ace", "enumeration"], "enumeration"),
    "active-directory---certificate-esc1":  (["active-directory", "adcs", "certificates", "windows", "esc1", "exploitation"], "exploitation"),
    "active-directory---certificate-esc2":  (["active-directory", "adcs", "certificates", "windows", "esc2", "exploitation"], "exploitation"),
    "active-directory---certificate-esc3":  (["active-directory", "adcs", "certificates", "windows", "esc3", "exploitation"], "exploitation"),
    "active-directory---certificate-esc4":  (["active-directory", "adcs", "certificates", "windows", "esc4", "exploitation"], "exploitation"),
    "active-directory---certificate-esc5":  (["active-directory", "adcs", "certificates", "windows", "esc5", "exploitation"], "exploitation"),
    "active-directory---certificate-esc6":  (["active-directory", "adcs", "certificates", "windows", "esc6", "exploitation"], "exploitation"),
    "active-directory---certificate-esc7":  (["active-directory", "adcs", "certificates", "windows", "esc7", "exploitation"], "exploitation"),
    "active-directory---certificate-esc8":  (["active-directory", "adcs", "certificates", "windows", "esc8", "exploitation"], "exploitation"),
    "active-directory---certificate-esc9":  (["active-directory", "adcs", "certificates", "windows", "esc9", "exploitation"], "exploitation"),
    "active-directory---certificate-esc10": (["active-directory", "adcs", "certificates", "windows", "esc10", "exploitation"], "exploitation"),
    "active-directory---certificate-esc11": (["active-directory", "adcs", "certificates", "windows", "esc11", "exploitation"], "exploitation"),
    "active-directory---certificate-esc12": (["active-directory", "adcs", "certificates", "windows", "esc12", "exploitation"], "exploitation"),
    "active-directory---certificate-esc13": (["active-directory", "adcs", "certificates", "windows", "esc13", "exploitation"], "exploitation"),
    "active-directory---certificate-esc14": (["active-directory", "adcs", "certificates", "windows", "esc14", "exploitation"], "exploitation"),
    "active-directory---certificate-esc15": (["active-directory", "adcs", "certificates", "windows", "esc15", "exploitation"], "exploitation"),
    "active-directory---certificate-esc-attacks": (["active-directory", "adcs", "certificates", "windows", "exploitation"], "exploitation"),
    "active-directory---certificate-services": (["active-directory", "adcs", "certificates", "windows", "enumeration"], "enumeration"),
    "active-directory---enumeration":       (["active-directory", "windows", "enumeration", "ldap", "bloodhound"], "enumeration"),
    "active-directory-enumeration":         (["active-directory", "windows", "enumeration", "bloodhound", "powershell"], "enumeration"),
    "active-directory---federation-services": (["active-directory", "adfs", "federation", "saml", "windows", "exploitation"], "exploitation"),
    "active-directory---golden-certificate": (["active-directory", "adcs", "certificates", "windows", "persistence"], "post-exploitation"),
    "active-directory-gpo":                 (["active-directory", "windows", "gpo", "persistence", "privilege-escalation"], "post-exploitation"),
    "active-directory---group-policy-objects": (["active-directory", "windows", "gpo", "persistence"], "post-exploitation"),
    "active-directory---groups":            (["active-directory", "windows", "groups", "enumeration"], "enumeration"),
    "active-directory---integrated-dns---adidns": (["active-directory", "windows", "dns", "adidns", "enumeration"], "enumeration"),
    "active-directory---linux":             (["active-directory", "linux", "windows", "enumeration"], "enumeration"),
    "active-directory---machine-account-quota": (["active-directory", "windows", "machine-account", "exploitation"], "exploitation"),
    "active-directory---ntds-dumping":      (["active-directory", "windows", "credentials", "ntds", "dcsync"], "post-exploitation"),
    "active-directory---read-only-domain-controller": (["active-directory", "windows", "rodc", "credentials"], "post-exploitation"),
    "active-directory---recycle-bin":       (["active-directory", "windows", "enumeration"], "enumeration"),
    "active-directory---tricks":            (["active-directory", "windows", "lateral-movement"], "post-exploitation"),
    "ad-privilege-escalation":              (["active-directory", "windows", "privilege-escalation", "kerberoasting", "dcsync", "genericall", "pass-the-hash"], "exploitation"),
    "internal-all-the-things":              (["active-directory", "azure", "aws", "internal-pentest", "enumeration"], "enumeration"),

    # ── Internal AD attacks ───────────────────────────────────────────────
    "internal---coerce":        (["active-directory", "windows", "ntlm", "coercion", "exploitation"], "exploitation"),
    "internal---dcom":          (["active-directory", "windows", "dcom", "lateral-movement"], "post-exploitation"),
    "internal---kerberos-relay":(["active-directory", "kerberos", "relay", "exploitation"], "exploitation"),
    "internal---ntlm-relay":    (["active-directory", "ntlm", "relay", "lateral-movement", "exploitation"], "exploitation"),
    "internal---pxe-boot-image":(["active-directory", "windows", "pxe", "credentials", "network"], "recon"),
    "internal---shares":        (["active-directory", "windows", "smb", "enumeration", "credentials"], "enumeration"),

    # ── Kerberos ──────────────────────────────────────────────────────────
    "kerberos---bronze-bit":    (["active-directory", "kerberos", "windows", "exploitation"], "exploitation"),
    "kerberos-delegation---constrained-delegation":           (["active-directory", "kerberos", "windows", "delegation", "lateral-movement"], "post-exploitation"),
    "kerberos-delegation---resource-based-constrained-delegation": (["active-directory", "kerberos", "rbcd", "windows", "exploitation"], "exploitation"),
    "kerberos-delegation---unconstrained-delegation":         (["active-directory", "kerberos", "windows", "delegation", "lateral-movement"], "post-exploitation"),
    "kerberos---service-for-user-extension":  (["active-directory", "kerberos", "windows", "delegation", "exploitation"], "exploitation"),
    "kerberos---tickets":       (["active-directory", "kerberos", "windows", "credentials", "golden-ticket", "silver-ticket"], "post-exploitation"),

    # ── Roasting ─────────────────────────────────────────────────────────
    "roasting---asrep-roasting":  (["active-directory", "kerberos", "windows", "asrep", "password-cracking", "enumeration"], "enumeration"),
    "roasting---kerberoasting":   (["active-directory", "kerberos", "windows", "kerberoasting", "password-cracking"], "enumeration"),
    "roasting---timeroasting":    (["active-directory", "kerberos", "windows", "password-cracking"], "enumeration"),

    # ── Hash / credential techniques ──────────────────────────────────────
    "hash---capture-and-cracking": (["active-directory", "windows", "credentials", "password-cracking", "ntlm"], "post-exploitation"),
    "hash-cracking":              (["credentials", "password-cracking", "hashcat", "john"], "post-exploitation"),
    "hash---overpass-the-hash":   (["active-directory", "windows", "lateral-movement", "kerberos"], "post-exploitation"),
    "hash---pass-the-hash":       (["active-directory", "windows", "lateral-movement", "pass-the-hash", "ntlm"], "post-exploitation"),
    "hash---pass-the-key":        (["active-directory", "windows", "kerberos", "lateral-movement"], "post-exploitation"),

    # ── Password / credential stores ─────────────────────────────────────
    "password---ad-user-comment":        (["active-directory", "windows", "credentials", "enumeration"], "recon"),
    "password---dmsa":                   (["active-directory", "windows", "credentials"], "post-exploitation"),
    "password---dsrm-credentials":       (["active-directory", "windows", "credentials", "persistence"], "post-exploitation"),
    "password---gmsa":                   (["active-directory", "windows", "gmsa", "credentials"], "post-exploitation"),
    "password---group-policy-preferences": (["active-directory", "windows", "gpp", "credentials"], "recon"),
    "password---laps":                   (["active-directory", "windows", "laps", "credentials"], "post-exploitation"),
    "password---pre-created-computer-account": (["active-directory", "windows", "credentials", "machine-account", "exploitation"], "exploitation"),
    "password---shadow-credentials":     (["active-directory", "windows", "shadow-credentials", "certificates", "exploitation"], "exploitation"),
    "password---spraying":               (["active-directory", "windows", "password-spray", "brute-force", "exploitation"], "exploitation"),

    # ── Trust / forest ────────────────────────────────────────────────────
    "child-domain-to-forest-compromise---sid-hijacking": (["active-directory", "windows", "forest", "sid-hijacking", "exploitation"], "exploitation"),
    "forest-to-forest-compromise---trust-ticket":        (["active-directory", "windows", "forest", "kerberos", "exploitation"], "exploitation"),
    "trust---privileged-access-management": (["active-directory", "windows", "pam", "trust"], "post-exploitation"),
    "trust---relationship":                 (["active-directory", "windows", "trust", "forest", "enumeration"], "enumeration"),

    # ── AD exploits / named vulns ─────────────────────────────────────────
    "nopac--samaccountname-spoofing": (["active-directory", "windows", "privilege-escalation", "cve", "exploitation"], "exploitation"),
    "printnightmare":                 (["active-directory", "windows", "privilege-escalation", "cve", "exploitation"], "exploitation"),
    "zerologon":                      (["active-directory", "windows", "exploitation", "cve"], "exploitation"),
    "privexchange":                   (["active-directory", "windows", "ntlm", "exploitation"], "exploitation"),
    "ms14-068-checksum-validation":   (["active-directory", "windows", "kerberos", "cve", "exploitation"], "exploitation"),

    # ── Deployment / management infra ─────────────────────────────────────
    "deployment---mdt":  (["active-directory", "windows", "mdt", "credentials", "lateral-movement"], "recon"),
    "deployment---sccm": (["active-directory", "windows", "sccm", "credentials", "lateral-movement"], "post-exploitation"),
    "deployment---scom": (["active-directory", "windows", "scom"], "post-exploitation"),
    "deployment---wsus": (["active-directory", "windows", "wsus", "lateral-movement", "persistence"], "post-exploitation"),

    # ── Windows OS techniques ─────────────────────────────────────────────
    "windows---amsi-bypass":              (["windows", "amsi", "evasion", "bypass"], "post-exploitation"),
    "windows---defenses":                 (["windows", "edr", "defense-evasion"], "post-exploitation"),
    "windows---download-and-execute-methods": (["windows", "payload-delivery", "initial-access"], "exploitation"),
    "windows---dpapi":                    (["windows", "dpapi", "credentials"], "post-exploitation"),
    "windows---persistence":              (["windows", "persistence"], "post-exploitation"),
    "windows---privilege-escalation":     (["windows", "privilege-escalation"], "post-exploitation"),
    "windows---using-credentials":        (["windows", "credentials", "lateral-movement"], "post-exploitation"),
    "rdp---persistence":                  (["windows", "rdp", "persistence"], "post-exploitation"),
    "kiosk-escape-and-jail-breakout":     (["windows", "kiosk", "bypass", "evasion"], "post-exploitation"),
    "proxy-bypass":                       (["windows", "proxy", "evasion", "bypass"], "post-exploitation"),

    # ── Linux OS techniques ───────────────────────────────────────────────
    "linux---evasion":             (["linux", "evasion"], "post-exploitation"),
    "linux---persistence":         (["linux", "persistence"], "post-exploitation"),
    "linux---privilege-escalation":(["linux", "privilege-escalation"], "post-exploitation"),

    # ── AWS ───────────────────────────────────────────────────────────────
    "aws---access-token--secrets":         (["cloud", "aws", "credentials", "secrets", "enumeration"], "enumeration"),
    "aws---cli":                           (["cloud", "aws", "enumeration"], "enumeration"),
    "aws---enumerate":                     (["cloud", "aws", "enumeration"], "enumeration"),
    "aws---identity--access-management":   (["cloud", "aws", "iam", "privilege-escalation", "credentials"], "post-exploitation"),
    "aws---ioc--detections":               (["cloud", "aws", "detection"], "recon"),
    "aws---metadata-ssrf":                 (["cloud", "aws", "ssrf", "metadata", "exploitation"], "exploitation"),
    "aws---service---cognito":             (["cloud", "aws", "cognito", "authentication", "exploitation"], "exploitation"),
    "aws---service---dynamodb":            (["cloud", "aws", "dynamodb", "database", "exploitation"], "exploitation"),
    "aws---service---ec2":                 (["cloud", "aws", "ec2", "exploitation"], "exploitation"),
    "aws---service---lambda--api-gateway": (["cloud", "aws", "lambda", "api", "exploitation"], "exploitation"),
    "aws---service---s3-buckets":          (["cloud", "aws", "s3", "storage", "exploitation"], "exploitation"),
    "aws---service---ssm":                 (["cloud", "aws", "ssm", "credentials"], "post-exploitation"),
    "aws---training":                      (["cloud", "aws"], "recon"),

    # ── Azure ─────────────────────────────────────────────────────────────
    "azure-ad---access-and-tokens":           (["cloud", "azure", "credentials", "oauth", "tokens"], "post-exploitation"),
    "azure-ad---ad-connect-and-cloud-sync":   (["cloud", "azure", "active-directory", "lateral-movement"], "post-exploitation"),
    "azure-ad---conditional-access-policy":   (["cloud", "azure", "bypass", "evasion"], "exploitation"),
    "azure-ad---enumerate":                   (["cloud", "azure", "enumeration"], "enumeration"),
    "azure-ad---iam":                         (["cloud", "azure", "iam", "privilege-escalation"], "post-exploitation"),
    "azure-ad---persistence":                 (["cloud", "azure", "persistence"], "post-exploitation"),
    "azure-ad---phishing":                    (["cloud", "azure", "phishing", "initial-access"], "exploitation"),
    "azure---requirements":                   (["cloud", "azure", "enumeration"], "enumeration"),
    "azure-services---application-endpoint":  (["cloud", "azure", "web", "enumeration"], "enumeration"),
    "azure-services---application-proxy":     (["cloud", "azure", "lateral-movement"], "post-exploitation"),
    "azure-services---azure-devops":          (["cloud", "azure", "cicd", "exploitation"], "exploitation"),
    "azure-services---container-registry":    (["cloud", "azure", "container", "exploitation"], "exploitation"),
    "azure-services---deployment-template":   (["cloud", "azure", "credentials"], "post-exploitation"),
    "azure-services---dns-suffix":            (["cloud", "azure", "dns", "enumeration"], "enumeration"),
    "azure-services---keyvault":              (["cloud", "azure", "credentials", "secrets"], "post-exploitation"),
    "azure-services---microsoft-intune":      (["cloud", "azure", "intune", "lateral-movement"], "post-exploitation"),
    "azure-services---office-365":            (["cloud", "azure", "office365", "exploitation"], "exploitation"),
    "azure-services---runbook-and-automation":(["cloud", "azure", "lateral-movement", "persistence"], "post-exploitation"),
    "azure-services---storage-blob":          (["cloud", "azure", "storage", "exploitation"], "exploitation"),
    "azure-services---virtual-machine":       (["cloud", "azure", "ec2", "exploitation"], "exploitation"),
    "azure-services---web-apps":              (["cloud", "azure", "web", "exploitation"], "exploitation"),
    "akams-shortcuts":                        (["cloud", "azure", "microsoft", "enumeration"], "recon"),

    # ── CI/CD ─────────────────────────────────────────────────────────────
    "cicd-attacks":          (["cicd", "supply-chain", "pipeline", "exploitation"], "exploitation"),
    "cicd---azure-devops":   (["cicd", "azure", "devops", "exploitation"], "exploitation"),
    "cicd---buildkite":      (["cicd", "buildkite", "exploitation"], "exploitation"),
    "cicd---circleci":       (["cicd", "circleci", "exploitation"], "exploitation"),
    "cicd---drone-ci":       (["cicd", "drone-ci", "exploitation"], "exploitation"),
    "cicd---github-actions": (["cicd", "github", "exploitation"], "exploitation"),
    "cicd---gitlab-ci":      (["cicd", "gitlab", "exploitation"], "exploitation"),

    # ── MSSQL ─────────────────────────────────────────────────────────────
    "mssql---audit-checks":       (["mssql", "database", "enumeration"], "enumeration"),
    "mssql---command-execution":  (["mssql", "database", "rce", "exploitation"], "exploitation"),
    "mssql---credentials":        (["mssql", "database", "credentials"], "post-exploitation"),
    "mssql---database-enumeration": (["mssql", "database", "enumeration"], "enumeration"),
    "mssql---linked-database":    (["mssql", "database", "lateral-movement"], "post-exploitation"),

    # ── Network / pivoting ────────────────────────────────────────────────
    "network-discovery":         (["network", "enumeration"], "enumeration"),
    "network-pivoting-techniques":(["network", "pivoting", "tunneling"], "post-exploitation"),
    "network-pivoting-tools":    (["network", "pivoting", "tunneling"], "post-exploitation"),

    # ── Containers ────────────────────────────────────────────────────────
    "docker":     (["docker", "container", "linux", "exploitation"], "exploitation"),
    "kubernetes": (["kubernetes", "container", "cloud", "exploitation"], "exploitation"),

    # ── C2 frameworks ─────────────────────────────────────────────────────
    "cobalt-strike---beacons": (["c2", "cobalt-strike", "evasion"], "post-exploitation"),
    "cobalt-strike---kits":    (["c2", "cobalt-strike", "evasion"], "post-exploitation"),
    "cobalt-strike":           (["c2", "cobalt-strike"], "post-exploitation"),
    "mythic-c2":               (["c2", "mythic"], "post-exploitation"),
    "metasploit":              (["exploitation", "framework", "post-exploitation"], "exploitation"),
    "mimikatz":                (["active-directory", "windows", "credentials"], "post-exploitation"),
    "powershell":              (["windows", "powershell", "scripting"], "post-exploitation"),

    # ── Initial access / phishing ─────────────────────────────────────────
    "phishing":           (["phishing", "initial-access"], "exploitation"),
    "initial-access":     (["initial-access"], "exploitation"),
    "html-smuggling":     (["phishing", "initial-access", "evasion"], "exploitation"),
    "clickfix":           (["phishing", "initial-access"], "exploitation"),
    "office---attacks":   (["office", "phishing", "initial-access"], "exploitation"),

    # ── Shells ────────────────────────────────────────────────────────────
    "bind-shell":                (["reverse-shell", "network", "exploitation"], "exploitation"),
    "reverse-shell-cheat-sheet": (["reverse-shell", "web-shell", "exploitation"], "exploitation"),

    # ── EDR / evasion ─────────────────────────────────────────────────────
    "endpoint-detection-and-response": (["edr", "evasion", "windows"], "post-exploitation"),
    "elastic-edr":                     (["edr", "elastic", "evasion", "windows"], "post-exploitation"),
    "opsec":                           (["opsec", "evasion"], "post-exploitation"),

    # ── Recon / methodology ───────────────────────────────────────────────
    "source-code-analysis":          (["sast", "source-review", "recon"], "recon"),
    "web-attack-surface":            (["web", "enumeration"], "recon"),
    "bug-hunting-methodology":       (["methodology", "recon"], "recon"),
    "hardcoded-secrets-enumeration": (["secrets", "credentials", "enumeration"], "recon"),
    "vulnerability-reports":         (["reporting", "methodology"], "recon"),
    "package-managers-and-build-files": (["supply-chain", "cicd", "recon"], "recon"),

    # ── Misc / niche ──────────────────────────────────────────────────────
    "android-application":           (["mobile", "android", "exploitation"], "exploitation"),
    "as400":                         (["as400", "legacy", "exploitation"], "exploitation"),
    "liferay":                       (["web", "cms", "exploitation"], "exploitation"),
    "ibm-cloud-managed-database-services": (["cloud", "ibm", "database", "exploitation"], "exploitation"),
    "ibm-cloud-object-storage":      (["cloud", "ibm", "storage", "exploitation"], "exploitation"),
    "miscellaneous--tricks":         (["active-directory", "windows"], "post-exploitation"),
}

# ---------------------------------------------------------------------------
# Phase normalisation -- fix legacy values
# ---------------------------------------------------------------------------
PHASE_ALIASES = {
    "reconnaissance": "recon",
    "post_exploitation": "post-exploitation",
}

VALID_PHASES = {"recon", "enumeration", "exploitation", "post-exploitation", "reporting"}


def parse_frontmatter(text: str):
    """Return (fm_dict_raw, body_after_closing_delimiter)."""
    if not text.startswith("---"):
        return None, text
    end = text.index("---", 3)
    fm_block = text[3:end].strip()
    body = text[end + 3:]
    return fm_block, body


def build_tags_yaml(tags: list) -> str:
    return "[" + ", ".join(tags) + "]"


def process_file(path: Path) -> str | None:
    """Return a one-line status message or None if unchanged."""
    stem = path.stem
    raw = path.read_text(encoding="utf-8")

    # Only process files with reference-import in tags
    if "reference-import" not in raw:
        return None

    fm_block, body = parse_frontmatter(raw)
    if fm_block is None:
        return f"SKIP (no frontmatter): {stem}"

    # ── Look up mapping ───────────────────────────────────────────────────
    if stem not in MAPPING:
        return f"UNMAPPED: {stem}"

    desired_tags_base, desired_phase = MAPPING[stem]
    desired_tags = desired_tags_base + ["reference-import"]

    # ── Patch each frontmatter field ──────────────────────────────────────
    new_fm = fm_block

    # tags:
    current_tags_match = re.search(r"^tags: \[.*?\]$", new_fm, re.MULTILINE)
    new_tags_str = build_tags_yaml(desired_tags)
    if current_tags_match:
        new_fm = new_fm[:current_tags_match.start()] + f"tags: {new_tags_str}" + new_fm[current_tags_match.end():]
    else:
        new_fm += f"\ntags: {new_tags_str}"

    # phase:
    phase_match = re.search(r"^phase: .+$", new_fm, re.MULTILINE)
    if phase_match:
        new_fm = new_fm[:phase_match.start()] + f"phase: {desired_phase}" + new_fm[phase_match.end():]
    else:
        new_fm += f"\nphase: {desired_phase}"

    # date_updated:
    date_match = re.search(r"^date_updated: .+$", new_fm, re.MULTILINE)
    if date_match:
        new_fm = new_fm[:date_match.start()] + f"date_updated: {TODAY}" + new_fm[date_match.end():]
    else:
        new_fm += f"\ndate_updated: {TODAY}"

    new_content = f"---\n{new_fm}\n---{body}"

    if new_content == raw:
        return f"UNCHANGED: {stem}"

    if not DRY_RUN:
        path.write_text(new_content, encoding="utf-8")

    # Build a compact diff summary
    old_tags = (re.search(r"^tags: \[.*?\]$", fm_block, re.MULTILINE) or type("", (), {"group": lambda self: "?"})()).group() if hasattr(re.search(r"^tags: \[.*?\]$", fm_block, re.MULTILINE), "group") else "?"
    old_phase = (re.search(r"^phase: .+$", fm_block, re.MULTILINE) or type("", (), {"group": lambda self: "?"})()).group() if hasattr(re.search(r"^phase: .+$", fm_block, re.MULTILINE), "group") else "?"

    prefix = "[DRY] " if DRY_RUN else ""
    return f"{prefix}FIXED  {stem}\n       phase: {old_phase.replace('phase: ','')} → {desired_phase}\n       tags: {new_tags_str}"


def main():
    files = sorted(TECHNIQUES.glob("*.md"))
    results = {"fixed": 0, "unchanged": 0, "unmapped": 0, "skipped": 0}
    unmapped = []

    for f in files:
        msg = process_file(f)
        if msg is None:
            results["skipped"] += 1
        elif msg.startswith("UNMAPPED"):
            results["unmapped"] += 1
            unmapped.append(f.stem)
        elif "UNCHANGED" in msg:
            results["unchanged"] += 1
        elif "FIXED" in msg or "[DRY]" in msg:
            results["fixed"] += 1
            print(msg)

    print(f"\n{'='*60}")
    prefix = "[DRY RUN] " if DRY_RUN else ""
    print(f"{prefix}Fixed: {results['fixed']}  Unchanged: {results['unchanged']}  Unmapped: {results['unmapped']}  Non-IATT skipped: {results['skipped']}")
    if unmapped:
        print("\nUnmapped IATT pages (need manual entries in MAPPING):")
        for s in unmapped:
            print(f"  {s}")


if __name__ == "__main__":
    main()
