# Harness wordlists

Small, high-signal lists of the **non-obvious** web paths and params we actually hit on boxes -
the ones the big generic lists (raft/seclists) miss or bury thousands of entries deep (e.g.
`/internal`, `/customapi`, `/health`, `?target=`). Run these FIRST, then fall back to the big lists.

- `harness-paths.txt`  - routes / dirs / high-value files (extensionless base names + a few specific
  files like `server-status`, `.git/config`, `secret.config`). Use with ffuf `-e .php,.py,...`.
- `harness-params.txt` - parameter names worth fuzzing for SSRF/LFI/cmdi/IDOR.

## Use (run before the big wordlist)
```bash
ffuf -u http://$T/FUZZ -w scripts/wordlists/harness-paths.txt -e .php,.py,.html,.txt -mc 200,301,302,401,403 -ac
ffuf -u "http://$T/page?FUZZ=test" -w scripts/wordlists/harness-params.txt -fs <baseline>     # param mining
```

## Keep it growing (the point)
After an engagement, surface generic tokens we discovered but don't yet list:
```bash
python3 scripts/wordlist-suggest.py          # read-only; prints NEW generic candidates from targets/*
scripts/wl-add.sh paths  internal customapi health     # add the good ones
scripts/wl-add.sh params target host file
scripts/wl-add.sh ignore cucm-uds paskolos             # suppress box-specific noise from FUTURE suggestions
```
`.wl-ignore` keeps rejected/box-specific tokens from resurfacing, so `wordlist-suggest.py --count`
(surfaced at SessionStart by engagement-init) reads `0 0` until a genuinely NEW token appears - no nag.
`wordlist-suggest.py` mines `targets/*/` (paths/walkthrough/state/log) for path+param tokens NOT
already listed, and is **leak-safe**: it drops anything that is an IP, a scope host/domain, the
engagement name, a flag, or a filesystem path (etc/home/root/...). It only SUGGESTS - you curate
(so client-specific branding never lands in this tracked, shippable list). `wl-add.sh` dedups + sorts.

## Client-data boundary
These files are tracked/shippable -> **generic methodology only**. Never paste a client hostname,
IP, real route name that identifies a target, cred, or flag. When in doubt, leave it out.
`scripts/check-leaks.sh` scans for active-engagement markers before sharing.
