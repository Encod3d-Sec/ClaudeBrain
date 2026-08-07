# Harness wordlists

Small, high-signal lists of the **non-obvious** web paths and params we actually hit on boxes -
the ones the big generic lists (raft/seclists) miss or bury thousands of entries deep (e.g.
`/internal`, `/customapi`, `/health`, `?target=`). Run these FIRST, then fall back to the big lists.

- `harness-paths.txt`  - routes / dirs / high-value files (extensionless base names + a few specific
  files like `server-status`, `.git/config`, `secret.config`). Use with ffuf `-e .php,.py,...`.
- `harness-params.txt` - parameter names worth fuzzing for SSRF/LFI/cmdi/IDOR.

## Use (run before the big wordlist)
```bash
ffuf -c -u http://$T/FUZZ -w scripts/wordlists/harness-paths.txt -e .php,.py,.html,.txt -mc 200,301,302,401,403 -ac
ffuf -c -u "http://$T/page?FUZZ=test" -w scripts/wordlists/harness-params.txt -fs <baseline>     # param mining
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

## sensitive-artifacts.txt

Artifact paths that should never be reachable in production: VCS internals, framework debug
endpoints, config and backup files, dev leftovers. Fuzzing target for exposed-artifact
sweeps; not a general directory list.

Built from four sources, assembled with `sort -u` (1247 entries):
1. `harness-paths.txt` (this directory)
2. A seclists slice filtered to artifact-shaped names (`raft-large-files.txt`,
   `UnixDotfiles.fuzz.txt`, `Common-DB-Backups.txt`), kept only where the entry ends in a
   backup/config/archive extension, ends in `~`, or starts with a dot
3. An authored stack-specific core: CMSMS, WordPress, Symfony/Laravel, ABP/.NET, GWT,
   Directus, Node/Next, CI and editor leftovers
4. Non-English (Lithuanian) artifact and app names, permuted against artifact extensions

Deliberately not a `raft-large` dump: at an RoE-safe rate across a large estate that is days
of scanning with poor signal for this bug class, and WAFs wholesale-block sustained fuzzing.

The non-English set is evidence-backed: on a non-English-language app an English-only
wordlist returned nothing while a targeted native-language sweep found the real endpoints.
Keep it when regenerating.

Entries carry no leading slash (they are appended to a URL already ending in `/`), and the
list is filtered of domain-shaped and IP-shaped tokens so it stays publishable.
