# Machine-specific vault access (LOCAL, untracked) - EXAMPLE

Copy this file to `CLAUDE.local.md` (which is git-ignored) and fill in your own
machines. The tracked `CLAUDE.md` imports it via `@CLAUDE.local.md`, so your real
hostnames and user paths stay out of the published repo.

Bold names are hostnames. Run `hostname` to identify the active machine.

`- **<HOSTNAME-A>: ** vault at C:\Users\<you>\Documents\ObsidianVaults\ClaudeBrain `
`- WSL: /mnt/c/Users/<you>/Documents/ObsidianVaults/ClaudeBrain.`
`- **<HOSTNAME-B>:** vault at <another path>`; WSL: `<another /mnt path>`.``

If you only use one machine, you can skip this entirely and just set
`OBSIDIAN_VAULT` (or `QMD_VAULT`) in your shell profile - the path resolvers and
hooks self-locate or read those env vars.
