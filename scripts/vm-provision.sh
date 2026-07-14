#!/usr/bin/env bash
# Provision the Kali VM: screenshot/tmux capture deps AND the recon + test toolchain that
# the recon-capture nudges point at, so those nudges reference tools that
# actually exist on the box.
#
# apt-first by design: Kali packages the whole ProjectDiscovery suite, which avoids the
# fragile `go install` path through the VPN tunnel (often egress-blocked) and installs the
# REAL ProjectDiscovery httpx as `httpx-toolkit` (the plain `httpx` apt/pip package is the
# Python HTTP library -- installing the toolkit is exactly the fix for the recurring
# "python httpx, not PD httpx" gap). Per-package tolerant: one unavailable name does not
# abort the batch. Idempotent (apt-get install is a no-op when already present).
#
#   bash vm-provision.sh          # install everything on the configured VM
#   bash vm-provision.sh --list   # print the toolset (no VM needed)
set -uo pipefail

# Screenshot / tmux-runner capture deps (this script's original purpose).
CAPTURE="tmux scrot xdotool imagemagick x11-utils xauth"
# Recon + test toolchain, Kali package names. httpx-toolkit = ProjectDiscovery httpx.
RECON="httpx-toolkit subfinder nuclei naabu dnsx katana amass gau gobuster ffuf \
feroxbuster dalfox gowitness arjun sqlmap hydra medusa nikto whatweb wpscan swaks \
jwt-tool trufflehog gitleaks seclists jq"

if [ "${1:-}" = "--list" ]; then
  echo "capture deps:"; printf '  %s\n' $CAPTURE
  echo "recon/test toolchain (Kali apt):"; printf '  %s\n' $RECON
  exit 0
fi

if [ ! -f /root/vm.sh ] || [ ! -f /root/creds.txt ]; then
  echo "[note] Kali VM not configured (need /root/vm.sh + /root/creds.txt)."
  echo "       See docs/virtual-machine.md, then re-run: bash scripts/vm-provision.sh"
  exit 0
fi

# Build the remote installer as a self-contained script and push it via base64 (vm.sh
# does not forward stdin and quoting a per-package loop inline is brittle -- the vault
# already uses this base64-push pattern for shot.py).
REMOTE=$(cat <<REMOTE_EOF
#!/usr/bin/env bash
SUDO=""; [ "\$(id -u)" -eq 0 ] || SUDO="sudo"
\$SUDO DEBIAN_FRONTEND=noninteractive apt-get update -qq || echo "[warn] apt update failed"
for p in $CAPTURE $RECON; do
  if \$SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "\$p" >/dev/null 2>&1; then
    echo "  ok   \$p"
  else
    echo "  MISS \$p (not in repo or failed)"
  fi
done
# fallbacks for tools not always apt-packaged
if ! command -v trufflehog >/dev/null 2>&1; then
  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | \$SUDO sh -s -- -b /usr/local/bin >/dev/null 2>&1 && echo "  trufflehog (installer)" || echo "  MISS trufflehog"
fi
if ! command -v jwt_tool >/dev/null 2>&1 && [ ! -x /usr/local/bin/jwt_tool ]; then
  [ -d /opt/jwt_tool ] || \$SUDO git clone -q https://github.com/ticarpi/jwt_tool /opt/jwt_tool 2>/dev/null
  [ -f /opt/jwt_tool/jwt_tool.py ] && \$SUDO ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool && echo "  jwt_tool (git)" || echo "  MISS jwt_tool"
fi
REMOTE_EOF
)

echo "[..] provisioning toolchain on the VM (apt-first, per-package tolerant)"
B64=$(printf '%s' "$REMOTE" | base64 -w0)
bash /root/vm.sh "echo $B64 | base64 -d | bash"

echo "[ok] provisioning attempted. Verify installed binaries with:"
echo "     bash /root/vm.sh 'for t in httpx subfinder ffuf naabu dnsx katana gau dalfox arjun sqlmap swaks jwt_tool trufflehog gitleaks; do command -v \$t >/dev/null 2>&1 && echo \"ok \$t\" || echo \"MISSING \$t\"; done'"
echo "     (note: httpx-toolkit installs the binary as 'httpx'; if a name is MISSING, tune the package name for your Kali release.)"
