---
title: Azure Services - DNS Suffix
type: technique
tags: [azure, cloud, dns, enumeration, reference-import]
phase: enumeration
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Azure Services - DNS Suffix

## What it is

Many Azure services generate custom endpoints with a suffix such as `.cloudapp.azure.com`, `.windows.net`. Below is a table of common services and their associated DNS suffixes.

## How it works

Azure services are assigned predictable DNS suffixes (`.blob.core.windows.net`, `.vault.azure.net`, `.azurewebsites.net`) that correspond to specific service types, allowing attackers to enumerate exposed endpoints through DNS brute-forcing and subdomain takeover identification. Services with custom DNS names that have been deprovisioned but whose CNAME records still point to Azure-controlled suffixes are vulnerable to subdomain takeover, where an attacker provisions the same Azure resource name to serve malicious content from the victim's domain. Knowing the suffix-to-service mapping aids in recon, takeover hunting, and SSRF target identification.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## DNS table

Many Azure services generate custom endpoints with a suffix such as `.cloudapp.azure.com`, `.windows.net`. Below is a table of common services and their associated DNS suffixes.

These services can also be leveraged for domain fronting or communication with an external C2 server when they are whitelisted by the proxy or the firewall rules.

| Service | Domain |
| --- | --- |
| Analysis Services Suffix | .asazure.windows.net |
| API Management Suffix | .azure-api.net |
| App Services Suffix | .azurewebsites.net |
| Automation Suffix | .azure-automation.net |
| Batch Suffix | .batch.azure.com |
| Blob Endpoint Suffix | .blob.core.windows.net |
| CDN Suffix | .azureedge.net |
| Data Lake Analytics Catalog Suffix | .azuredatalakeanalytics.net |
| Data Lake Store Suffix | .azuredatalakestore.net |
| DocumentDB/CosmosDB Suffix | .documents.azure.com |
| Event Hubs Suffix | .servicesbus.windows.net |
| File Endpoint Suffix | .file.core.windows.net |
| FrontDoor Suffix | .azurefd.net |
| IoT Hub Suffix | .azure-devices.net |
| Key Vault Suffix | .vault.azure.net |
| Logic App Suffix | .azurewebsites.net |
| Queue Endpoint Suffix | .queue.core.windows.net |
| Redis Cache Suffix | .redis.cache.windows.net |
| Service Bus Suffix | .servicesbus.windows.net  |
| Service Fabric Suffix | .cloudapp.azure.com |
| SQL Database Suffix | .database.windows.net |
| Storage Endpoint Suffix | .core.windows.net |
| Table Endpoint Suffix | .table.core.windows.net |
| Traffic Manager Suffix | .trafficmanager.net |
| Web Application Gateway Suffix | .cloudapp.azure.com |

## References

* [Azure services URLs and IP addresses for firewall or proxy whitelisting - Daniel Neumann - 20. December 2016](https://www.danielstechblog.io/azure-services-urls-and-ip-addresses-for-firewall-or-proxy-whitelisting/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
