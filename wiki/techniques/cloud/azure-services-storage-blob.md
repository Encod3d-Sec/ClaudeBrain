---
title: Azure Services - Storage Blob
type: technique
tags: [azure, cloud, exploitation, reference-import, storage]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Azure Services - Storage Blob

## What it is

Technical reference for **Azure Services - Storage Blob** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

Azure Storage Blobs may be publicly accessible if the storage account allows anonymous blob access and the container ACL is set to `Container` (public list and read) or `Blob` (public read). Attackers enumerate storage accounts by brute-forcing common names against `*.blob.core.windows.net` and then probe each container's HTTP endpoint for public listing, downloading files without authentication. Storage account keys, once obtained, grant full access to all blobs, tables, queues, and files in the account and are often found in application configuration files, deployment templates, or connection strings.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

* Blobs - `*.blob.core.windows.net`
* File Services - `*.file.core.windows.net`
* Data Tables - `*.table.core.windows.net`
* Queues - `*.queue.core.windows.net`

## Enumerate blobs

```powershell
PS > . C:\Tools\MicroBurst\Misc\InvokeEnumerateAzureBlobs.ps1
PS > Invoke-EnumerateAzureBlobs -Base <SHORT DOMAIN> -OutputFile azureblobs.txt
Found Storage Account -  redacted.blob.core.windows.net
```

## List and download blobs

Visiting `https://<storage-name>.blob.core.windows.net/<storage-container>?restype=container&comp=list` provides a JSON file containing a complete list of the Azure Blobs.

```xml
<EnumerationResults ContainerName="https://<storage-name>.blob.core.windows.net/<storage-container>">
    <Blobs>
        <Blob>
            <Name>index.html</Name>
            <Url>https://<storage-name>.blob.core.windows.net/<storage-container>/index.html</Url>
            <Properties>
            <Last-Modified>Fri, 20 Oct 2023 20:08:20 GMT</Last-Modified>
            <Etag>0x8DBD1A84E6455C0</Etag>
            <Content-Length>782359</Content-Length>
            <Content-Type>text/html</Content-Type>
            <Content-Encoding/>
            <Content-Language/>
            <Content-MD5>JSe+sM+pXGAEFInxDgv4CA==</Content-MD5>
            <Cache-Control/>
            <BlobType>BlockBlob</BlobType>
            <LeaseStatus>unlocked</LeaseStatus>
            </Properties>
        </Blob>
```

Browse deleted files.

```ps1
$ curl -s -H "x-ms-version: 2019-12-12" 'https://<storage-name>.blob.core.windows.net/<storage-container>?restype=container&comp=list&include=versions' | xmllint --format - | grep Name

<EnumerationResults ServiceEndpoint="https://<storage-name>.blob.core.windows.net/" ContainerName="<storage-container>">
      <Name>index.html</Name>
      <Name>scripts-transfer.zip</Name>
```

```powershell
PS Az> Get-AzResource
PS Az> Get-AzStorageAccount -name <NAME> -ResourceGroupName <NAME>
PS Az> Get-AzStorageContainer -Context (Get-AzStorageAccount -name <NAME> -ResourceGroupName <NAME>).context
PS Az> Get-AzStorageBlobContent -Container <NAME> -Context (Get-AzStorageAccount -name <NAME> -ResourceGroupName <NAME>).context -Blob
```

Retrieve exposed containers with public access

```ps1
PS Az> (Get-AzStorageAccount | Get-AzStorageContainer).cloudBlobContainer | select Uri,@{n='PublicAccess';e={$_.Properties.PublicAccess}}
```

## SAS URL

* Use [Storage Explorer](https://azure.microsoft.com/en-us/features/storage-explorer/)
* Click on **Open Connect Dialog** in the left menu.
* Select **Blob container**.
* On the **Select Authentication Method** page
    * Select **Shared access signature (SAS)** and click on Next
    * Copy the URL in **Blob container SAS URL** field.

:warning: You can also use `subscription`(username/password) to access storage resources such as blobs and files.

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
