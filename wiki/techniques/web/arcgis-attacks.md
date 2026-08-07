---
title: "ArcGIS Attacks"
type: technique
tags: [exploitation, web, arcgis, enumeration, spatial-data]
phase: exploitation
date_created: 2026-08-06
date_updated: 2026-08-06
sources: []
---

# ArcGIS Attacks

Esri ArcGIS Enterprise publishes map and feature services over a REST API. The viewer UI is not the
authorization boundary: service capabilities are advertised and enforced per service, so a map that
renders read-only can sit on a layer that still accepts anonymous writes.

## ArcGIS Enterprise REST API attack technique

1. Fetch each layer's `?f=json` capabilities metadata directly; a citizen-facing "view only" map can sit on a layer still advertising `Create,Update,Delete`, independent of what the viewer UI renders.
2. Enumerate `capabilities` at every `/FeatureServer` and `/MapServer` SERVICE ROOT across every published folder. `Create,Update,Delete` on the root JSON means anonymous write regardless of the app's UI.
3. Layer indices inside one service are often NON-CONTIGUOUS; always read the service root's own layer list rather than sequentially scanning ids.
4. A read-only MapServer/view can be backed by the exact same underlying table as a separate, anonymously-editable FeatureServer elsewhere on the host; compare full OBJECTID sets (`returnIdsOnly=true`) between the two, identical sets prove one table behind two doors.
5. Safely verify mass-destruction primitives without touching data: call `deleteFeatures`/`calculate` with `where=OBJECTID=999999999` (matches nothing). `{"success":true}` proves the operation is anonymously reachable and would apply to `where=1=1` across the whole table, with zero rows touched.
6. `outStatistics` + `groupByFieldsForStatistics` profiles any field's distinct values/counts in aggregate anonymously, without reading a single personal record.
7. Test a full write-then-revert (create, confirm persisted, delete, confirm restored) to prove impact on a service the viewer implies is display-only.

## References

<!-- promoted-slug: arcgis-esri-rest-featureserver-mapserver-deployments-are-a-d -->
