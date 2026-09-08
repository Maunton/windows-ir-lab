# Open-source comparison for Windows IR Lab

Reviewed 2026-09-08. Scope: targeted source and license review of six repositories against Windows IR Lab 0.2.1-preview. This is not a whole-codebase security audit or a six-engine runtime benchmark. No upstream implementation code or rules were copied into the app.

## License and revision inventory

| Project | Reviewed commit | Root license |
|---|---|---|
| hayabusa | `851cea78151f30259f95979118d7591c9f70c6f3` | [AGPL-3.0; detection rules separately licensed](https://github.com/Yamato-Security/hayabusa/blob/851cea78151f30259f95979118d7591c9f70c6f3/LICENSE.txt) |
| chainsaw | `82fabe2436876f951d37485ed2bfb42e7568bdb3` | [GPL-3.0](https://github.com/WithSecureLabs/chainsaw/blob/82fabe2436876f951d37485ed2bfb42e7568bdb3/LICENCE) |
| velociraptor | `c37e355e6586fd5dcfc284c2dbc50bef16299362` | [AGPL-3.0](https://github.com/Velocidex/velociraptor/blob/c37e355e6586fd5dcfc284c2dbc50bef16299362/LICENSE) |
| WELA | `faa7988b8722a77f0d34b431d3590841f0d35d18` | [MIT](https://github.com/Yamato-Security/WELA/blob/faa7988b8722a77f0d34b431d3590841f0d35d18/LICENSE) |
| sysmon-modular | `a5072591e173b7f7a9fe518ebd5c10e5313ef6f8` | [MIT permission/warranty text](https://github.com/olafhartong/sysmon-modular/blob/a5072591e173b7f7a9fe518ebd5c10e5313ef6f8/license.md) |
| EVTX-ATTACK-SAMPLES | `4ceed2f4706daf601c212a8f91c113dd85349a2c` | [GPL-3.0; sample dataset and scripts](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/4ceed2f4706daf601c212a8f91c113dd85349a2c/LICENSE.GPL) |

All six repositories provide open-source license terms. EVTX Attack Samples is mainly a dataset, and Sysmon Modular is primarily configuration and tooling. Hayabusa documents Detection Rule License 1.1 separately from the engine license. Root licenses do not replace notices or licenses on dependencies, rules, or individual files. Learning from designs and running comparisons does not require copying implementation code. Before redistributing adapted code, engines, rules, or fixtures, preserve applicable notices and review source/distribution obligations; placing a copyleft engine beside an MIT application is not automatically a licensing determination.

## Source comparisons

### Hayabusa

**Source inspected:** [src/timeline/log_metrics.rs](https://github.com/Yamato-Security/hayabusa/blob/851cea78151f30259f95979118d7591c9f70c6f3/src/timeline/log_metrics.rs), [src/filter.rs](https://github.com/Yamato-Security/hayabusa/blob/851cea78151f30259f95979118d7591c9f70c6f3/src/filter.rs), [src/timeline/metrics.rs](https://github.com/Yamato-Security/hayabusa/blob/851cea78151f30259f95979118d7591c9f70c6f3/src/timeline/metrics.rs).

**Observed:** LogMetrics.update tracks record counts and first/last timestamps, and records timestamp parse errors. Channel filtering reads EVTX records with a dedicated parser and checks channels against rule inputs. Its first-record channel probe also has a limitation: some first-record parse failures are skipped silently. Upstream is a reference to test against, not infallible ground truth.

**Application to our project:** Keep parsed, rejected, and missing-timestamp counts separate. Add per-file/channel coverage and source-file provenance. Compare the same immutable EVTX files using exported timeline data before adding its engine as an optional integration.

### Chainsaw

**Source inspected:** [src/file/evtx.rs](https://github.com/WithSecureLabs/chainsaw/blob/82fabe2436876f951d37485ed2bfb42e7568bdb3/src/file/evtx.rs), [src/analyse/gaps.rs](https://github.com/WithSecureLabs/chainsaw/blob/82fabe2436876f951d37485ed2bfb42e7568bdb3/src/analyse/gaps.rs), [src/hunt.rs](https://github.com/WithSecureLabs/chainsaw/blob/82fabe2436876f951d37485ed2bfb42e7568bdb3/src/hunt.rs).

**Observed:** The EVTX wrapper iterates typed parser results and aliases provider/timestamp fields. Gap analysis groups records by channel, uses event record IDs and timestamps, and has explicit parse-error behavior. Tests cover gaps and channel separation.

**Application to our project:** Build a canonical event schema and validate it at input. Retain record IDs and source channel. Diagnose ID/time gaps only on appropriate complete streams: our selected event-ID queries and caps create intentional gaps, so those gaps alone must not be labeled tampering.

### Velociraptor

**Source inspected:** [artifacts/definitions/Windows/EventLogs/Evtx.yaml](https://github.com/Velocidex/velociraptor/blob/c37e355e6586fd5dcfc284c2dbc50bef16299362/artifacts/definitions/Windows/EventLogs/Evtx.yaml).

**Observed:** The artifact enumerates EVTX paths, uses parse_evtx, preserves source paths/channel/record IDs, and filters start/end times and IDs. It can choose a VSS accessor when configured. Collection definitions are separate from analysis and presentation.

**Application to our project:** Split collection, parsing, detection and report rendering into separate modules. Add saved-log input with source-file hashes. A single saved snapshot would also prevent sequential live queries from observing different retention windows; VSS support is a later feature, not a prerequisite.

### WELA

**Source inspected:** [WELA.ps1](https://github.com/Yamato-Security/WELA/blob/faa7988b8722a77f0d34b431d3590841f0d35d18/WELA.ps1).

**Observed:** Audit code reads auditpol output and detects missing administrator access. File-size auditing inspects MaximumSizeInBytes, FileSize and LogMode; it tracks missing logs and compares settings with a baseline.

**Application to our project:** Add a read-only preflight: administrator status, channel enabled state, capacity, retention mode and oldest available record. Keep a separate opt-in configuration operation. A nearly full circular log does not by itself prove evidence loss; inspect the oldest retained record against the requested start.

### Sysmon Modular

**Source inspected:** [10_process_access/exclude_lsass_noise.xml](https://github.com/olafhartong/sysmon-modular/blob/a5072591e173b7f7a9fe518ebd5c10e5313ef6f8/10_process_access/exclude_lsass_noise.xml), [merge_sysmon_configs.py](https://github.com/olafhartong/sysmon-modular/blob/a5072591e173b7f7a9fe518ebd5c10e5313ef6f8/merge_sysmon_configs.py), [Merge-SysmonXml.ps1](https://github.com/olafhartong/sysmon-modular/blob/a5072591e173b7f7a9fe518ebd5c10e5313ef6f8/Merge-SysmonXml.ps1).

**Observed:** The process-access noise module includes rules for 0x1000 and 0x1400 access and common service processes. The Python merger combines XML inputs by type, include/exclude subtype and priority. The input schema and Sysmon version must be respected.

**Application to our project:** This directly matches noise observed in the user reports. Review the currently installed configuration and selected exclusions in a lab, preserving useful detection coverage. Do not apply broad exclusions or replace a working custom configuration wholesale. Post-processing suppression reduces report clutter but cannot reduce logging volume or recover overwritten records.

### EVTX Attack Samples

**Source inspected:** [README.md](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/4ceed2f4706daf601c212a8f91c113dd85349a2c/README.md), [Evtx-to-Xml.ps1](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/4ceed2f4706daf601c212a8f91c113dd85349a2c/Evtx-to-Xml.ps1).

**Observed:** The checked-out revision contains 278 .evtx files organized across technique categories. The supplied conversion script uses wevtutil and strips selected control characters before parsing XML. That transformation can change evidence, so keep the original file.

**Application to our project:** Use a small, pinned, hashed fixture set to compare event IDs, timestamps, DNS/IP fields and detection results. Add benign fixtures alongside attack examples. Our reporter currently has no native offline EVTX input, so this review did not run the dataset through it or measure detection recall.

## Local probes performed

The reporter was imported on Linux using the existing test shim for Windows registry constants. Its PowerShell subprocess was mocked only to exercise the input boundary; no Windows collection occurred in these probes.

| Input / behavior | Observed result | Interpretation |
|---|---|---|
| `events: null` | 0 events | Empty representation handled. |
| `events: {}` | 1 event, no error | Empty objects are accepted and counted. |
| `events: {"value": [], "Count": 0}` | 1 event, no error | Non-event wrapper objects are accepted and counted. |
| Hostname `-` with destination IP `192.0.2.10` | Summary selects `-` | Placeholder prevents valid IP fallback. |

These reproduce weaknesses in our own code. They do not prove that the user DNS response had one of those exact shapes: the raw JSON from the affected run is still needed.

## Recommended implementation order

1. Validate event objects (ID, timestamp, provider/channel as available), distinguish rejected objects from empty results, and record structured parsing errors. Test zero, one and many events plus malformed/wrapper objects.
2. Normalize absent hostnames (`-`, empty, whitespace) and preserve both hostname and IP. Test compressed/expanded IPv6 and IPv4-mapped IPv6.
3. Add read-only log health and retention diagnostics before collecting. Separate requested, retained, collected, parsed and displayed coverage.
4. Export evidence to a fixed EVTX snapshot with a manifest and SHA-256 hashes; analyze that same snapshot offline. Record any export failure and never infer success from a zero count.
5. Run Hayabusa or Chainsaw on those exact files. Compare counts by channel/event ID, record identities and timestamps, then DNS/network fields, then detections. A detection-only comparison cannot isolate collection bugs.
6. Add fixture-based tests and a separate benign baseline. Independently evaluate rule false positives and false negatives; different rule sets naturally produce different findings.
7. Consider a version-pinned optional engine adapter while retaining the desktop app and reports. Verify output schema, errors and license obligations before shipping it.

## What remains untested

- Native builds and executions of Hayabusa, Chainsaw, Velociraptor and WELA were not performed in this comparison. The current local runtime has neither cargo nor pwsh. Their source is available, but availability is not a successful build.
- No equivalent same-input event/detection benchmark has been completed. The supplied user artifact is HTML, not original EVTX or raw JSON.
- Sysmon Modular configurations were reviewed but not applied to the user computer.
- EVTX fixtures were inventoried, not parsed by all engines.
- No speed, recall, precision, or full-three-day coverage claim is made.

## Deliverable status

This document records a completed targeted source comparison of all six projects and reproducible observations of the existing reporter. It does not represent a new executable release.
