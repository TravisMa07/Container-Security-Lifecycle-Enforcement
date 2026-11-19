# P0 authoritative framework source review

Reviewed 2026-11-19 by independent read-only researcher `p0_sources`, base `8c5e95e661781f2810030ca6b89d6c0f7afd4f08`. No release control mappings ship in P0. Source access and reviewed text are separate from implemented technical evidence.

## NIST SP 800-53 Rev.5

The [official publication](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) links the official NIST OSCAL distribution. Reviewed [catalog at oscal-content v1.4.0](https://raw.githubusercontent.com/usnistgov/oscal-content/v1.4.0/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json), tag commit `bc8a528770033611df899b3d52703fb3dc91a20d`. Metadata: control catalog version 5.2.0, modified 2025-08-26, OSCAL 1.1.3. Exact downloaded bytes SHA-256: `1645df6a370dcb931db2e2d5d70c2f77bc89c38499a416c23a70eb2c0e595bcc`. Source license is US public domain plus worldwide CC0 dedication, recorded in the pinned repository LICENSE.md. Download retained only in ignored `.local/p0-sources/`.

Reviewed statements and EXAMINE/INTERVIEW/TEST assessment entries for RA-5, SI-2, CM-6 and AC-6. Candidate technical associations:

| Control | CSLE evidence direction | Facts the tool cannot establish |
| --- | --- | --- |
| RA-5 | Digest-bound scans, DB freshness and vulnerability inventory | Organizational cadence, risk decisions and whole-system coverage |
| SI-2 | Scoped replacement/rescan and regression history | Vendor release deadlines, side-effect testing and organizational change process |
| CM-6 | Versioned hardening policy, observed settings, exceptions and admission results | Approved organizational baselines, operational needs and full change control |
| AC-6 | Read-only collector RBAC and workload privilege restrictions | Task-specific necessity and all organizational identities/access |

These are source-reviewed mapping directions, not implemented assessments or organizational compliance claims.

## PCI DSS v4.0.1 — exact-source gate open

The [official document library](https://www.pcisecuritystandards.org/document_library/?class=pcidss&doc=pci_dss) links the full standard to [PCI-DSS-v4_0_1.pdf](https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0_1.pdf). Both ordinary HTTP retrieval and the web tool returned 403. Full requirements, applicability and testing procedures were not reviewed; no access restriction was bypassed.

[Official FAQ 1597](https://www.pcisecuritystandards.org/faqs/1597/) supports investigation of 6.3.1, 6.3.3 and 11.3.1. Scan severity cannot replace entity-specific risk ranking. Scan time and FixedVersion cannot establish vendor patch release dates or SLA satisfaction. Container image scans do not establish full internal-network/CDE coverage or qualified independent scanning personnel. All three candidates remain proposed/source-review-pending until the official full text is reviewed.

## CIS Kubernetes Benchmark — exact-source gate open

The [official benchmark listing](https://www.cisecurity.org/benchmark/kubernetes) identifies edition 2.1.0. Its [download route](https://learn.cisecurity.org/benchmarks) requires registration/contact fields and presents usage terms. No registration or personal-data submission was performed.

Candidate workload topics: privileged containers, host PID/IPC/network sharing, privilege escalation and root execution. Exact clause IDs, automated/manual classifications and applicability to the selected Kubernetes 1.37 profile remain unreviewed. Do not inherit IDs from older editions or equate P0's privilege smoke policy with an approved CIS check.

## Closure access investigation — 2026-11-19

Read-only researcher `closure_sources` exhausted the legitimate public publisher paths found. PCI's actual published library feed is <https://docs-pub.pcisecuritystandards.org/doc_library.json>, SHA-256 `1cd52e54bcb9953c44cd3a62664c1034923af9d454484f4252e57fb8aa0cc659`. It identifies the full standard as protected/agreement-required and the ROC/SAQ templates as unprotected. Current official [ROC r3](https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Reporting%20Template%20or%20Form/PCI-DSS-v4-0-1-ROC-Template-r3.pdf), [SAQ D Merchant](https://docs-prv.pcisecuritystandards.org/SAQ%20(Assessment)/SAQ/PCI-DSS-v4-0-1-SAQ-D-Merchant.pdf) and Service Provider r2 ordinary retrieval all returned403, including a normal cookie-preserving public-page/library session. Empty WordPress API results are not the operative document library. No agreement was accepted.

CIS official metadata identifies2.1.0 published2026-09-30 and advertises <https://workbench.cisecurity.org/cis/api/v1/file/7832/download>; ordinary retrieval returned404. Official campaign and applicability discussion returned403. Public metadata-page SHA-256 `ae0bf9c5d9ea946d07be36c0bd1d5c5a7e456701c4c6ca19659ec192a8db6e85`. No registration, personal-data submission or access-control bypass occurred. No third-party mirror was substituted as authoritative.

Exact selected requirement wording remains unverified beyond the facts explicitly stated by the official PCI FAQ. Full PDFs are not inherently required as a format; an official source reproducing the exact selected text can suffice. Such a source has not been obtained for all selected PCI/CIS clauses. P6 mappings cannot be shipped on the basis of this access report.
