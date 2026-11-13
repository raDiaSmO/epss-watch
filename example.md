# EPSS watch — 2026-11-13

EPSS model `v2026.06.15`, 406,184 CVEs scored.
CISA KEV catalog `2026.11.13`, 1,781 entries.

- **EPSS since 2026-11-12:** 12 movers, 1 new and already high.
- **KEV since 2026-11-12:** 2 additions.

## Added to CISA KEV

| CVE | Vendor / product | Vulnerability | EPSS | Due | Ransomware |
|---|---|---|---|---|---|
| [CVE-2026-123039](https://nvd.nist.gov/vuln/detail/CVE-2026-123039) | Check Point / Multiple Products | Check Point Multiple Products Incorrect Permission Assignment for Critical Resource Vulnerability | 0.013 | 2026-11-16 | Unknown |
| [CVE-2026-114713](https://nvd.nist.gov/vuln/detail/CVE-2026-114713) | UnrealIRCd / UnrealIRCd | UnrealIRCd Improper Neutralization of Delimiters Vulnerability | 0.003 | 2026-11-16 | Unknown |

CISA has evidence of active exploitation: for anything running these products this is no longer a prediction. The due date is the deadline CISA sets for US federal agencies.

## Movers

| CVE | EPSS 2026-11-12 → 2026-11-13 | Δ | Crossed | Top | KEV |
|---|---|---|---|---|---|
| [CVE-2023-49606](https://nvd.nist.gov/vuln/detail/CVE-2023-49606) | 0.631 → 0.809 | +0.178 | — | 0.4% | — |
| [CVE-2025-11201](https://nvd.nist.gov/vuln/detail/CVE-2025-11201) | 0.282 → 0.603 | +0.321 | 0.5 | 0.8% | — |
| [CVE-2025-60021](https://nvd.nist.gov/vuln/detail/CVE-2025-60021) | 0.257 → 0.552 | +0.295 | 0.5 | 1.0% | — |
| [CVE-2026-39813](https://nvd.nist.gov/vuln/detail/CVE-2026-39813) | 0.226 → 0.440 | +0.214 | — | 1.2% | — |
| [CVE-2026-27175](https://nvd.nist.gov/vuln/detail/CVE-2026-27175) | 0.069 → 0.240 | +0.171 | 0.1 | 2.1% | — |
| [CVE-2025-69985](https://nvd.nist.gov/vuln/detail/CVE-2025-69985) | 0.060 → 0.143 | +0.083 | 0.1 | 3.3% | — |
| [CVE-2022-3980](https://nvd.nist.gov/vuln/detail/CVE-2022-3980) | 0.098 → 0.127 | +0.029 | 0.1 | 3.7% | — |
| [CVE-2025-53143](https://nvd.nist.gov/vuln/detail/CVE-2025-53143) | 0.090 → 0.123 | +0.033 | 0.1 | 3.7% | — |
| [CVE-2025-53144](https://nvd.nist.gov/vuln/detail/CVE-2025-53144) | 0.085 → 0.116 | +0.031 | 0.1 | 3.9% | — |
| [CVE-2025-53145](https://nvd.nist.gov/vuln/detail/CVE-2025-53145) | 0.085 → 0.116 | +0.031 | 0.1 | 3.9% | — |
| [CVE-2025-53766](https://nvd.nist.gov/vuln/detail/CVE-2025-53766) | 0.085 → 0.115 | +0.031 | 0.1 | 3.9% | — |
| [CVE-2026-116606](https://nvd.nist.gov/vuln/detail/CVE-2026-116606) | 0.089 → 0.109 | +0.020 | 0.1 | 4.0% | since 2026-11-10 |

A score rises when the model sees new evidence, such as a public exploit or reports of exploitation. It is a reason to read the advisory, not a verdict.

## New and already high

| CVE | EPSS | Top | KEV |
|---|---|---|---|
| [CVE-2026-75869](https://nvd.nist.gov/vuln/detail/CVE-2026-75869) | 0.204 | 2.5% | — |

First scored today, already at or above 0.1: the model sees exploitation signals from day one.

## Sources

- EPSS: <https://epss.empiricalsecurity.com/epss_scores-2026-11-13.csv.gz>, compared with <https://epss.empiricalsecurity.com/epss_scores-2026-11-12.csv.gz>
- CISA KEV: <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>

## About these numbers

EPSS is FIRST's daily estimate of the probability that a CVE sees exploitation activity in the next 30 days. This digest reports *movement* in that estimate, because a score that changes is telling you something a static score cannot. Movement is a reason to look at the advisory, not a measure of your exposure.
