# epss-watch

What moved in EPSS scores and the CISA KEV catalog since yesterday.

The EPSS score of a CVE is available everywhere. Its movement is not. A score that went
from 0.02 to 0.70 overnight, a CVE that just entered KEV, a new CVE that arrives already
hot: that is the signal, and a daily snapshot alone hides it. This script downloads the
two public files every day, keeps them, and writes a short Markdown digest of what changed.

One file, standard library only, no database. The downloaded files are the data; a digest
is the diff between two of them.

## What a digest looks like

[example.md](example.md) is a complete one, built from the EPSS files of 2026-11-12 and
2026-11-13 and the two entries CISA added to KEV on 2026-11-13. Its tables, with rows left out:

**Added to CISA KEV**

| CVE | Vendor / product | Vulnerability | EPSS | Due | Ransomware |
|---|---|---|---|---|---|
| [CVE-2026-123039](https://nvd.nist.gov/vuln/detail/CVE-2026-123039) | Check Point / Multiple Products | Check Point Multiple Products Incorrect Permission Assignment for Critical Resource Vulnerability | 0.013 | 2026-11-16 | Unknown |
| [CVE-2026-114713](https://nvd.nist.gov/vuln/detail/CVE-2026-114713) | UnrealIRCd / UnrealIRCd | UnrealIRCd Improper Neutralization of Delimiters Vulnerability | 0.003 | 2026-11-16 | Unknown |

**Movers**

| CVE | EPSS 2026-11-12 → 2026-11-13 | Δ | Crossed | Top | KEV |
|---|---|---|---|---|---|
| [CVE-2023-49606](https://nvd.nist.gov/vuln/detail/CVE-2023-49606) | 0.631 → 0.809 | +0.178 | — | 0.4% | — |
| [CVE-2025-11201](https://nvd.nist.gov/vuln/detail/CVE-2025-11201) | 0.282 → 0.603 | +0.321 | 0.5 | 0.8% | — |
| [CVE-2026-27175](https://nvd.nist.gov/vuln/detail/CVE-2026-27175) | 0.069 → 0.240 | +0.171 | 0.1 | 2.1% | — |
| [CVE-2026-116606](https://nvd.nist.gov/vuln/detail/CVE-2026-116606) | 0.089 → 0.109 | +0.020 | 0.1 | 4.0% | since 2026-11-10 |

**New and already high**

| CVE | EPSS | Top | KEV |
|---|---|---|---|
| [CVE-2026-75869](https://nvd.nist.gov/vuln/detail/CVE-2026-75869) | 0.204 | 2.5% | — |

`Top` is where the new score ranks among all scored CVEs. Both KEV additions had an EPSS
under 0.02: exploitation confirmed where the model predicted almost none. That is why the
digest watches both feeds.

## Run

Python 3.9 or later. Nothing to install.

```bash
python3 epss_watch.py run                 # download today's files, write out/<date>.md and out/latest.md
python3 epss_watch.py backfill 30         # download the EPSS files of the last 30 days
python3 epss_watch.py digest 2026-11-10   # write the digest of any day already kept
python3 epss_watch.py history CVE-2025-11201
```

EPSS files appear at 13:30 UTC every day. One run a day after that is enough:

```
0 14 * * *  python3 /path/to/epss_watch.py run >> /path/to/run.log 2>&1
```

Cron uses the machine's time zone, so convert. `run` is safe to repeat, and KEV is usually
updated later in the day: a second run in the evening puts the day's KEV additions in the
day's digest instead of the next one.

`data/` and `out/` sit next to the script, wherever it is called from; `--data` and `--out`
move them. A run takes a few seconds and about 300 MB of memory.

A problem is reported in one line on stderr, with exit status 1. If only KEV is out of
reach, the digest is still written, without it. A damaged file is named in the error:
delete it, and `backfill` fetches an EPSS file again.

The first digest is a baseline: there is nothing to compare with. EPSS has an archive, so
`backfill` fills in the past, back to 2022-02-04 (older files do not state their model
version and are skipped). KEV has no archive, so KEV additions appear from the second day
on. Start collecting before you need it.

## What counts as movement

Every rule is a constant at the top of `epss_watch.py`.

| Reported as | Rule | Default |
|---|---|---|
| Mover | rose across a level, and by at least `CROSS_MIN` | levels 0.1, 0.5, 0.9; 0.02 |
| Mover | rose by at least `SPIKE_ABS` since the previous file | 0.10 |
| Mover | rose `SPIKE_REL`×, and is now at least `SPIKE_REL_MIN` | 5×, 0.05 |
| New and already high | first appearance at or above `NEW_HIGH` | 0.10 |
| Added to CISA KEV | in the catalog, not in the previous one kept | |

Measured on the 151 days of the current EPSS model (`v2026.06.15`): a median of 3 movers a
day out of 400,000 CVEs, 8 or fewer nine days in ten, none on 8 days. Three days went over
50; a table that long is cut to the 50 highest scores, and says so. "New and already high"
is rare: 13 CVEs in five months.

The rules are tuned to this model. The previous one was noisier, and the same rules gave
15 to 97 movers a day. Expect to retune after a model change.

## Recalibration

EPSS is a model. When it changes, every score moves at once, for reasons that have nothing
to do with the CVEs. Reporting movement that day would be wrong in bulk, so the digest says
what happened and leaves the movers out. Either sign is enough:

- the model version stated in the file changed;
- one CVE in a thousand (`RECAL_FRACTION`) moved by `RECAL_DELTA` (0.05) or more since the
  previous file.

The second does most of the work. Replayed over 220 days of real files, across the last
two model changes:

| What happened | CVEs that moved by 0.05 or more |
|---|---|
| Ordinary day, current model | 0.002% (median) |
| Busiest days still reported | up to 0.09% |
| A data source flapping: the same 850 old CVEs drop, then come back a day or two later (8 days, Aug–Sep 2026) | 0.27% to 0.32% |
| Aftershocks of the March 2025 model, over the following weeks (12 days) | 0.18% to 9.7% |
| The day of a model change (2 days) | 7.8% and 10.1% |

The highest share on a day that was reported is 0.091%, the lowest on a day left out is
0.176%: the threshold sits in that gap. Of the 22 days left out, the model version had
changed on 2.

The cost: real movement on such a day is lost with the noise, because the next digest
compares with that day's values. KEV additions and new CVEs are reported regardless.

## Files

```
data/epss_scores-YYYY-MM-DD.csv.gz    ~2.8 MB a day, from FIRST (epss.empiricalsecurity.com)
data/kev-YYYY-MM-DD.json.gz           ~0.2 MB a day, from CISA (www.cisa.gov)
out/YYYY-MM-DD.md, out/latest.md      the digests
```

About 1.1 GB a year. Keep them: they are the history, and the KEV copies become over time
the archive CISA does not publish. Nothing else is stored, and any digest can be rewritten
from them.

## Security

- It talks to two hosts over HTTPS, with a generic User-Agent. No account, no key, no
  telemetry. Nothing about you or your systems is sent.
- What it downloads is data, checked before use: the date in a file before it names a file
  on disk, CVE ids before they go into a link, scores before they are compared.
- Text from the KEV catalog is reduced to ASCII letters, digits and plain punctuation, and
  cut to length. It cannot bring markup, a clickable link, an invisible character or a
  look-alike letter into a digest.
- Downloads and decompression are capped in size, a redirect away from HTTPS is refused,
  and nothing downloaded is executed.
- A digest still quotes third-party text. If an AI agent reads your digests, they are data
  there too, not instructions.

## What it will not do

- Enrich from NVD or any other API. Each CVE links to its NVD page; the reading is yours.
- Match against an inventory, score your exposure, or say what to patch.
- Report a slow climb as such. A score rising 0.02 a day is reported the day it crosses a
  level, and only then.
- Report decreases, or removals from KEV.
- Hide a gap. After a missed day the digest compares with the last file kept, and says
  since when.
- Send anything anywhere. Output is files in `out/`.

## Tests

```bash
python3 -m unittest
```

No network, nothing to install. They cover the rules above, and what happens when a
download is not what it should be.

## License

MIT — see [LICENSE](LICENSE).
