#!/usr/bin/env python3
"""epss-watch: what moved in EPSS scores and the CISA KEV catalog since the last snapshot.

The EPSS score of a CVE is available everywhere. Its movement is not: a score that
went from 0.02 to 0.70 overnight, a CVE that entered KEV, a new CVE that arrives
already hot. This script downloads the two daily public files, keeps them, and
writes a Markdown digest of what changed since the previous day.

Standard library only. `python3 epss_watch.py run` is the cron entry.
"""

from __future__ import annotations

import argparse
import gzip
import http.client
import io
import json
import os
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

# ---- What counts as movement. See README. ------------------------------------------
LEVELS = (0.1, 0.5, 0.9)  # an upward crossing of any of these is reported ...
CROSS_MIN = 0.02  # ... if the score also rose by at least this; 0.099 -> 0.101 is jitter
SPIKE_ABS = 0.10  # a one-day increase of at least this is a spike ...
SPIKE_REL, SPIKE_REL_MIN = 5.0, 0.05  # ... or a 5x increase, if the new score is at least 0.05
NEW_HIGH = 0.10  # a CVE seen for the first time at or above this is reported
RECAL_DELTA, RECAL_FRACTION = 0.05, 0.001  # one CVE in a thousand moving 0.05 in a day = the model moved
MAX_ROWS = 50  # a longer table is cut, and says so: one strange day must not make an unreadable digest

# ---- Where the data comes from, and how much of it is accepted ---------------------
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-{}.csv.gz"  # {} is YYYY-MM-DD or "current"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://nvd.nist.gov/vuln/detail/"
USER_AGENT = "epss-watch/1.0"
MAX_BYTES = 100 * 1024 * 1024  # eight times today's EPSS file; raise it when the feed outgrows it

HERE = Path(__file__).resolve().parent
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,10}", re.ASCII)  # ASCII: a bare \d also matches Arabic or fullwidth digits
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}", re.ASCII)


# ---- Everything downloaded is data, and is checked before it is used ---------------


def check_date(text: str) -> str:
    """`text` if it is a real YYYY-MM-DD date. Dates become file names, so nothing else gets through."""
    try:
        if DATE_RE.fullmatch(text):
            return date.fromisoformat(text).isoformat()
    except ValueError:
        pass
    raise ValueError(f"not a YYYY-MM-DD date: {text!r}")


def say(message: str) -> None:
    """Progress and errors go to stderr, without anything that could drive the terminal they land in."""
    print("".join(ch if ch.isprintable() else "?" for ch in message), file=sys.stderr)


def clean(text: object, limit: int = 100) -> str:
    """Third-party text reduced to ASCII letters, digits and plain punctuation, on one line, cut at `limit`.

    What is left cannot form markup, HTML or a link in the digest, and cannot hide anything in it:
    no invisible character, no look-alike letter from another alphabet, no right-to-left text.
    """
    text = unicodedata.normalize("NFKD", str(text))  # split è into e and its accent ...
    text = "".join(ch for ch in text if not unicodedata.combining(ch))  # ... and drop the accent
    text = re.sub(r"[^A-Za-z0-9 .,()/+&'!-]", " ", text)  # no | < > [ ] ` * : " and nothing outside ASCII
    text = re.sub(r"(?i)(www)\.", r"\1 ", text)  # GitHub turns a bare www.x.y into a link
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def gunzip(data: bytes) -> bytes:
    """Unpack gzip data. ValueError if it is not gzip, or unpacks to more than MAX_BYTES."""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
            out = f.read(MAX_BYTES + 1)
    except (OSError, EOFError, zlib.error) as exc:
        raise ValueError(f"not a gzip file ({exc})") from None
    if len(out) > MAX_BYTES:
        raise ValueError(f"unpacks to more than {MAX_BYTES:,} bytes")
    return out


def parse_epss(data: bytes) -> tuple[str, str, dict[str, tuple[float, float]]]:
    """-> (score_date, model_version, {cve: (epss, percentile)}).

    The file starts with `#model_version:...,score_date:...`, then `cve,epss,percentile` rows.
    The model version is what makes recalibration detection cheap. Rows that are not a CVE id
    and two numbers between 0 and 1 are dropped.
    """
    text = gunzip(data).decode("utf-8", "replace")
    head, _, body = text.partition("\n")
    when = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", head, re.ASCII)
    model = re.search(r"model_version:([A-Za-z0-9.-]{1,40})", head)
    if not (when and model):
        raise ValueError("EPSS file: no '#model_version:...,score_date:...' first line")
    scores = {}
    for line in body.splitlines():
        row = line.split(",", 3)
        try:
            cve, epss, pct = row[0], float(row[1]), float(row[2])
        except (IndexError, ValueError):
            continue
        if CVE_RE.fullmatch(cve) and 0 <= epss <= 1 and 0 <= pct <= 1:
            scores[cve] = (epss, pct)
    if not scores:
        raise ValueError("EPSS file: no scores in it")
    return check_date(when[1]), model[1], scores


def parse_kev(data: bytes) -> tuple[str, dict[str, dict[str, str]]]:
    """-> (catalog_version, {cve: {vendor, product, name, added, due, ransomware}}), every field cleaned."""
    try:
        doc = json.loads(gunzip(data) if data[:2] == b"\x1f\x8b" else data)
        entries = {}
        for v in doc["vulnerabilities"]:
            cve = str(v.get("cveID", ""))
            if CVE_RE.fullmatch(cve):
                added, due = str(v.get("dateAdded", "")), str(v.get("dueDate", ""))
                entries[cve] = {
                    "vendor": clean(v.get("vendorProject", ""), 40),
                    "product": clean(v.get("product", ""), 60),
                    "name": clean(v.get("vulnerabilityName", "")),
                    "added": added if DATE_RE.fullmatch(added) else "—",
                    "due": due if DATE_RE.fullmatch(due) else "—",
                    "ransomware": clean(v.get("knownRansomwareCampaignUse", ""), 10) or "—",
                }
        version = clean(doc.get("catalogVersion", ""), 20)
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        raise ValueError(f"KEV catalog: not the expected JSON ({type(exc).__name__})") from None
    if not entries:
        raise ValueError("KEV catalog: no entries in it")
    return version, entries


# ---- Files -------------------------------------------------------------------------


def download(url: str) -> bytes:
    """GET `url`, trying three times. FileNotFoundError if the server does not have the file."""
    for attempt in (1, 2, 3):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=120) as resp:
                if not resp.url.startswith("https://"):
                    raise ValueError(f"{url}: redirected away from HTTPS")
                data = resp.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ValueError(f"{url}: more than {MAX_BYTES:,} bytes")
            return data
        except urllib.error.HTTPError as exc:
            exc.close()  # an HTTP error is a response too, and holds its connection until closed
            if exc.code in (403, 404):  # the EPSS archive answers 403 for a day it does not have
                raise FileNotFoundError(f"{url}: HTTP {exc.code}") from None
            failure = OSError(f"{url}: HTTP {exc.code}")
            if exc.code != 429 and exc.code < 500:
                raise failure from None  # the request is wrong; asking again will not help
        except (OSError, http.client.HTTPException) as exc:  # no network, timeout, connection cut
            failure = OSError(f"{url}: {exc}")
        if attempt < 3:
            time.sleep(10 * attempt)
    raise failure


def save(path: Path, data: bytes) -> None:
    """Write `data` to `path`: all of it, or nothing."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.part")  # its own name: two runs at once cannot mix their writes
    tmp.write_bytes(data)
    tmp.replace(path)  # a killed run never leaves a truncated file behind


def load(parse, path: Path):
    """Read a file kept on disk and parse it, naming the file if it turns out to be damaged."""
    try:
        return parse(path.read_bytes())
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from None


def epss_file(data_dir: Path, day: str) -> Path:
    return data_dir / f"epss_scores-{day}.csv.gz"


def kev_file(data_dir: Path, day: str) -> Path:
    return data_dir / f"kev-{day}.json.gz"


def cached(data_dir: Path, kind: str) -> list[str]:
    """Days for which a file of this kind ("epss" or "kev") is kept, oldest first."""
    name = {"epss": r"epss_scores-(\d{4}-\d{2}-\d{2})\.csv\.gz", "kev": r"kev-(\d{4}-\d{2}-\d{2})\.json\.gz"}[kind]
    return sorted(m[1] for p in data_dir.glob("*.gz") if (m := re.fullmatch(name, p.name, re.ASCII)))


def kept(data_dir: Path) -> list[str]:
    """The days for which an EPSS file is kept, oldest first. ValueError if there is none yet."""
    days = cached(data_dir, "epss")
    if not days:
        raise ValueError(f"nothing kept in {data_dir} yet; use `run` or `backfill` first")
    return days


def previous(days: list[str], day: str) -> str:
    """The latest of `days` before `day`, or "" if there is none."""
    return max((d for d in days if d < day), default="")


def fetch_epss(data_dir: Path) -> str:
    """Download the current EPSS file and keep it under its own score date. Returns that date."""
    raw = download(EPSS_URL.format("current"))
    day, _, _ = parse_epss(raw)  # nothing is kept that does not parse
    if epss_file(data_dir, day).exists():
        say(f"EPSS {day}: already here")
    else:
        save(epss_file(data_dir, day), raw)
        say(f"EPSS {day}: downloaded")
    return day


def fetch_kev(data_dir: Path, day: str) -> None:
    """Download the KEV catalog and keep it under `day`, replacing an earlier copy from the same day."""
    raw = download(KEV_URL)
    parse_kev(raw)  # nothing is kept that does not parse
    save(kev_file(data_dir, day), gzip.compress(raw, mtime=0))
    say(f"KEV: downloaded, kept under {day}")


def backfill(data_dir: Path, days: int) -> None:
    """Download the EPSS files of the last `days` days that are not here yet. KEV has no archive."""
    if days < 1:
        raise ValueError("backfill: give a number of days, 1 or more")
    today = datetime.now(timezone.utc).date()
    for ago in range(days, 0, -1):
        day = (today - timedelta(days=ago)).isoformat()
        if epss_file(data_dir, day).exists():
            continue
        try:
            raw = download(EPSS_URL.format(day))
            if parse_epss(raw)[0] != day:
                raise ValueError("the file is dated another day")
        except FileNotFoundError:
            say(f"EPSS {day}: not published")
        except ValueError as exc:  # before 2022-02-04 the files carry no model version
            say(f"EPSS {day}: skipped, {exc}")
        else:
            save(epss_file(data_dir, day), raw)
            say(f"EPSS {day}: downloaded")


# ---- The digest --------------------------------------------------------------------


@dataclass
class Day:
    """What the digest of one day says. Filled by compare(), written by render()."""

    date: str
    model: str
    total: int  # CVEs scored
    prev: str = ""  # the earlier EPSS day it is compared with; empty for the first file kept
    prev_model: str = ""
    shifted: float = 0.0  # share of all CVEs that moved by RECAL_DELTA or more
    recalibrated: bool = False
    movers: list = field(default_factory=list)  # (cve, old, new, percentile, levels crossed)
    new: list = field(default_factory=list)  # (cve, epss, percentile)
    kev: dict = field(default_factory=dict)  # the catalog kept that day, {cve: entry}
    kev_version: str = ""
    kev_prev: str = ""  # the earlier catalog it is compared with; empty for the first one kept
    added: list = field(default_factory=list)  # (cve, epss or None)


def compare(data_dir: Path, day: str) -> Day:
    """Compare the files of `day` with the previous ones kept."""
    epss_days = cached(data_dir, "epss")
    if day not in epss_days:
        raise ValueError(f"no EPSS file for {day} in {data_dir}")
    _, model, cur = load(parse_epss, epss_file(data_dir, day))
    r = Day(date=day, model=model, total=len(cur))

    # KEV: what the catalog has that the previous catalog kept did not. The first one is a baseline.
    kev_days = cached(data_dir, "kev")
    if day in kev_days:
        r.kev_version, r.kev = load(parse_kev, kev_file(data_dir, day))
        r.kev_prev = previous(kev_days, day)
        if r.kev_prev:
            _, before = load(parse_kev, kev_file(data_dir, r.kev_prev))
            added = [(c, cur[c][0] if c in cur else None) for c in r.kev.keys() - before.keys()]
            r.added = sorted(added, key=lambda a: (-(a[1] or 0), a[0]))

    r.prev = previous(epss_days, day)
    if not r.prev:
        return r
    _, r.prev_model, old = load(parse_epss, epss_file(data_dir, r.prev))
    common = cur.keys() & old.keys()
    moved = 0
    for c in common:
        o, n = old[c][0], cur[c][0]
        if n == o:
            continue
        rise = round(n - o, 5)  # the feed has five decimals; unrounded, 0.12 - 0.10 is less than 0.02
        moved += abs(rise) >= RECAL_DELTA
        crossed = [lv for lv in LEVELS if o < lv <= n] if rise >= CROSS_MIN else []
        spike = rise >= SPIKE_ABS or (o > 0 and n >= SPIKE_REL_MIN and n / o >= SPIKE_REL)
        if crossed or spike:
            r.movers.append((c, o, n, cur[c][1], crossed))
    r.shifted = moved / max(len(common), 1)
    r.recalibrated = r.prev_model != model or r.shifted >= RECAL_FRACTION
    if r.recalibrated:
        r.movers = []  # every score moved with the model: none of it is about the CVEs
    r.movers.sort(key=lambda m: (-m[2], m[0]))
    # A CVE that was not scored yesterday has no "before" for a recalibration to distort.
    new = [(c, *cur[c]) for c in cur.keys() - old.keys() if cur[c][0] >= NEW_HIGH]
    r.new = sorted(new, key=lambda n: (-n[1], n[0]))
    return r


MASS_SHIFT = (
    "{share:.2%} of all scored CVEs moved by {delta} or more since {prev}. Movement that broad comes "
    "from the model or the data behind it, whatever version the file states."
)
RECALIBRATED = (
    "Day-over-day movement is **not reported today**: a score that moved with the model says nothing "
    "about the CVE. Reporting resumes with the next snapshot, against today's values. KEV additions "
    "and new high-scoring CVEs are unaffected."
)
ABOUT_ADDED = (
    "CISA has evidence of active exploitation: for anything running these products this is no longer "
    "a prediction. The due date is the deadline CISA sets for US federal agencies."
)
ABOUT_MOVERS = (
    "A score rises when the model sees new evidence, such as a public exploit or reports of "
    "exploitation. It is a reason to read the advisory, not a verdict."
)
ABOUT_NEW = f"First scored today, already at or above {NEW_HIGH}: the model sees exploitation signals from day one."
ABOUT = (
    "EPSS is FIRST's daily estimate of the probability that a CVE sees exploitation activity in the "
    "next 30 days. This digest reports *movement* in that estimate, because a score that changes is "
    "telling you something a static score cannot. Movement is a reason to look at the advisory, not "
    "a measure of your exposure."
)


def render(r: Day) -> str:
    """The digest as Markdown. Every string that came from a feed was checked or cleaned when parsed."""

    def link(cve: str) -> str:
        return f"[{cve}]({NVD_URL}{cve})"

    def in_kev(cve: str) -> str:
        return f"since {r.kev[cve]['added']}" if cve in r.kev else "—"

    def top(percentile: float) -> str:
        return f"{(1 - percentile) * 100:.1f}%"

    def count(n: int, noun: str) -> str:
        return f"{n:,} {noun}" + ("" if n == 1 else "s")

    def table(head: str, rows: list[str]) -> list[str]:
        cut = [f"Showing the {MAX_ROWS} highest of {len(rows):,}.", ""] if len(rows) > MAX_ROWS else []
        return [head, "|" + "---|" * (head.count("|") - 1), *rows[:MAX_ROWS], "", *cut]

    lines = [f"# EPSS watch — {r.date}", "", f"EPSS model `{r.model}`, {r.total:,} CVEs scored."]
    if r.kev:
        lines.append(f"CISA KEV catalog `{r.kev_version}`, {len(r.kev):,} entries.")
    lines.append("")

    high = f"{len(r.new):,} new and already high"
    if not r.prev:
        lines.append("- **EPSS:** first file kept, a baseline. Movement is reported from the next one.")
    elif r.recalibrated:
        lines.append(f"- **EPSS since {r.prev}:** model recalibration, movers not reported; {high}.")
    else:
        lines.append(f"- **EPSS since {r.prev}:** {count(len(r.movers), 'mover')}, {high}.")
    if not r.kev:
        lines.append("- **KEV:** no catalog kept for this day.")
    elif not r.kev_prev:
        lines.append("- **KEV:** first catalog kept, a baseline. Additions are reported from the next one.")
    else:
        lines.append(f"- **KEV since {r.kev_prev}:** {count(len(r.added), 'addition')}.")
    lines.append("")

    if r.recalibrated:
        lines += ["## Model recalibration", ""]
        if r.prev_model != r.model:
            lines.append(f"The EPSS model changed from `{r.prev_model}` to `{r.model}`.")
        else:
            lines.append(MASS_SHIFT.format(share=r.shifted, delta=RECAL_DELTA, prev=r.prev))
        lines += ["", RECALIBRATED, ""]
    if r.added:
        rows = []
        for cve, epss in r.added:
            e, score = r.kev[cve], "—" if epss is None else f"{epss:.3f}"
            what = f"{e['vendor']} / {e['product']} | {e['name']}"
            rows.append(f"| {link(cve)} | {what} | {score} | {e['due']} | {e['ransomware']} |")
        head = "| CVE | Vendor / product | Vulnerability | EPSS | Due | Ransomware |"
        lines += ["## Added to CISA KEV", "", *table(head, rows), ABOUT_ADDED, ""]
    if r.movers:
        rows = []
        for cve, old, new, pct, crossed in r.movers:
            change, levels = f"{old:.3f} → {new:.3f} | {new - old:+.3f}", ", ".join(map(str, crossed)) or "—"
            rows.append(f"| {link(cve)} | {change} | {levels} | {top(pct)} | {in_kev(cve)} |")
        head = f"| CVE | EPSS {r.prev} → {r.date} | Δ | Crossed | Top | KEV |"
        lines += ["## Movers", "", *table(head, rows), ABOUT_MOVERS, ""]
    if r.new:
        rows = [f"| {link(cve)} | {epss:.3f} | {top(pct)} | {in_kev(cve)} |" for cve, epss, pct in r.new]
        lines += ["## New and already high", "", *table("| CVE | EPSS | Top | KEV |", rows), ABOUT_NEW, ""]

    source = f"- EPSS: <{EPSS_URL.format(r.date)}>"
    if r.prev:
        source += f", compared with <{EPSS_URL.format(r.prev)}>"
    lines += ["## Sources", "", source]
    if r.kev:
        lines.append(f"- CISA KEV: <{KEV_URL}>")
    lines += ["", "## About these numbers", "", ABOUT, ""]
    return "\n".join(lines)


def digest(data_dir: Path, out_dir: Path, day: str | None = None) -> Path:
    """Write the digest of `day` (default: the newest day kept) and return its path."""
    days = kept(data_dir)
    day = day or days[-1]
    text = render(compare(data_dir, day)).encode()  # compare() refuses a day that is not among the files kept
    save(out_dir / f"{day}.md", text)
    if day == days[-1]:
        save(out_dir / "latest.md", text)
    return out_dir / f"{day}.md"


def history(data_dir: Path, cve: str) -> None:
    """Print the score of one CVE on every day kept. Reads every file, so it takes a moment."""
    cve = cve.strip().upper()
    if not CVE_RE.fullmatch(cve):
        raise ValueError(f"not a CVE id: {cve!r}")
    days = kept(data_dir)
    print("date        epss     percentile")
    for day in days:
        text = load(gunzip, epss_file(data_dir, day)).decode("utf-8", "replace")
        row = re.search(rf"^{cve},([^,\n]+),([^,\n]+)$", text, re.M)
        try:
            print(f"{day}  {float(row[1]):.5f}  {float(row[2]):.5f}")
        except (TypeError, ValueError):
            print(f"{day}  -")  # not scored that day


# ---- Command line ------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="epss_watch.py", description=__doc__.split("\n\n")[1])
    p.add_argument("--data", type=Path, default=HERE / "data",
                   help="where the downloaded files are kept (default: data/ next to this script)")
    p.add_argument("--out", type=Path, default=HERE / "out",
                   help="where the digests are written (default: out/ next to this script)")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="command")
    sub.add_parser("run", help="download today's files and write today's digest (the cron entry)")
    sub.add_parser("backfill", help="download the EPSS files of the last DAYS days").add_argument("days", type=int)
    digest_cmd = sub.add_parser("digest", help="write the digest of a day already kept (default: the newest)")
    digest_cmd.add_argument("date", nargs="?")
    sub.add_parser("history", help="print one CVE's score on every day kept").add_argument("cve")
    a = p.parse_args(argv)
    try:
        if a.cmd == "run":
            day = fetch_epss(a.data)
            try:
                fetch_kev(a.data, day)
            finally:  # KEV out of reach is reported below, but is no reason to hold back what EPSS says
                print(digest(a.data, a.out, day))
        elif a.cmd == "backfill":
            backfill(a.data, a.days)
        elif a.cmd == "digest":
            print(digest(a.data, a.out, a.date))
        else:
            history(a.data, a.cve)
    except (OSError, ValueError) as exc:  # network, disk, or a file that is not what it should be
        say(f"epss-watch: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
