"""python3 -m unittest            (from this directory; no network, no dependencies)"""

import contextlib
import gzip
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import epss_watch as ew

# Enough CVEs that do not move to keep a handful of movers under RECAL_FRACTION, as in the real feed.
QUIET = {f"CVE-2000-{i:05d}": 0.001 for i in range(10_000)}


def epss_bytes(day: str, model: str, scores: dict, head: str = "") -> bytes:
    rows = [head or f"#model_version:{model},score_date:{day}T12:00:00Z", "cve,epss,percentile"]
    rows += [f"{c},{s:.5f},{min(0.999, s * 1.2):.5f}" for c, s in scores.items()]
    return gzip.compress("\n".join(rows).encode())


def kev_bytes(version: str, cves: list, **fields) -> bytes:
    entry = {"vendorProject": "Example", "product": "Thing", "vulnerabilityName": "Example Thing Bug",
             "dateAdded": "2026-01-01", "dueDate": "2026-01-22", "knownRansomwareCampaignUse": "Unknown"}
    vulns = [{**entry, **fields, "cveID": c} for c in cves]
    return json.dumps({"catalogVersion": version, "vulnerabilities": vulns}).encode()


class Case(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.data, self.out = Path(tmp.name) / "data", Path(tmp.name) / "out"
        self.data.mkdir()
        sleep = mock.patch.object(ew.time, "sleep")  # retries must not slow the tests down
        self.sleep = sleep.start()
        self.addCleanup(sleep.stop)

    def put_epss(self, day, model, scores):
        ew.epss_file(self.data, day).write_bytes(epss_bytes(day, model, scores))

    def put_kev(self, day, version, cves, **fields):
        ew.kev_file(self.data, day).write_bytes(gzip.compress(kev_bytes(version, cves, **fields)))

    def render(self, day):
        return ew.digest(self.data, self.out, day).read_text(encoding="utf-8")


class Parsing(Case):
    """Everything downloaded is data. These are the checks that keep it that way."""

    def test_the_date_in_the_header_must_be_a_real_date(self):
        # The date names the file the download is saved under, so a hostile one must never get that far.
        for head in ("#model_version:v1,score_date:../../../x", "#model_version:v1,score_date:2026-13-45",
                     "#score_date:2026-01-01", "cve,epss,percentile"):
            with self.assertRaises(ValueError, msg=head):
                ew.parse_epss(epss_bytes("2026-01-01", "v1", {"CVE-2026-0001": 0.5}, head=head))

    def test_rows_that_are_not_scores_are_dropped(self):
        rows = ["#model_version:v1,score_date:2026-01-01T00:00:00Z", "cve,epss,percentile",
                "CVE-2026-0001,0.5,0.9", "CVE-2026-0002,4.3e-4,0.1", "CVE-2026-0003<script>,0.5,0.9",
                "CVE-2026-0004,nan,0.9", "CVE-2026-0005,1.5,0.9", "CVE-2026-0006,0.5", "[x](y),0.5,0.9", "",
                "CVE-２０２６-0007,0.5,0.9",  # fullwidth digits: not an id anyone can look up
                "CVE-2026-١٢٣٤,0.5,0.9",  # nor Arabic-Indic ones
                "CVE-2026-" + "8" * 5000 + ",0.5,0.9",        # nor five thousand of them
                '"' + "A," * 200_000]                         # one 400 kB line with an open quote
        day, model, scores = ew.parse_epss(gzip.compress("\n".join(rows).encode()))
        self.assertEqual((day, model), ("2026-01-01", "v1"))
        self.assertEqual(scores, {"CVE-2026-0001": (0.5, 0.9), "CVE-2026-0002": (0.00043, 0.1)})
        with self.assertRaises(ValueError):
            ew.parse_epss(gzip.compress("\n".join(rows[:2]).encode()))  # a header and nothing else

    def test_the_model_version_is_kept_short_and_plain(self):
        # It is printed in every digest, so it gets no room for markup, hidden letters or a novel.
        for stated, kept in (("v2026.06.15", "v2026.06.15"), ("v2\u3164א<b>`x`", "v2"), ("9" * 500, "9" * 40)):
            head = f"#model_version:{stated},score_date:2026-01-01T00:00:00Z"
            self.assertEqual(ew.parse_epss(epss_bytes("", "", {"CVE-2026-0001": 0.5}, head=head))[1], kept)

    def test_what_is_not_gzip_or_is_too_large_is_refused(self):
        for junk in (b"<html>503</html>", b"", gzip.compress(b"x" * 100)[:-8]):
            with self.assertRaises(ValueError):
                ew.parse_epss(junk)
        # Larger than allowed: refused outright, not read up to the limit and passed off as the whole file.
        with mock.patch.object(ew, "MAX_BYTES", 500), self.assertRaisesRegex(ValueError, "unpacks to more than 500"):
            ew.parse_epss(epss_bytes("2026-01-01", "v1", QUIET))

    def test_kev_text_cannot_carry_markup_into_the_digest(self):
        hostile = kev_bytes(
            "v|1`", ["CVE-2026-0001", "CVE-1 | <b>", "[x](https://evil.example)"],
            vendorProject="Evil | Corp", product="<script>alert(1)</script>",
            vulnerabilityName="[click](https://evil.example) ![i](x) \u202E`code`\nnew line www.Evil.example " + "A" * 200,
            dateAdded="<b>", dueDate="soon",
        )
        version, entries = ew.parse_kev(hostile)
        self.assertEqual(list(entries), ["CVE-2026-0001"])  # ids that are not CVE ids are dropped
        e = entries["CVE-2026-0001"]
        self.assertEqual((e["vendor"], e["product"], e["added"], e["due"]), ("Evil Corp", "script alert(1) /script", "—", "—"))
        self.assertTrue(e["name"].startswith("click (https //evil.example) !") and e["name"].endswith("…"), e["name"])
        self.assertEqual(len(e["name"]), 100)
        for text in (version, *e.values()):
            self.assertNotRegex(text, r"[|<>\[\]`:\n\u202E]|www\.")
        deep = b"[" * 100_000 + b"]" * 100_000
        for junk in (b"not json", b"[]", b'{"vulnerabilities": [1]}', b'{"vulnerabilities": []}', deep):
            with self.assertRaises(ValueError):
                ew.parse_kev(junk)

    def test_kev_text_cannot_hide_anything_either(self):
        for raw, cleaned in {
            "Acme\u3164\u115FCorp": "Acme Corp",  # Hangul fillers: letters that render as nothing
            "Мiсrоsоft": "i r s ft",  # Cyrillic look-alikes of M, c and o
            "abc אבג def": "abc def",  # right-to-left letters
            "v١٢٣": "v",  # digits from another script
            "a\u200Bb\u202Ec": "a b c",  # zero-width space, direction override
            "＜script＞": "script",  # fullwidth < and >
            "Crème Brûlée": "Creme Brulee",  # an accent is dropped, its letter stays
            "Thingwww.evil.example (WWW.x.y)": "Thingwww evil.example (WWW x.y)",  # nothing GitHub would link
        }.items():
            self.assertEqual(ew.clean(raw), cleaned, ascii(raw))


class Digest(Case):
    def test_first_snapshot_is_a_baseline(self):
        self.put_epss("2026-01-01", "v1", {"CVE-2026-0001": 0.9})
        self.put_kev("2026-01-01", "k1", ["CVE-2026-0001"])
        text = self.render("2026-01-01")
        self.assertIn("- **EPSS:** first file kept, a baseline.", text)
        self.assertIn("- **KEV:** first catalog kept, a baseline.", text)
        for section in ("## Movers", "## New and already high", "## Added to CISA KEV"):
            self.assertNotIn(section, text)
        self.assertEqual(text, (self.out / "latest.md").read_text(encoding="utf-8"))

    def test_movement_rules(self):
        self.put_epss("2026-01-01", "v1", QUIET | {
            "CVE-2026-0001": 0.05,   # crosses 0.1 and 0.5 -> mover
            "CVE-2026-0002": 0.30,   # +0.15 -> spike, no level crossed
            "CVE-2026-0003": 0.01,   # x6 to 0.06 -> relative spike
            "CVE-2026-0004": 0.20,   # +0.04 -> nothing
            "CVE-2026-0005": 0.80,   # falls -> nothing
            "CVE-2026-0006": 0.002,  # x5 but below SPIKE_REL_MIN -> nothing
            "CVE-2026-0009": 0.098,  # crosses 0.1 by 0.003 -> jitter, nothing
            "CVE-2026-0010": 0.082,  # crosses 0.1 by exactly CROSS_MIN -> mover, though 0.102 - 0.082 < 0.02 in floats
            "CVE-2026-0011": 0.20,   # rises by exactly SPIKE_ABS -> mover, though 0.30 - 0.20 < 0.10 in floats
        })
        self.put_epss("2026-01-02", "v1", QUIET | {
            "CVE-2026-0001": 0.60, "CVE-2026-0002": 0.45, "CVE-2026-0003": 0.06, "CVE-2026-0004": 0.24,
            "CVE-2026-0005": 0.10, "CVE-2026-0006": 0.010, "CVE-2026-0009": 0.101, "CVE-2026-0010": 0.102,
            "CVE-2026-0011": 0.30,
            "CVE-2026-0007": 0.50,   # new, high -> listed
            "CVE-2026-0008": 0.02,   # new, low -> not listed
        })
        self.put_kev("2026-01-01", "k1", ["CVE-2026-0005"])
        self.put_kev("2026-01-02", "k2", ["CVE-2026-0005", "CVE-2026-0001"])
        text = self.render("2026-01-02")
        self.assertIn("- **EPSS since 2026-01-01:** 5 movers, 1 new and already high.", text)
        self.assertIn("- **KEV since 2026-01-01:** 1 addition.", text)
        movers = text.split("## Movers")[1].split("## New")[0]
        self.assertIn("| [CVE-2026-0001](https://nvd.nist.gov/vuln/detail/CVE-2026-0001) | 0.050 → 0.600 | +0.550 | 0.1, 0.5 |", movers)
        self.assertEqual([ln.split("]")[0][3:] for ln in movers.splitlines() if ln.startswith("| [")],
                         ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0011", "CVE-2026-0010", "CVE-2026-0003"])  # by score
        self.assertIn("since 2026-01-01", movers)  # CVE-2026-0001 is now in KEV
        self.assertIn("| [CVE-2026-0007]", text.split("## New and already high")[1])
        self.assertNotIn("CVE-2026-0008", text)
        added = text.split("## Added to CISA KEV")[1].split("## Movers")[0]
        self.assertIn("| Example / Thing | Example Thing Bug | 0.600 | 2026-01-22 | Unknown |", added)

    def test_model_change_suppresses_movement(self):
        # One CVE in 10,000 moves, far under RECAL_FRACTION: only the version in the header gives it away.
        self.put_epss("2026-01-01", "v1", QUIET | {"CVE-2026-0001": 0.05, "CVE-2026-0002": 0.3})
        self.put_epss("2026-01-02", "v2", QUIET | {"CVE-2026-0001": 0.60, "CVE-2026-0002": 0.3, "CVE-2026-0003": 0.7})
        text = self.render("2026-01-02")
        self.assertIn("model recalibration, movers not reported; 1 new and already high.", text)
        self.assertIn("The EPSS model changed from `v1` to `v2`.", text)
        self.assertNotIn("## Movers", text)
        self.assertIn("| [CVE-2026-0003]", text)  # new CVEs are still reported

    def test_mass_shift_is_a_recalibration_too(self):
        # Same model version, but 20 CVEs in 10,000 jump together: 0.20%, twice RECAL_FRACTION.
        self.put_epss("2026-01-01", "v1", QUIET)
        self.put_epss("2026-01-02", "v1", QUIET | {c: 0.30 for c in list(QUIET)[:20]})
        text = self.render("2026-01-02")
        self.assertIn("model recalibration, movers not reported", text)
        self.assertIn("0.20% of all scored CVEs moved by 0.05 or more since 2026-01-01.", text)
        self.assertNotIn("## Movers", text)
        # Nine in 10,000 is under it: an ordinary busy day, reported as such.
        self.put_epss("2026-01-02", "v1", QUIET | {c: 0.30 for c in list(QUIET)[:9]})
        self.assertIn("- **EPSS since 2026-01-01:** 9 movers,", self.render("2026-01-02"))

    def test_each_feed_is_compared_with_the_previous_file_kept_whatever_its_date(self):
        self.put_epss("2026-01-01", "v1", QUIET | {"CVE-2026-0001": 0.05})
        self.put_epss("2026-01-04", "v1", QUIET | {"CVE-2026-0001": 0.05})
        self.put_epss("2026-01-05", "v1", QUIET | {"CVE-2026-0001": 0.60})
        self.put_kev("2026-01-01", "k1", ["CVE-2026-0002"])
        self.put_kev("2026-01-05", "k2", ["CVE-2026-0002", "CVE-2026-0003"])
        text = self.render("2026-01-05")
        self.assertIn("- **EPSS since 2026-01-04:** 1 mover,", text)
        self.assertIn("- **KEV since 2026-01-01:** 1 addition.", text)
        self.assertIn("| [CVE-2026-0003](https://nvd.nist.gov/vuln/detail/CVE-2026-0003) | Example / Thing | Example Thing Bug | — |", text)
        text = self.render("2026-01-04")
        self.assertIn("- **EPSS since 2026-01-01:** 0 movers,", text)
        self.assertIn("- **KEV:** no catalog kept for this day.", text)
        self.assertIn("2026-01-05", (self.out / "latest.md").read_text(encoding="utf-8"))  # an older day leaves it alone

    def test_a_long_table_is_cut_and_says_so(self):
        self.put_epss("2026-01-01", "v1", QUIET)
        self.put_epss("2026-01-02", "v1", QUIET | {f"CVE-2026-{i:04d}": 0.2 + i / 100 for i in range(5)})
        with mock.patch.object(ew, "MAX_ROWS", 2):
            text = self.render("2026-01-02")
        self.assertIn("5 new and already high", text)
        self.assertEqual(text.count("\n| [CVE-"), 2)
        self.assertIn("| [CVE-2026-0004]", text)  # the highest are the ones kept
        self.assertIn("Showing the 2 highest of 5.", text)

    def test_the_same_files_always_give_the_same_digest(self):
        # Equal scores: only the id can order the rows, in both tables.
        movers = {f"CVE-2025-{i:04d}": 0.3 for i in range(8)}
        new = {f"CVE-2026-{i:04d}": 0.3 for i in range(40)}
        self.put_epss("2026-01-01", "v1", QUIET | dict.fromkeys(movers, 0.01))
        self.put_epss("2026-01-02", "v1", QUIET | movers | new)
        text = self.render("2026-01-02")
        listed = [ln.split("]")[0][3:] for ln in text.splitlines() if ln.startswith("| [")]
        self.assertEqual(listed, sorted(movers) + sorted(new))
        self.assertNotIn("Showing", text)

    def test_a_damaged_file_is_named(self):
        self.put_epss("2026-01-01", "v1", QUIET)
        ew.epss_file(self.data, "2026-01-02").write_bytes(b"\x1f\x8b cut short")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            for args in (["digest"], ["history", "CVE-2026-0001"]):
                self.assertEqual(ew.main(["--data", str(self.data), "--out", str(self.out), *args]), 1)
        self.assertEqual(err.getvalue().count("epss_scores-2026-01-02.csv.gz: not a gzip file"), 2)

    def test_what_cannot_be_done_is_said_in_one_line(self):
        err, where = io.StringIO(), ["--data", str(self.data), "--out", str(self.out)]
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            for args in (["digest"], ["history", "CVE-2026-0001"]):  # nothing kept yet
                self.assertEqual(ew.main([*where, *args]), 1, args)
            self.put_epss("2026-01-01", "v1", QUIET)
            for args in (["digest", "2026-01-02"], ["digest", "../../etc/passwd"], ["history", "CVE-1; rm"], ["backfill", "0"]):
                self.assertEqual(ew.main([*where, *args]), 1, args)
        self.assertEqual(err.getvalue().count("\n"), 6)
        self.assertEqual(err.getvalue().count("epss-watch: nothing kept in"), 2)
        self.assertNotIn("Traceback", err.getvalue())
        for day in ("2026-01-02", "../../etc/passwd"):  # turned away by name, before any file is looked for
            self.assertIn(f"epss-watch: no EPSS file for {day} in", err.getvalue())
        self.assertFalse(self.out.exists())


class Network(Case):
    def serve(self, responses):
        """Patch download() with a dict of url -> bytes, or -> an exception to raise."""
        def fake(url):
            if url not in responses:
                raise FileNotFoundError(url)
            if isinstance(responses[url], Exception):
                raise responses[url]
            return responses[url]
        patch = mock.patch.object(ew, "download", side_effect=fake)
        patch.start()
        self.addCleanup(patch.stop)

    def test_run_keeps_both_feeds_under_the_epss_score_date(self):
        self.serve({ew.EPSS_URL.format("current"): epss_bytes("2026-03-04", "v1", {"CVE-2026-0001": 0.5}),
                    ew.KEV_URL: kev_bytes("k1", ["CVE-2026-0001"])})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            for _ in range(2):  # a second run the same day is harmless
                self.assertEqual(ew.main(["--data", str(self.data), "--out", str(self.out), "run"]), 0)
        self.assertEqual((ew.cached(self.data, "epss"), ew.cached(self.data, "kev")), (["2026-03-04"], ["2026-03-04"]))
        self.assertEqual(out.getvalue().split(), [str(self.out / "2026-03-04.md")] * 2)
        self.assertIn("EPSS 2026-03-04: already here", err.getvalue())

    def test_a_download_that_does_not_check_out_is_not_kept(self):
        good_epss, good_kev = epss_bytes("2026-03-04", "v1", {"CVE-2026-0001": 0.5}), kev_bytes("k1", ["CVE-2026-0001"])
        hostile = epss_bytes("", "v1", {"CVE-2026-0001": 0.5}, head="#model_version:v1,score_date:../../../x")
        run = ["--data", str(self.data), "--out", str(self.out), "run"]
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            for epss in (hostile, b"<html>"):
                self.serve({ew.EPSS_URL.format("current"): epss, ew.KEV_URL: good_kev})
                self.assertEqual(ew.main(run), 1)
            self.assertEqual([p for p in self.data.parent.rglob("*") if p.is_file()], [])  # no date, so nothing at all
            for kev in (b"<html>", OSError("bad \x1b[2J gateway")):
                self.serve({ew.EPSS_URL.format("current"): good_epss, ew.KEV_URL: kev})
                self.assertEqual(ew.main(run), 1)  # the failure is reported ...
        self.assertEqual((ew.cached(self.data, "epss"), ew.cached(self.data, "kev")), (["2026-03-04"], []))
        digest = (self.out / "latest.md").read_text(encoding="utf-8")  # ... and what EPSS says is written anyway
        self.assertIn("- **KEV:** no catalog kept for this day.", digest)
        self.assertIn("epss-watch: bad ?[2J gateway", err.getvalue())  # an error cannot drive the terminal it lands in
        self.assertNotIn("\x1b", err.getvalue())
        self.assertEqual([p.name for p in self.data.iterdir()], ["epss_scores-2026-03-04.csv.gz"])  # no stray .part

    def test_backfill_skips_what_is_missing_or_unreadable_and_goes_on(self):
        today = ew.datetime.now(ew.timezone.utc).date()
        day = [(today - ew.timedelta(days=n)).isoformat() for n in range(7)]
        self.put_epss(day[5], "v1", QUIET)  # already here: not asked for again
        self.serve({                        # day[6] is not served at all: the archive answers 403
            ew.EPSS_URL.format(day[4]): epss_bytes(day[4], "v1", QUIET),
            ew.EPSS_URL.format(day[3]): gzip.compress(b"cve,epss,percentile\nCVE-2021-0001,0.5,0.9"),  # the 2021 format
            ew.EPSS_URL.format(day[2]): epss_bytes("2020-01-01", "v1", QUIET),  # dated another day
            ew.EPSS_URL.format(day[1]): epss_bytes(day[1], "v1", QUIET),
        })
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            ew.backfill(self.data, 6)
        self.assertEqual(ew.cached(self.data, "epss"), [day[5], day[4], day[1]])
        self.assertEqual(ew.download.call_count, 5)
        self.assertEqual((err.getvalue().count("not published"), err.getvalue().count("skipped")), (1, 2))
        self.serve({ew.EPSS_URL.format(day[1]): OSError("network is down")})
        ew.epss_file(self.data, day[1]).unlink()
        with self.assertRaises(OSError), contextlib.redirect_stderr(err):
            ew.backfill(self.data, 1)  # a real failure stops the run; running it again resumes

    def test_download_retries_what_may_pass_and_gives_up_on_what_will_not(self):
        class Response(io.BytesIO):
            url = "https://example.org/x"

        def http_error(code):
            return urllib.error.HTTPError("https://example.org/x", code, "no", None, io.BytesIO())

        with mock.patch.object(ew.urllib.request, "urlopen") as urlopen:
            urlopen.side_effect = [http_error(503), TimeoutError("timed out"), Response(b"body")]
            self.assertEqual(ew.download("https://example.org/x"), b"body")
            self.assertEqual((urlopen.call_count, self.sleep.call_count), (3, 2))
            self.assertEqual(urlopen.call_args[0][0].get_header("User-agent"), ew.USER_AGENT)

            urlopen.side_effect = [http_error(500)] * 3
            with self.assertRaisesRegex(OSError, "example.org/x: HTTP 500"):
                ew.download("https://example.org/x")

            for code, error in ((403, FileNotFoundError), (404, FileNotFoundError), (400, OSError)):
                urlopen.reset_mock()
                urlopen.side_effect = [http_error(code)]
                with self.assertRaises(error):
                    ew.download("https://example.org/x")
                self.assertEqual(urlopen.call_count, 1, code)  # asking again would not help

            plain = Response(b"body")
            plain.url = "http://example.org/x"
            urlopen.side_effect = [plain]
            with self.assertRaisesRegex(ValueError, "redirected away from HTTPS"):
                ew.download("https://example.org/x")
            urlopen.side_effect = [Response(b"x" * 11)]
            with mock.patch.object(ew, "MAX_BYTES", 10), self.assertRaisesRegex(ValueError, "more than 10 bytes"):
                ew.download("https://example.org/x")

    def test_history_prints_one_line_per_day_kept(self):
        self.put_epss("2026-01-01", "v1", {"CVE-2026-00012": 0.9, "CVE-2026-0001": 0.25})  # the longer id first: not a match
        self.put_epss("2026-01-02", "v1", {"CVE-2026-0002": 0.5})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            ew.history(self.data, " cve-2026-0001 ")
        self.assertEqual(out.getvalue().splitlines()[1:], ["2026-01-01  0.25000  0.30000", "2026-01-02  -"])


if __name__ == "__main__":
    unittest.main()
