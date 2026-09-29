"""Tests for emit_akcm_entry.py, written before the implementation (test-first).

Pins the gate this whole redo exists for: a mechanism claim with no expert-verify execution
record is NOT an attested mapping. dispatch_domain.ts's CONTRIBUTE/SYNTHESIZE/REVIEW loop
produces a reviewed CANDIDATE (ssm-mapping-run + expert-counter + mapping-consensus) but does
not itself execute anything on a real kernel (expert-verify is a separate, not-yet-wired step
using the QEMU runner) -- so without an --execution-records file, entries must land as
`asserted`/quarantined under catalog/_unattested/, never `attested` in catalog/ proper.
"""
import tempfile
import unittest
from pathlib import Path

import emit_akcm_entry as eae

PROVENANCE_ARGS = dict(
    selection_record="sel-2026-07-aicm-kernel-primitives",
    delivery_brief="brief-2026-07-akcm",
    engine="secid:methodology/cloudsecurityalliance.org/control-to-capability",
    factory_commit="c48b99d",
    run_id="run-2026-07-30-uem",
    date="2026-07-30",
)


def _synthesis(control_id="UEM-10"):
    return {
        "aicm_control_id": control_id,
        "atf_pillar": "identity",
        "kernel_baseline": "6.12",
        "gap": False,
        "primitives": [{
            "primitive": "landlock",
            "mechanism": "LANDLOCK_CREATE_RULESET network rule",
            "min_kernel": "6.7",
            "role": "primary",
            "citation": "https://docs.kernel.org/userspace-api/landlock.html#network-rules",
        }],
        "rationale": "Landlock can restrict outbound TCP connect() per port at the kernel layer.",
        "workflow": "agent action -> connect() -> LSM hook -> landlock ruleset -> allow/deny",
        "notes": "Reviewer independence: 6 harnesses share account, image, model.",
    }


def _gap_synthesis(control_id="GRC-05"):
    return {
        "aicm_control_id": control_id,
        "atf_pillar": "data_governance",
        "kernel_baseline": "6.12",
        "gap": True,
        "gap_reason": "No kernel decision point mediates a governance policy-authorship control.",
        "rationale": "Policy authorship is not a kernel-mediated action.",
        "workflow": "no decision point: policy authorship happens outside any syscall boundary",
        "notes": "",
    }


def _reviews(control_id="UEM-10"):
    return {
        control_id: {
            "consensus": "consensus",
            "status": "locked",
            "reviewers": [
                {"id": "reviewer:landlock", "verdict": "concur", "date": "2026-07-30", "notes": "holds"},
                {"id": "reviewer:seccomp", "verdict": "concur", "date": "2026-07-30", "notes": "holds"},
            ],
        }
    }


def _execution_records(control_id="UEM-10"):
    return {
        control_id: {
            "landlock": {
                "kernel_release": "6.8.0-136-generic",
                "kernel_arch": "aarch64",
                "probe": "landlock-abi",
                "observed": "4",
                "runner": "qemu",
            }
        }
    }


class EmitAkcmEntryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.catalog = Path(self.tmp.name) / "catalog"
        self.catalog.mkdir()
        self.known_controls = {"UEM-10": {"domain": "Universal Endpoint Management", "title": "Software Firewall"},
                                "GRC-05": {"domain": "Governance, Risk and Compliance", "title": "Some Control"}}

    def tearDown(self):
        self.tmp.cleanup()

    def test_with_execution_record_writes_attested_entry(self):
        path, errors = eae.emit(
            _synthesis(), _reviews(), self.known_controls, self.catalog,
            execution_records=_execution_records(), **PROVENANCE_ARGS,
        )
        self.assertEqual(errors, [])
        self.assertTrue(path.exists())
        self.assertIn("catalog/uem-10.yaml", str(path).replace(str(self.tmp.name), "").lstrip("/"))
        text = path.read_text()
        self.assertIn("attestation_state: attested", text)
        self.assertIn("min_kernel_basis: measured", text)
        self.assertIn("kernel_release: \"6.8.0-136-generic\"", text)

    def test_without_execution_record_writes_asserted_entry_to_unattested_dir(self):
        """The exact gate the retracted run skipped: no execution record means it is
        asserted, not mapped, and must never sit beside attested entries."""
        path, errors = eae.emit(
            _synthesis(), _reviews(), self.known_controls, self.catalog,
            execution_records=None, **PROVENANCE_ARGS,
        )
        self.assertEqual(errors, [])
        self.assertIn("_unattested", str(path))
        text = path.read_text()
        self.assertIn("attestation_state: asserted", text)

    def test_gap_entry_needs_no_execution_record(self):
        gap_reviews = {"GRC-05": _reviews()["UEM-10"]}
        path, errors = eae.emit(
            _gap_synthesis(), gap_reviews, self.known_controls, self.catalog,
            execution_records=None, **PROVENANCE_ARGS,
        )
        self.assertEqual(errors, [])
        text = path.read_text()
        self.assertIn("attestation_state: attested", text)
        self.assertIn("gap: true", text)

    def test_unknown_control_id_is_refused(self):
        syn = _synthesis("NOT-A-REAL-CONTROL")
        path, errors = eae.emit(
            syn, _reviews("NOT-A-REAL-CONTROL"), self.known_controls, self.catalog,
            execution_records=None, **PROVENANCE_ARGS,
        )
        self.assertIsNone(path)
        self.assertTrue(any("not in" in e or "register" in e for e in errors))

    def test_existing_file_refuses_overwrite_by_default(self):
        eae.emit(_synthesis(), _reviews(), self.known_controls, self.catalog,
                  execution_records=_execution_records(), write=True, **PROVENANCE_ARGS)
        path, errors = eae.emit(
            _synthesis(), _reviews(), self.known_controls, self.catalog,
            execution_records=_execution_records(), write=True, **PROVENANCE_ARGS,
        )
        self.assertIsNone(path)
        self.assertTrue(any("already exists" in e for e in errors))

    def test_check_mode_does_not_write(self):
        path, errors = eae.emit(
            _synthesis(), _reviews(), self.known_controls, self.catalog,
            execution_records=_execution_records(), write=False, **PROVENANCE_ARGS,
        )
        self.assertEqual(errors, [])
        self.assertFalse(path.exists())

    def test_promoting_asserted_to_attested_removes_the_stale_quarantined_copy(self):
        """A live re-emit surfaced this: writing UEM-10 attested (now that an execution
        record exists) left the old asserted copy sitting in catalog/_unattested/ too --
        both would validate individually but check_register flags it as a duplicate
        aicm_control_id, and worse, a reader could find the stale unattested one first."""
        path1, errors1 = eae.emit(
            _synthesis(), _reviews(), self.known_controls, self.catalog,
            execution_records=None, **PROVENANCE_ARGS,
        )
        self.assertEqual(errors1, [])
        self.assertIn("_unattested", str(path1))
        self.assertTrue(path1.exists())

        path2, errors2 = eae.emit(
            _synthesis(), _reviews(), self.known_controls, self.catalog,
            execution_records=_execution_records(), overwrite=True, **PROVENANCE_ARGS,
        )
        self.assertEqual(errors2, [])
        self.assertNotIn("_unattested", str(path2))
        self.assertFalse(path1.exists(), "stale _unattested copy must be removed once promoted")

    def test_demoting_attested_to_asserted_removes_the_stale_attested_copy(self):
        """The reverse direction: re-emitting without execution records (or after one is
        retracted) must not leave a stale attested copy sitting beside the new asserted one."""
        path1, errors1 = eae.emit(
            _synthesis(), _reviews(), self.known_controls, self.catalog,
            execution_records=_execution_records(), **PROVENANCE_ARGS,
        )
        self.assertEqual(errors1, [])
        self.assertNotIn("_unattested", str(path1))

        path2, errors2 = eae.emit(
            _synthesis(), _reviews(), self.known_controls, self.catalog,
            execution_records=None, overwrite=True, **PROVENANCE_ARGS,
        )
        self.assertEqual(errors2, [])
        self.assertIn("_unattested", str(path2))
        self.assertFalse(path1.exists(), "stale attested copy must be removed once demoted")

    def test_reviews_lookup_is_case_insensitive_to_control_id(self):
        """buildReviewsJson (rr_aicm_round.ts) lowercases the stem for its keys ('uem-10'),
        while synthesis.json keeps the register's real casing ('UEM-10') -- a live dispatch
        run surfaced this exact mismatch. The lookup must not silently refuse every real entry."""
        lowercase_reviews = {"uem-10": _reviews()["UEM-10"]}
        path, errors = eae.emit(
            _synthesis(), lowercase_reviews, self.known_controls, self.catalog,
            execution_records=_execution_records(), **PROVENANCE_ARGS,
        )
        self.assertEqual(errors, [])
        self.assertIsNotNone(path)

    def test_emitted_entry_passes_the_real_validator(self):
        """Round-trip: whatever this writes must pass check_catalog_entries.py, not just
        this module's own opinion of itself. That validator lives in this same repo's
        scripts/ directory (../scripts relative to this file)."""
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
        import importlib
        cce = importlib.import_module("check_catalog_entries")
        import yaml

        path, errors = eae.emit(
            _synthesis(), _reviews(), self.known_controls, self.catalog,
            execution_records=_execution_records(), write=True, **PROVENANCE_ARGS,
        )
        self.assertEqual(errors, [])
        entry = yaml.safe_load(path.read_text())
        violations = cce.check_entry(entry, str(path))
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()


def _two_primitive_synthesis(control_id="UEM-10"):
    syn = _synthesis(control_id)
    syn["primitives"].append({
        "primitive": "seccomp",
        "mechanism": "SECCOMP_RET_LOG writes an audit record per filtered syscall",
        "role": "supporting",
        "citation": "https://docs.kernel.org/userspace-api/seccomp_filter.html#return-values",
    })
    return syn


class PerPrimitiveExecutionTests(unittest.TestCase):
    """mEllergrace/AKCM-Mappings#1, #2, #3: execution was recorded for primitives[0] only,
    kernel_baseline defaulted to an unmeasured 6.12, and the validator gate was documented
    but never called."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.catalog = Path(self.tmp.name) / "catalog"
        self.catalog.mkdir()
        self.known = {"UEM-10": {"domain": "Universal Endpoint Management", "title": "Software Firewall"}}

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_primitive_without_its_own_record_keeps_the_entry_unattested(self):
        path, errors = eae.emit(_two_primitive_synthesis(), _reviews(), self.known, self.catalog,
                                execution_records=_execution_records(), **PROVENANCE_ARGS)
        self.assertEqual(errors, [])
        self.assertIn("_unattested", str(path))
        self.assertIn("attestation_state: asserted", path.read_text())

    def test_every_primitive_carries_its_own_execution_block_when_all_were_executed(self):
        recs = _execution_records()
        recs["UEM-10"]["seccomp"] = {"kernel_release": "6.8.0-142-generic", "kernel_arch": "aarch64",
                                     "probe": "akcm-wall:UEM-10:seccomp:x", "observed": "audit: type=1326 ...",
                                     "runner": "qemu"}
        path, errors = eae.emit(_two_primitive_synthesis(), _reviews(), self.known, self.catalog,
                                execution_records=recs, **PROVENANCE_ARGS)
        self.assertEqual(errors, [])
        self.assertNotIn("_unattested", str(path))
        import yaml

        entry = yaml.safe_load(path.read_text())
        self.assertEqual([p["execution"]["kernel_release"] for p in entry["primitives"]],
                         ["6.8.0-136-generic", "6.8.0-142-generic"])
        # the top-level block is kept for existing readers
        self.assertEqual(entry["provenance"]["execution"]["kernel_release"], "6.8.0-136-generic")

    def test_kernel_baseline_is_not_defaulted_to_an_unmeasured_version(self):
        syn = _synthesis()
        del syn["kernel_baseline"]
        path, _ = eae.emit(syn, _reviews(), self.known, self.catalog,
                           execution_records=_execution_records(), **PROVENANCE_ARGS)
        self.assertIn('kernel_baseline: "6.8.0-136-generic"', path.read_text())
        self.assertNotIn("6.12", path.read_text())

    def test_an_explicit_kernel_baseline_is_still_honoured(self):
        path, _ = eae.emit(_synthesis(), _reviews(), self.known, self.catalog,
                           execution_records=_execution_records(), **PROVENANCE_ARGS)
        self.assertIn('kernel_baseline: "6.12"', path.read_text())

    def test_emit_refuses_an_entry_the_validator_rejects(self):
        syn = _synthesis()
        syn["primitives"][0]["mechanism"] = "too short"  # passes validate_synthesis, fails MIN_TEXT
        path, errors = eae.emit(syn, _reviews(), self.known, self.catalog,
                                execution_records=_execution_records(), **PROVENANCE_ARGS)
        self.assertIsNone(path)
        self.assertTrue(any("check_catalog_entries" in e for e in errors), errors)
        self.assertEqual(list(self.catalog.rglob("*.yaml")), [])


class ClaimFixTests(unittest.TestCase):
    """#8 (replace atf_pillar with an AKCM-native field), #2 (baseline from execution), #6/#9
    (evidence-derived caveats appended to notes)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.catalog = Path(self.tmp.name) / "catalog"
        self.catalog.mkdir()
        self.known = {"UEM-10": {"domain": "Universal Endpoint Management", "title": "Software Firewall"}}

    def tearDown(self):
        self.tmp.cleanup()

    def _emit(self, syn=None, **kw):
        return eae.emit(syn or _synthesis(), _reviews(), self.known, self.catalog,
                        execution_records=_execution_records(), **PROVENANCE_ARGS, **kw)

    def test_entry_carries_aicm_domain_from_the_register_not_atf_pillar(self):
        import yaml

        path, errors = self._emit()
        self.assertEqual(errors, [])
        entry = yaml.safe_load(path.read_text())
        self.assertEqual(entry["aicm_domain"], "Universal Endpoint Management")
        self.assertNotIn("atf_pillar", entry)

    def test_synthesis_without_atf_pillar_is_accepted(self):
        syn = _synthesis()
        del syn["atf_pillar"]
        path, errors = self._emit(syn)
        self.assertEqual(errors, [])

    def test_baseline_from_execution_overrides_an_unmeasured_synthesis_value(self):
        path, _ = self._emit(baseline_from_execution=True)
        self.assertIn('kernel_baseline: "6.8.0-136-generic"', path.read_text())
        path, _ = self._emit(overwrite=True)  # default unchanged: explicit value honoured
        self.assertIn('kernel_baseline: "6.12"', path.read_text())

    def test_caveats_are_appended_to_notes(self):
        import yaml

        cav = {"UEM-10": {"landlock": ["Landlock audit needs ABI 7 and audit_enabled=1."]}}
        path, _ = self._emit(caveats=cav)
        notes = yaml.safe_load(path.read_text())["notes"]
        self.assertIn("Reviewer independence", notes)
        self.assertIn("[landlock] Landlock audit needs ABI 7 and audit_enabled=1.", notes)


class QuotingTests(unittest.TestCase):
    def test_observed_text_with_quotes_round_trips_as_valid_yaml(self):
        import yaml

        with tempfile.TemporaryDirectory() as d:
            cat = Path(d) / "catalog"
            cat.mkdir()
            rec = _execution_records()
            rec["UEM-10"]["landlock"]["observed"] = 'audit: type=1400 apparmor="DENIED" name="/x \\\\ y"'
            path, errors = eae.emit(_synthesis(), _reviews(), {"UEM-10": {"domain": "D", "title": "T"}}, cat,
                                    execution_records=rec, **PROVENANCE_ARGS)
            self.assertEqual(errors, [])
            entry = yaml.safe_load(path.read_text())
            self.assertEqual(entry["provenance"]["execution"]["observed"], rec["UEM-10"]["landlock"]["observed"])
            self.assertEqual(entry["primitives"][0]["execution"]["observed"], rec["UEM-10"]["landlock"]["observed"])


class TopLevelExecutionSourceTests(unittest.TestCase):
    def test_top_level_block_comes_from_a_primitive_that_was_executed(self):
        import yaml

        with tempfile.TemporaryDirectory() as d:
            cat = Path(d) / "catalog"
            cat.mkdir()
            syn = _two_primitive_synthesis()  # landlock first, seccomp second
            rec = {"UEM-10": {"seccomp": {"kernel_release": "6.17.0-40-generic", "kernel_arch": "aarch64",
                                          "probe": "akcm-wall:x", "observed": "audit: type=1326", "runner": "qemu"}}}
            path, errors = eae.emit(syn, _reviews(), {"UEM-10": {"domain": "D", "title": "T"}}, cat,
                                    execution_records=rec, **PROVENANCE_ARGS)
            self.assertEqual(errors, [])
            self.assertIn("_unattested", str(path))  # landlock has no record of its own
            entry = yaml.safe_load(path.read_text())
            self.assertEqual(entry["provenance"]["execution"]["kernel_release"], "6.17.0-40-generic")
