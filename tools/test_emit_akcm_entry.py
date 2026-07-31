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
