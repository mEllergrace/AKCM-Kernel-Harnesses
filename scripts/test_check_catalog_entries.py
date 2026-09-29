"""Tests for check_catalog_entries.py — the AICM-control-keyed validator.

Written before the implementation (test-first, per docs/HANDOFF.md rule 1). Each
case pins one gate from provenance/schema.md / ASSURANCE.md so a later change to
the validator can't silently drop one.
"""
import copy
import unittest

import check_catalog_entries as cce


def _valid_entry():
    return copy.deepcopy({
        "aicm_control_id": "UEM-10",
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
        "notes": "",
        "attestation_state": "attested",
        "provenance": {
            "selection_record": "sel-2026-07-aicm-kernel-primitives",
            "delivery_brief": "brief-2026-07-akcm",
            "engine": "secid:methodology/cloudsecurityalliance.org/control-to-capability",
            "factory_commit": "c48b99d",
            "block_chain": ["ssm-mapping-run", "expert-verify", "expert-counter",
                             "mapping-consensus", "akcm-emit"],
            "run_id": "run-2026-07-30-uem",
            "date": "2026-07-30",
            "execution": {
                "kernel_release": "6.8.0-136-generic",
                "kernel_arch": "aarch64",
                "probe": "landlock-abi",
                "observed": "4",
                "runner": "qemu",
            },
            "min_kernel_basis": "measured",
            "reviewers": [
                {"id": "expert-landlock", "verdict": "concur",
                 "independence": {"shared": ["account", "image", "model"],
                                   "correlated": True,
                                   "caveat": "6 harnesses share account/image/model; not independent AI systems"}},
                {"id": "expert-seccomp-bpf", "verdict": "concur",
                 "independence": {"shared": ["account", "image", "model"],
                                   "correlated": True,
                                   "caveat": "6 harnesses share account/image/model; not independent AI systems"}},
            ],
        },
    })


def _gap_entry():
    e = _valid_entry()
    e["aicm_control_id"] = "GRC-05"
    e["gap"] = True
    e["gap_reason"] = "No kernel decision point mediates a governance policy-authorship control."
    del e["primitives"]
    e["provenance"].pop("execution", None)
    e["provenance"]["min_kernel_basis"] = "unverified"
    return e


class ValidEntryTests(unittest.TestCase):
    def test_valid_mapped_entry_passes(self):
        self.assertEqual(cce.check_entry(_valid_entry(), "catalog/UEM-10.yaml"), [])

    def test_valid_gap_entry_passes(self):
        self.assertEqual(cce.check_entry(_gap_entry(), "catalog/GRC-05.yaml"), [])


class GapRulesTests(unittest.TestCase):
    def test_gap_true_without_gap_reason_fails(self):
        e = _gap_entry()
        del e["gap_reason"]
        v = cce.check_entry(e, "catalog/GRC-05.yaml")
        self.assertTrue(any("gap_reason" in x for x in v))

    def test_gap_true_with_primitives_fails(self):
        e = _gap_entry()
        e["primitives"] = [_valid_entry()["primitives"][0]]
        v = cce.check_entry(e, "catalog/GRC-05.yaml")
        self.assertTrue(any("gap" in x and "primitives" in x for x in v))

    def test_gap_false_without_primitives_fails(self):
        e = _valid_entry()
        e["primitives"] = []
        v = cce.check_entry(e, "catalog/UEM-10.yaml")
        self.assertTrue(any("primitives" in x for x in v))


class PrimitiveRulesTests(unittest.TestCase):
    def test_unknown_primitive_fails(self):
        e = _valid_entry()
        e["primitives"][0]["primitive"] = "spectre-mitigation"
        v = cce.check_entry(e, "x")
        self.assertTrue(any("primitive" in x for x in v))

    def test_citation_without_https_fails(self):
        e = _valid_entry()
        e["primitives"][0]["citation"] = "docs.kernel.org/landlock#network-rules"
        v = cce.check_entry(e, "x")
        self.assertTrue(any("https://" in x for x in v))

    def test_citation_without_fragment_fails(self):
        e = _valid_entry()
        e["primitives"][0]["citation"] = "https://docs.kernel.org/userspace-api/landlock.html"
        v = cce.check_entry(e, "x")
        self.assertTrue(any("#fragment" in x for x in v))

    def test_bad_role_fails(self):
        e = _valid_entry()
        e["primitives"][0]["role"] = "sole"
        v = cce.check_entry(e, "x")
        self.assertTrue(any("role" in x for x in v))


class ExecutionRulesTests(unittest.TestCase):
    def test_mapped_entry_without_execution_record_fails(self):
        e = _valid_entry()
        del e["provenance"]["execution"]
        v = cce.check_entry(e, "x")
        self.assertTrue(any("execution" in x for x in v))

    def test_gvisor_expert_container_as_runner_fails(self):
        """A self-probe from inside a gVisor expert container reports a fake kernel
        (4.19.0-gvisor) and false-negatives real capabilities — never a valid runner."""
        e = _valid_entry()
        e["provenance"]["execution"]["runner"] = "expert-landlock"
        v = cce.check_entry(e, "x")
        self.assertTrue(any("runner" in x for x in v))

    def test_measured_min_kernel_with_unverified_basis_fails(self):
        """A real version bound with min_kernel_basis still 'unverified' is exactly the
        changelog-inferred-floor mistake provenance/schema.md gate 3 exists to catch."""
        e = _valid_entry()
        e["provenance"]["min_kernel_basis"] = "unverified"
        v = cce.check_entry(e, "x")
        self.assertTrue(any("min_kernel_basis" in x for x in v))

    def test_unverified_min_kernel_is_allowed_only_while_min_kernel_basis_unverified(self):
        e = _gap_entry()  # no primitives, so no measured min_kernel to conflict
        self.assertEqual(cce.check_entry(e, "x"), [])


class ProvenanceRulesTests(unittest.TestCase):
    def test_missing_selection_record_fails(self):
        e = _valid_entry()
        del e["provenance"]["selection_record"]
        v = cce.check_entry(e, "x")
        self.assertTrue(any("selection_record" in x for x in v))

    def test_missing_reviewers_fails(self):
        e = _valid_entry()
        e["provenance"]["reviewers"] = []
        v = cce.check_entry(e, "x")
        self.assertTrue(any("reviewers" in x for x in v))

    def test_reviewer_without_independence_caveat_fails(self):
        """Independence must be STATED per entry, never implied from a verdict count."""
        e = _valid_entry()
        del e["provenance"]["reviewers"][0]["independence"]["caveat"]
        v = cce.check_entry(e, "x")
        self.assertTrue(any("caveat" in x for x in v))

    def test_bad_reviewer_verdict_fails(self):
        e = _valid_entry()
        e["provenance"]["reviewers"][0]["verdict"] = "confirmed"
        v = cce.check_entry(e, "x")
        self.assertTrue(any("verdict" in x for x in v))


class AttestationStateRulesTests(unittest.TestCase):
    def test_attested_entry_in_unattested_dir_fails(self):
        v = cce.check_entry(_valid_entry(), "catalog/_unattested/UEM-10.yaml")
        self.assertTrue(any("attestation_state" in x for x in v))

    def test_incomplete_provenance_outside_unattested_dir_fails(self):
        e = _valid_entry()
        del e["provenance"]["factory_commit"]
        v = cce.check_entry(e, "catalog/UEM-10.yaml")
        self.assertTrue(any("factory_commit" in x for x in v))

    def test_incomplete_provenance_inside_unattested_dir_is_tolerated(self):
        e = _valid_entry()
        del e["provenance"]["factory_commit"]
        e["attestation_state"] = "unattested"
        v = cce.check_entry(e, "catalog/_unattested/UEM-10.yaml")
        self.assertEqual(v, [])


class RegisterTests(unittest.TestCase):
    def test_duplicate_control_id_across_entries_fails(self):
        e1 = _valid_entry()
        e2 = _valid_entry()
        v = cce.check_register([e1, e2], ["catalog/a.yaml", "catalog/b.yaml"])
        self.assertTrue(any("duplicate" in x for x in v))


if __name__ == "__main__":
    unittest.main()


class PerPrimitiveExecutionTests(unittest.TestCase):
    """mEllergrace/AKCM-Mappings#1: one execution block used to attest every primitive."""

    def _two(self):
        e = _valid_entry()
        p2 = copy.deepcopy(e["primitives"][0])
        p2["primitive"] = "seccomp"
        e["primitives"].append(p2)
        return e

    def test_default_behaviour_is_unchanged(self):
        self.assertEqual(cce.check_entry(self._two(), "catalog/UEM-10.yaml"), [])

    def test_strict_mode_names_every_primitive_without_its_own_record(self):
        v = cce.check_entry(self._two(), "catalog/UEM-10.yaml", require_per_primitive=True)
        self.assertEqual(len([x for x in v if "own execution record" in x]), 2)

    def test_strict_mode_passes_when_each_primitive_was_executed(self):
        e = self._two()
        for p in e["primitives"]:
            p["execution"] = dict(e["provenance"]["execution"])
        self.assertEqual(cce.check_entry(e, "catalog/UEM-10.yaml", require_per_primitive=True), [])

    def test_an_incomplete_per_primitive_block_is_always_a_violation(self):
        e = _valid_entry()
        e["primitives"][0]["execution"] = {"kernel_release": "6.8.0-142-generic"}
        v = cce.check_entry(e, "catalog/UEM-10.yaml")
        self.assertTrue(any("primitives[0].execution.kernel_arch" in x for x in v), v)


class AicmDomainTests(unittest.TestCase):
    """#8: aicm_domain replaces atf_pillar; entries with only atf_pillar remain valid."""

    def test_aicm_domain_alone_is_valid(self):
        e = _valid_entry()
        del e["atf_pillar"]
        e["aicm_domain"] = "Universal Endpoint Management"
        self.assertEqual(cce.check_entry(e, "catalog/UEM-10.yaml"), [])

    def test_neither_field_is_a_violation(self):
        e = _valid_entry()
        del e["atf_pillar"]
        self.assertTrue(any("aicm_domain is required" in x for x in cce.check_entry(e, "catalog/UEM-10.yaml")))

    def test_legacy_atf_pillar_still_accepted_and_still_validated(self):
        self.assertEqual(cce.check_entry(_valid_entry(), "catalog/UEM-10.yaml"), [])
        e = _valid_entry()
        e["atf_pillar"] = "not-a-pillar"
        self.assertTrue(cce.check_entry(e, "catalog/UEM-10.yaml"))
