# build-ok: searched scripts/ across the CSA repos before writing this. Found
# ZTAF-Primitive-Mapping/scripts/check_catalog_entries.py (v1) — unusable as-is: it
# validates atf_pillar/requirement_ids/primitive_family against catalog/vocabulary/*.yaml,
# a different axis (ATF requirement -> kernel primitive family) than AKCM's
# aicm_control_id/primitives[]/gap + provenance/execution/independence blocks (see
# provenance/schema.md). No workflows/ block or existing script in this repo covers
# validating catalog/*.yaml against MANIFEST.yaml's schema — this repo's scripts/ dir
# does not exist yet. Extending v1 in place would silently start accepting the wrong
# field names for a different repo's schema.
#!/usr/bin/env python3
"""Validate AKCM catalog entries (catalog/*.yaml) against the AICM-control-keyed
schema in MANIFEST.yaml and the provenance/execution/independence gates in
provenance/schema.md and ASSURANCE.md.

Dependency-light (pyyaml only, already required by this toolchain per
docs/HANDOFF.md) rather than hand-rolling a YAML subset parser, since the schema
here is deeper than a flat key/value entry.

Exit codes: 0 all entries valid, 1 one or more violations, 2 operational failure.
"""
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_DIR = REPO_ROOT / "catalog"
UNATTESTED_DIRNAME = "_unattested"

MIN_TEXT = 20
PILLARS = {"identity", "behavior", "data_governance", "segmentation", "incident_response"}
PRIMITIVES = {"lsm", "landlock", "seccomp", "cgroups", "capabilities", "lockdown"}
ROLES = {"primary", "supporting"}
VERDICTS = {"concur", "revise", "dissent"}
RUNNERS = {"qemu", "remote-host"}
ATTESTATION_STATES = {"attested", "unattested", "asserted"}
MIN_KERNEL_BASES = {"measured", "unverified"}
UNVERIFIED = "unverified"

_VERSION_RE = re.compile(r"^\d+\.\d+(\.\d+)?$")


def _in_unattested_dir(path):
    return UNATTESTED_DIRNAME in Path(path).parts


def _nontrivial(text):
    return isinstance(text, str) and len(text.strip()) >= MIN_TEXT


def check_entry(entry, path):
    """Return a list of violation strings for one parsed entry dict. Pure —
    takes an already-loaded dict so tests don't need real files on disk."""
    v = []
    cid = entry.get("aicm_control_id") or "<no id>"

    if not entry.get("aicm_control_id"):
        v.append(f"{path}: missing aicm_control_id")

    pillar = entry.get("atf_pillar")
    if pillar not in PILLARS:
        v.append(f"{cid}: atf_pillar '{pillar}' not one of {sorted(PILLARS)}")

    gap = entry.get("gap")
    if not isinstance(gap, bool):
        v.append(f"{cid}: gap must be true or false")

    primitives = entry.get("primitives") or []
    if gap is True:
        if not _nontrivial(entry.get("gap_reason", "")):
            v.append(f"{cid}: gap is true but gap_reason is missing or too short")
        if primitives:
            v.append(f"{cid}: gap is true but primitives is present — a gap has no primitives")
    elif gap is False:
        if not primitives:
            v.append(f"{cid}: gap is false but primitives is empty — a mapped control needs at least one")

    has_mechanism_claim = bool(primitives)

    for i, p in enumerate(primitives):
        tag = f"{cid}.primitives[{i}]"
        if p.get("primitive") not in PRIMITIVES:
            v.append(f"{tag}: primitive '{p.get('primitive')}' not one of {sorted(PRIMITIVES)}")
        if not _nontrivial(p.get("mechanism", "")):
            v.append(f"{tag}: mechanism missing or too short")
        if p.get("role") not in ROLES:
            v.append(f"{tag}: role '{p.get('role')}' not one of {sorted(ROLES)}")
        min_kernel = p.get("min_kernel")
        if min_kernel and min_kernel != UNVERIFIED and not _VERSION_RE.match(min_kernel):
            v.append(f"{tag}: min_kernel '{min_kernel}' is not a version like '6.7' or '{UNVERIFIED}'")
        citation = p.get("citation") or ""
        if not citation.startswith("https://"):
            v.append(f"{tag}: citation '{citation}' is not an https:// URL")
        elif "#" not in citation:
            v.append(f"{tag}: citation '{citation}' has no #fragment — a bare page URL is not a citation")

    if not _nontrivial(entry.get("rationale", "")):
        v.append(f"{cid}: rationale missing or too short")
    if not _nontrivial(entry.get("workflow", "")):
        v.append(f"{cid}: workflow is required (even for a gap) and missing or too short")

    attestation_state = entry.get("attestation_state")
    if attestation_state not in ATTESTATION_STATES:
        v.append(f"{cid}: attestation_state '{attestation_state}' not one of {sorted(ATTESTATION_STATES)}")

    in_unattested = _in_unattested_dir(path)
    if attestation_state == "attested" and in_unattested:
        v.append(f"{cid}: attestation_state is 'attested' but the entry lives under {UNATTESTED_DIRNAME}/")
    if attestation_state != "attested" and not in_unattested:
        v.append(
            f"{cid}: attestation_state is '{attestation_state}' but the entry is not under "
            f"{UNATTESTED_DIRNAME}/ — an incomplete entry may not sit beside attested ones"
        )

    prov = entry.get("provenance") or {}
    required_prov_fields = ["selection_record", "delivery_brief", "engine", "factory_commit", "run_id", "date"]
    missing_prov = [f for f in required_prov_fields if not prov.get(f)]
    if missing_prov and not in_unattested:
        for f in missing_prov:
            v.append(f"{cid}: provenance.{f} is required and missing")
    if not prov.get("block_chain"):
        if not in_unattested:
            v.append(f"{cid}: provenance.block_chain is required and missing")
    elif not isinstance(prov["block_chain"], list) or not prov["block_chain"]:
        v.append(f"{cid}: provenance.block_chain must be a non-empty list")

    execution = prov.get("execution")
    if has_mechanism_claim and not execution:
        if not in_unattested:
            v.append(
                f"{cid}: a mechanism claim (primitives present) requires provenance.execution — "
                "no execution record means it is asserted, not mapped"
            )
    elif execution:
        for f in ("kernel_release", "kernel_arch", "probe", "observed", "runner"):
            if not execution.get(f):
                v.append(f"{cid}: provenance.execution.{f} is required and missing")
        runner = execution.get("runner")
        if runner and runner not in RUNNERS:
            v.append(
                f"{cid}: provenance.execution.runner '{runner}' is not one of {sorted(RUNNERS)} — "
                "never one of the gVisor expert containers, which report a fake kernel and false-negative real capabilities"
            )

    min_kernel_basis = prov.get("min_kernel_basis")
    if min_kernel_basis is not None and min_kernel_basis not in MIN_KERNEL_BASES:
        v.append(f"{cid}: provenance.min_kernel_basis '{min_kernel_basis}' not one of {sorted(MIN_KERNEL_BASES)}")
    measured_min_kernels = [
        p.get("min_kernel") for p in primitives if p.get("min_kernel") and p.get("min_kernel") != UNVERIFIED
    ]
    if measured_min_kernels and min_kernel_basis == UNVERIFIED and not in_unattested:
        v.append(
            f"{cid}: primitives carry a real min_kernel version but provenance.min_kernel_basis is "
            f"'{UNVERIFIED}' — a version bound with no measurement basis is a fabricated citation"
        )

    reviewers = prov.get("reviewers") or []
    if not reviewers and not in_unattested:
        v.append(f"{cid}: provenance.reviewers must be non-empty")
    for i, r in enumerate(reviewers):
        rtag = f"{cid}.reviewers[{i}]"
        if not r.get("id"):
            v.append(f"{rtag}: missing id")
        if r.get("verdict") not in VERDICTS:
            v.append(f"{rtag}: verdict '{r.get('verdict')}' not one of {sorted(VERDICTS)}")
        indep = r.get("independence") or {}
        if not _nontrivial(indep.get("caveat", "")):
            v.append(
                f"{rtag}: independence.caveat is required and missing — independence must be STATED, "
                "never implied from a verdict count"
            )

    return v


def check_register(entries, paths):
    """Cross-entry checks: uniqueness of aicm_control_id across the whole catalog."""
    v = []
    seen = {}
    for entry, path in zip(entries, paths):
        cid = entry.get("aicm_control_id")
        if not cid:
            continue
        if cid in seen:
            v.append(f"{path}: duplicate aicm_control_id '{cid}' (also in {seen[cid]})")
        else:
            seen[cid] = path
    return v


def _load_entries(catalog_dir):
    paths = sorted(p for p in catalog_dir.rglob("*.yaml"))
    entries, loaded_paths = [], []
    for p in paths:
        try:
            data = yaml.safe_load(p.read_text())
        except yaml.YAMLError as exc:
            print(f"FAIL: cannot parse {p}: {exc}", file=sys.stderr)
            return None, None
        if not isinstance(data, dict):
            print(f"FAIL: {p} did not parse to a mapping", file=sys.stderr)
            return None, None
        entries.append(data)
        loaded_paths.append(str(p.relative_to(catalog_dir.parent)))
    return entries, loaded_paths


def main(argv):
    catalog_dir = Path(argv[0]) if argv else CATALOG_DIR
    if not catalog_dir.exists():
        print(f"FAIL: {catalog_dir} does not exist", file=sys.stderr)
        return 2

    entries, paths = _load_entries(catalog_dir)
    if entries is None:
        return 2
    if not entries:
        print(f"FAIL: no entries found under {catalog_dir}", file=sys.stderr)
        return 2

    violations = []
    for entry, path in zip(entries, paths):
        violations.extend(check_entry(entry, path))
    violations.extend(check_register(entries, paths))

    print(f"Checked {len(entries)} catalog entr{'y' if len(entries) == 1 else 'ies'}")
    if violations:
        for v in violations:
            print(f"  VIOLATION: {v}")
        print(f"\nFAIL: {len(violations)} violation(s)")
        return 1
    print("PASS: all entries valid")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
