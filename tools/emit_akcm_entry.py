# build-ok: searched ZTAF-Primitive-Mapping-v2/scripts/emit_entry.py (the retracted repo's
# emit script, licensed by docs/HANDOFF.md for reuse "as Engine K's implementation") in
# detail before writing this. Its render/fold/validate shape is adopted almost verbatim
# (render_entry's YAML layout, the closed-vocabulary refusal gates) -- what could NOT be
# reused as-is: it has no `provenance:` block at all (that requirement postdates it, see
# AKCM-Mappings/provenance/schema.md), it looks up identity from ZTAF-v2's own
# catalog/sources.md rather than the factory's tested AICM loader (akcm_sources.py, this
# same directory), and it always writes to a flat catalog/ with no unattested-quarantine
# path. Those three gaps are exactly what the retracted run got wrong per
# AKCM-Mappings/ASSURANCE.md, so they could not be inherited unexamined even though the
# rendering logic they sit inside of was fine to keep.
#!/usr/bin/env python3
"""Emit a provenance-complete AKCM catalog entry from a dispatch_domain.ts synthesis result
plus its reviews.json, per AKCM-Mappings/provenance/schema.md.

Without an execution record (expert-verify — real-kernel execution, not yet wired into
dispatch_domain.ts's CONTRIBUTE/SYNTHESIZE/REVIEW loop) a mechanism claim is `asserted`, not
`attested`, and is written under catalog/_unattested/ rather than catalog/ proper — never
silently upgraded to attested for lack of the data that would justify it.
"""
from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path

PRIMITIVES = {"lsm", "landlock", "seccomp", "cgroups", "capabilities", "lockdown"}
PILLARS = {"identity", "behavior", "data_governance", "segmentation", "incident_response"}
ROLES = {"primary", "supporting"}
BLOCK_CHAIN = ["ssm-mapping-run", "expert-verify", "expert-counter", "mapping-consensus", "akcm-emit"]

# Fixed for this estate until an API-key second identity or model-family variation changes
# it (docs/HANDOFF.md "Open, and the owner's to decide") -- stated, never implied.
INDEPENDENCE_CAVEAT = (
    "Reviewer independence: 6 harnesses share account, image and model -- AKCM's charter "
    "requirement of confirmation by at least 2 other AI SYSTEMS is NOT satisfied. Recorded, "
    "not resolved."
)


def _fold(text, indent="      ", width=92):
    collapsed = " ".join(str(text).split()) or "(none)"
    return "\n".join(
        textwrap.wrap(collapsed, width=width, initial_indent=indent, subsequent_indent=indent,
                      break_long_words=False, break_on_hyphens=False)
    )


def _block(text, indent="  "):
    body = str(text).rstrip("\n")
    if not body.strip():
        body = "(none)"
    return "\n".join(indent + ln if ln.strip() else "" for ln in body.split("\n"))


def stem_for(control_id):
    return control_id.lower().replace("&", "-")


def validate_synthesis(syn, identity_known):
    errors = []
    if not identity_known:
        errors.append(
            f"aicm_control_id {syn.get('aicm_control_id')!r} is not in the AICM control register — "
            "identity must come from akcm_sources.py verbatim, never invented from the synthesis result"
        )
    if syn.get("atf_pillar") not in PILLARS:
        errors.append(f"atf_pillar {syn.get('atf_pillar')!r} not one of {sorted(PILLARS)}")

    is_gap = bool(syn.get("gap"))
    prims = syn.get("primitives") or []
    if is_gap and prims:
        errors.append("gap: true and primitives are mutually exclusive")
    if is_gap and not str(syn.get("gap_reason", "")).strip():
        errors.append("gap: true requires gap_reason")
    if not is_gap and not prims:
        errors.append("gap: false requires at least one primitive")

    for i, p in enumerate(prims):
        if p.get("primitive") not in PRIMITIVES:
            errors.append(f"primitives[{i}].primitive {p.get('primitive')!r} outside the closed six")
        if p.get("role") not in ROLES:
            errors.append(f"primitives[{i}].role {p.get('role')!r} not one of {sorted(ROLES)}")
        if not str(p.get("mechanism", "")).strip():
            errors.append(f"primitives[{i}].mechanism is empty")
        cit = str(p.get("citation", "")).strip()
        if not cit.startswith("https://") or "#" not in cit:
            errors.append(f"primitives[{i}].citation must be an https:// URL with a #fragment: {cit!r}")

    if not str(syn.get("rationale", "")).strip():
        errors.append("rationale is empty")
    if not str(syn.get("workflow", "")).strip():
        errors.append("workflow is required on every entry, including a gap")
    return errors


def _reviewers_block(reviews_entry):
    reviewers = []
    for r in (reviews_entry or {}).get("reviewers", []):
        reviewers.append({
            "id": r["id"],
            "verdict": r["verdict"],
            "independence": {
                "shared": ["account", "image", "model"],
                "correlated": True,
                "caveat": INDEPENDENCE_CAVEAT,
            },
        })
    return reviewers


def render_entry(control_id, domain, title, syn, reviews_entry, execution_by_primitive,
                  attestation_state, **provenance_args):
    out = ['schema_version: "1.0"', "", f'aicm_control_id: "{control_id}"']
    out += [f"atf_pillar: {syn['atf_pillar']}", ""]
    # An explicit baseline from the synthesis is still honoured. Otherwise it is the kernel
    # a mechanism was actually executed on -- never an unmeasured default (AKCM-Mappings#2).
    baseline = str(syn.get("kernel_baseline", "")).strip()
    if not baseline and execution_by_primitive:
        baseline = next((ex.get("kernel_release") for ex in execution_by_primitive.values()
                         if ex.get("kernel_release")), "")
    if baseline:
        out += [f'kernel_baseline: "{baseline}"', ""]

    if syn.get("gap"):
        out += ["gap: true", "", "gap_reason: >", _fold(syn["gap_reason"]), ""]
    else:
        out += ["gap: false", "", "primitives:"]
        for p in syn["primitives"]:
            out.append(f"  - primitive: {p['primitive']}")
            out.append("    mechanism: >")
            out.append(_fold(p["mechanism"]))
            if str(p.get("min_kernel", "")).strip():
                out.append(f"    min_kernel: \"{p['min_kernel']}\"")
            out.append(f"    role: {p['role']}")
            out.append(f"    citation: \"{p['citation']}\"")
            ex = (execution_by_primitive or {}).get(p["primitive"])
            if ex:  # this primitive's OWN execution record (AKCM-Mappings#1)
                out.append("    execution:")
                for f in ("kernel_release", "kernel_arch", "probe", "observed", "runner"):
                    out.append(f"      {f}: {json.dumps(str(ex.get(f, '')))}")
        out.append("")

    out += ["rationale: |", _block(syn["rationale"]), ""]
    out += ["workflow: |", _block(syn["workflow"]), ""]
    notes = str(syn.get("notes", "")).strip()
    if notes:
        out += ["notes: >", _fold(notes), ""]

    out += [f"attestation_state: {attestation_state}", ""]

    out += ["provenance:"]
    out.append(f'  selection_record: "{provenance_args["selection_record"]}"')
    out.append(f'  delivery_brief: "{provenance_args["delivery_brief"]}"')
    out.append(f'  engine: "{provenance_args["engine"]}"')
    out.append(f'  factory_commit: "{provenance_args["factory_commit"]}"')
    out.append(f"  block_chain: [{', '.join(BLOCK_CHAIN)}]")
    out.append(f'  run_id: "{provenance_args["run_id"]}"')
    out.append(f'  date: "{provenance_args["date"]}"')

    has_mechanism_claim = bool(syn.get("primitives"))
    if has_mechanism_claim and execution_by_primitive:
        out.append("  execution:")
        first_prim = syn["primitives"][0]["primitive"]
        ex = execution_by_primitive.get(first_prim, {})
        for f in ("kernel_release", "kernel_arch", "probe", "observed", "runner"):
            out.append(f'    {f}: "{ex.get(f, "")}"')
        out.append("  min_kernel_basis: measured")
    else:
        out.append("  min_kernel_basis: unverified")

    reviewers = _reviewers_block(reviews_entry)
    if reviewers:
        out.append("  reviewers:")
        for r in reviewers:
            out.append(f"    - id: \"{r['id']}\"")
            out.append(f"      verdict: {r['verdict']}")
            out.append("      independence:")
            out.append(f"        shared: [{', '.join(r['independence']['shared'])}]")
            out.append(f"        correlated: {'true' if r['independence']['correlated'] else 'false'}")
            out.append(f'        caveat: "{r["independence"]["caveat"]}"')
    else:
        out.append("  reviewers: []")

    return "\n".join(out).rstrip("\n") + "\n"


def _validate_rendered(text, path):
    import yaml

    scripts = Path(__file__).resolve().parent.parent / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import check_catalog_entries

    rel = path.relative_to(path.parents[1]) if "_unattested" not in path.parts else \
        Path("catalog") / "_unattested" / path.name
    return check_catalog_entries.check_entry(yaml.safe_load(text), str(rel))


def emit(synthesis, reviews, known_controls, catalog, execution_records=None, write=True,
         overwrite=False, **provenance_args):
    """known_controls: {control_id: {domain, title}} — from akcm_sources.py, never invented.
    execution_records: {control_id: {primitive: {kernel_release,...}}} or None.
    Returns (path, errors). errors non-empty => path is None (refused, nothing written)."""
    cid = str(synthesis.get("aicm_control_id", "")).strip()
    known = cid in known_controls
    errors = validate_synthesis(synthesis, known)
    if errors:
        return None, errors

    # buildReviewsJson (rockin-robin/scripts/rr_aicm_round.ts) keys reviews.json by
    # controlId.toLowerCase().replace('&','-') -- the same stem_for() transform used for the
    # catalog filename here, NOT the register's real casing. Falls back to the raw id so a
    # reviews.json produced some other way (already lowercase-keyed, or not) still resolves.
    reviews_entry = reviews.get(cid) or reviews.get(stem_for(cid))
    if not reviews_entry or not reviews_entry.get("reviewers"):
        errors.append(f"{cid}: no reviewers in reviews.json — mapping-consensus has not run for this control")
        return None, errors

    has_mechanism_claim = bool(synthesis.get("primitives"))
    exec_for_control = (execution_records or {}).get(cid)
    # Every primitive needs its OWN record; one probe for the first primitive no longer
    # attests the rest (AKCM-Mappings#1).
    attested = (not has_mechanism_claim) or all(
        (exec_for_control or {}).get(p["primitive"]) for p in synthesis.get("primitives") or [])
    attestation_state = "attested" if attested else "asserted"

    subdir = catalog if attestation_state == "attested" else (catalog / "_unattested")
    other_subdir = (catalog / "_unattested") if attestation_state == "attested" else catalog
    subdir.mkdir(parents=True, exist_ok=True)
    path = subdir / f"{stem_for(cid)}.yaml"
    stale_path = other_subdir / f"{stem_for(cid)}.yaml"
    if path.exists() and not overwrite:
        return None, [f"{path.name} already exists — refusing to overwrite. Pass overwrite=True deliberately."]
    text = render_entry(
        cid, known_controls[cid]["domain"], known_controls[cid]["title"], synthesis,
        reviews_entry, exec_for_control, attestation_state, **provenance_args,
    )
    # The documented gate, now real (AKCM-Mappings#3): nothing is written that
    # check_catalog_entries.check_entry would reject.
    violations = _validate_rendered(text, path)
    if violations:
        return None, [f"check_catalog_entries: {v}" for v in violations]
    # A control's attestation state can flip between runs (an execution record lands, or is
    # retracted). Without this, the stale copy in the OTHER location silently sits beside the
    # new one -- both individually valid, but check_register flags the duplicate id, and worse,
    # a reader could find the stale one first. Only remove it once the new one is confirmed
    # writable AND valid (overwrite check and validator gate above passed), never before.
    if write and stale_path.exists() and stale_path != path:
        stale_path.unlink()
    if write:
        path.write_text(text, encoding="utf-8")
    return path, []


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--synthesis", required=True, type=Path)
    ap.add_argument("--reviews", required=True, type=Path)
    ap.add_argument("--catalog", required=True, type=Path)
    ap.add_argument("--execution-records", type=Path, help="JSON: {control_id: {primitive: {...}}}")
    ap.add_argument("--selection-record", required=True)
    ap.add_argument("--delivery-brief", required=True)
    ap.add_argument("--engine", required=True)
    ap.add_argument("--factory-commit", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--date", required=True)
    ap.add_argument("--overwrite", action="store_true")
    ap.add_argument("--check", action="store_true", help="validate and report; write nothing")
    args = ap.parse_args(argv)

    here = Path(__file__).resolve().parent
    sys.path.insert(0, str(here))
    import akcm_sources

    payload = json.loads(args.synthesis.read_text(encoding="utf-8"))
    entries = payload if isinstance(payload, list) else [payload]
    reviews = json.loads(args.reviews.read_text(encoding="utf-8"))
    execution_records = (
        json.loads(args.execution_records.read_text(encoding="utf-8")) if args.execution_records else None
    )
    all_controls = {c["id"]: {"domain": c["domain"], "title": c["title"]} for c in akcm_sources.all_controls()}

    provenance_args = dict(
        selection_record=args.selection_record, delivery_brief=args.delivery_brief,
        engine=args.engine, factory_commit=args.factory_commit, run_id=args.run_id, date=args.date,
    )

    rc = 0
    for syn in entries:
        cid = syn.get("aicm_control_id", "?")
        path, errors = emit(
            syn, reviews, all_controls, args.catalog, execution_records=execution_records,
            write=not args.check, overwrite=args.overwrite, **provenance_args,
        )
        if errors:
            rc = 1
            print(f"  {cid:10} REFUSED")
            for e in errors:
                print(f"             - {e}")
            continue
        state = "attested" if "_unattested" not in str(path) else "asserted (quarantined)"
        verb = "would write" if args.check else "wrote"
        print(f"  {cid:10} {verb} {path.name} [{state}]")
    return rc


if __name__ == "__main__":
    sys.exit(main())
