# build-ok: searched engines/engine_k_csa_control_to_capability/stage4_mapping/processing/
# (empty before this work) and rockin-robin/scripts/rr_aicm_round.ts::parseSources, which
# re-parses ZTAF-Primitive-Mapping-v2/catalog/sources.md (the SUPERSEDED repo) via a bespoke
# markdown-table regex. That path is licensed only for control-identity acquisition evidence,
# never authoritative going forward. The factory already has a tested, authoritative AICM
# 1.0.3 loader at engine_b_nist_ir8477/engine_b2_supportive/stage4_mapping/processing/
# batch_harness/candidate_gen.py::load_aicm_by_domain (243 controls, per docs/HANDOFF.md's own
# "Factory operational" line) -- this bridges Engine K's TypeScript dispatch driver to that
# existing, tested loader instead of re-deriving control identity a third way.
#!/usr/bin/env python3
"""Print AICM 1.0.3 control identity (id, title, domain) as JSON, sourced from the factory's
own tested loader (candidate_gen.load_aicm_by_domain) rather than the superseded repo's
sources.md. Used by dispatch_domain.ts via subprocess so control-count math for --dry-run
and the real batch driver share one source of truth.

Usage:
  akcm_sources.py --domain "<AICM domain name>"   -> that domain's controls, JSON array
  akcm_sources.py --all                           -> every control, JSON array
"""
import json
import os
import sys
from pathlib import Path

# SSM_FACTORY_ROOT overrides the default. Security-Standards-Mapping ("the factory") is a
# private, separate repo this tooling depends on but does not vendor -- the default assumes
# it's cloned as a sibling directory next to this repo; set the env var if yours lives
# elsewhere.
FACTORY_ROOT = Path(os.environ.get(
    "SSM_FACTORY_ROOT", str(Path(__file__).resolve().parent.parent.parent / "Security-Standards-Mapping")
))
BATCH_HARNESS = FACTORY_ROOT / "engines" / "engine_b_nist_ir8477" / "engine_b2_supportive" / "stage4_mapping" / "processing"
sys.path.insert(0, str(BATCH_HARNESS))


def _load():
    from batch_harness import candidate_gen as cg  # imported here so import errors surface
    # under main()'s try/except, not at module load time (keeps this importable for tests
    # that only exercise argument parsing).
    return cg.load_aicm_by_domain("1.0.3")


def controls_for_domain(domain, by_domain=None):
    by_domain = by_domain if by_domain is not None else _load()
    matches = by_domain.get(domain, [])
    return [{"id": c["id"], "title": c["title"], "domain": domain} for c in matches]


def all_controls(by_domain=None):
    by_domain = by_domain if by_domain is not None else _load()
    out = []
    for domain, controls in by_domain.items():
        out.extend({"id": c["id"], "title": c["title"], "domain": domain} for c in controls)
    return out


def main(argv):
    if not argv:
        print("usage: akcm_sources.py --domain \"<name>\" | --all", file=sys.stderr)
        return 2
    try:
        by_domain = _load()
    except Exception as exc:  # noqa: BLE001 -- surfaced as an operational failure, not a crash
        print(f"FAIL: could not load the AICM source register: {exc}", file=sys.stderr)
        return 2

    if argv[0] == "--all":
        print(json.dumps(all_controls(by_domain)))
        return 0
    if argv[0] == "--domain" and len(argv) > 1:
        print(json.dumps(controls_for_domain(argv[1], by_domain)))
        return 0

    print("usage: akcm_sources.py --domain \"<name>\" | --all", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
