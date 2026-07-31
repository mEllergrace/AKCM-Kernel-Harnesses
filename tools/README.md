# AKCM mapping runner

The AKCM-specific driver code that produces the (separately maintained, private) AKCM
mapping catalog's entries.

| file | role |
|---|---|
| `dispatch_domain.ts` | Engine K's stage4 driver — dry-run/budget/approval wrapper around Rockin-Robin's CONTRIBUTE/SYNTHESIZE/REVIEW dispatch (`rr_aicm_round.ts`/`rr_aicm_batch.ts`, imported dynamically from a sibling `rockin-robin` checkout, not reimplemented) |
| `akcm_sources.py` | Bridges control identity from the factory's own tested AICM 1.0.3 loader (`candidate_gen.py`) — override its location with `SSM_FACTORY_ROOT` |
| `emit_akcm_entry.py` | Turns a synthesis + reviews into a provenance-complete catalog entry, gated on `../scripts/check_catalog_entries.py` (vendored in this repo) |

## Environment variables these expect

None of these ship with a real default baked in for a host, key, or private-repo path —
each is either required or defaults to a sibling-checkout convention:

- `AKCM_RR_SCRIPTS` — path to a `rockin-robin/scripts` checkout. Defaults to a sibling
  directory next to this repo (clone [rockin-robin](https://github.com/mEllergrace/rockin-robin)
  alongside this one, or set this to point elsewhere).
- `SSM_FACTORY_ROOT` — path to `Security-Standards-Mapping` ("the factory"), a private
  repo not vendored here. Defaults to a sibling directory; set explicitly if yours lives
  elsewhere.
- `SSM_DATASETS_ROOT` — path to `CloudSecurityAlliance-DataSets`, required by the
  factory's own AICM loader. No default; private, not vendored here.
- `AKCM_VPS` / `AKCM_SSH_KEY` — the real dispatch host and SSH key for running specialist
  containers. **Required, no default** — this is your own infrastructure, not something
  this repo can assume.
- `--sources-root` (CLI flag) or `AKCM_SOURCES_ROOT` — path to a `sources.md` control-identity
  register in a separate, private repo. **Required, no default.**
- `AKCM_PYTHON` — Python interpreter to invoke `akcm_sources.py` with. Defaults to `python3`
  on `PATH`.
- `AKCM_CONTAINER_USER` — the unix user configured inside your dispatch containers.
  Defaults to `isme` (the account these containers happen to run as here) — override if
  yours differ. Not a secret, just an operational detail specific to one deployment.

## Tests

`tests/test_akcm_sources.py`, `test_emit_akcm_entry.py` (Python, `pytest`),
`tests/dispatchDomain.test.ts` (`node --test`). Everything except the 3
`test_akcm_sources.py` cases that load the real AICM control register runs standalone,
with no external repo required — those 3 need `SSM_FACTORY_ROOT`/`SSM_DATASETS_ROOT`
pointing at real (private) checkouts to pass; they fail loudly and specifically (a
missing-file error naming the exact path) rather than silently, when those aren't
configured.
