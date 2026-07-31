# AKCM Kernel Harnesses

The harness, dispatch, and compile-time tooling behind CSA's AKCM (Agentic Kernel
Controls Matrix) work — how a claim that "control X can be enforced by Linux mechanism Y"
gets measured against a real kernel, dispatched through independent AI review, and gated
before it's allowed into a catalog entry.

This is tooling, not the mapping output itself: the actual 243-entry AICM-control-to-
kernel-primitive catalog lives in a separate, private repository. What's here is
everything CSA's AARM and CAR working groups (or anyone else) can inspect and run
themselves to check the process, independent of trusting the output.

## What's here

```
harness/     Real-kernel primitive verification (landlock, cgroup2, LSM, seccomp)
tools/       The compile-process dispatch/emit tooling ("Engine K")
scripts/     check_catalog_entries.py -- the schema/provenance gate every entry must pass
docs/ai-caiq/  Two AI-CAIQ v1.1.0 self-assessments for this toolchain
```

### `harness/` — kernel primitive verification

`kernel_harness.py` measures whether a kernel primitive is actually present and what it
reports, rather than citing a changelog or version number:

- `verify-mechanism` — runs a disposable container on a real host's own kernel (via SSH)
  and probes landlock ABI, cgroup2, the active LSM stack, or seccomp's available actions.
  Deliberately does **not** run under a sandboxed runtime like gVisor, which reimplements
  the kernel and would silently measure the sandbox instead of the host.
- A QEMU backend (`build_qemu_probe_script`) runs the identical probe inside a disposable
  local VM whose kernel is actually selectable — this exists because kernel capability is
  a *build-configuration* property, not a *version* property. Measured directly: one
  Docker Desktop kernel returned `ENOSYS` for landlock and exposed no LSM list at all,
  while a same-generation Ubuntu kernel reported landlock ABI 4 and five active LSMs. A
  `min_kernel` claim cannot be established from a single host for exactly this reason.
- `runtime-status` / `install-gvisor` cover the separate question of container-host
  sandboxing strength (AICM AIS-13) — whether agent-generated code runs on plain `runc`
  or a hardened runtime, and installing the latter when it's missing.

26 tests, all standalone (no external repo required): `python3 -m pytest harness/ -q`.

### `tools/` — the compile-process dispatch/emit chain ("Engine K")

`dispatch_domain.ts` wraps the round-robin CONTRIBUTE → SYNTHESIZE → REVIEW dispatch
(imported from a sibling [rockin-robin](https://github.com/mEllergrace/rockin-robin)
checkout, not reimplemented) with a dry-run/budget/named-approver guard, so a spend
estimate is available before anything is billed. `akcm_sources.py` bridges control
identity from CSA's own tested AICM 1.0.3 loader. `emit_akcm_entry.py` turns a
synthesis + its reviews into a provenance-complete catalog entry — or, lacking a real
execution record, a quarantined `_unattested` one, never silently upgraded. See
`tools/README.md` for the required environment variables (none of them ship with a real
host, key, or private-repo path baked in).

### `scripts/check_catalog_entries.py` — the gate

Validates a catalog entry's schema, gap-reasoning, citation format, and — the part this
audience will care most about — its **provenance and independence disclosure**: every
reviewer's verdict must carry a stated independence caveat (shared account/image/model
correlation disclosed, never implied from a verdict count alone), and a claim backed by
measurement must actually carry an execution record naming the kernel it was measured on.
21 tests, entirely self-contained (synthetic fixtures, no real catalog data required):
`python3 -m pytest scripts/ -q`.

### `docs/ai-caiq/` — self-assessment

Both AI-CAIQ v1.1.0 workbooks are the same toolchain configuration this repo packages —
the mapping factory's and the round-robin review engine's — included directly rather
than linked, since they're small and this audience will want them in hand.

## What's deliberately not vendored here

Two upstream dependencies stay private and external, each documented with the env var
that points at them (`SSM_FACTORY_ROOT`, `SSM_DATASETS_ROOT` — see `tools/README.md`):
CSA's Security-Standards-Mapping factory and its underlying dataset repo. The harness and
dispatch code itself — everything that can actually be inspected and run — is fully open
here.

## Running the tests

```
python3 -m pytest harness/ scripts/ tools/ -q   # 59 pass standalone, 3 need SSM_* env vars set
node --test tools/tests/dispatchDomain.test.ts   # 9 pass
```

## License

MIT — see `LICENSE`.
