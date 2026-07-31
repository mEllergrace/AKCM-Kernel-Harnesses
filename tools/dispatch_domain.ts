// build-ok: searched engines/engine_k_csa_control_to_capability/stage4_mapping/processing/
// (empty, .gitkeep only before this) and rockin-robin/workflows/*.json (ssm-mapping-run.json
// etc. define the block CONTRACT, not a CLI). rr_aicm_batch.ts/rr_aicm_round.ts already
// implement the CONTRIBUTE/SYNTHESIZE/REVIEW dispatch and are explicitly licensed for reuse
// as Engine K's stage4 by docs/HANDOFF.md -- imported dynamically below, not reimplemented.
// Neither has a --dry-run/--budget guard; only B2's run_mapping.py does (a different
// engine's harness, engines/engine_b_nist_ir8477/.../batch_harness/run_mapping.py), whose
// --dry-run/--budget/--max-cost shape this wraps around the AICM batch driver instead of
// duplicating the CONTRIBUTE/SYNTHESIZE/REVIEW logic itself.
//
// Engine K's stage4 implementation. Per docs/HANDOFF.md: "the difference from last time is
// provenance, not code" -- this file adds exactly what was missing (a real dry-run, a spend
// cap, and an explicit named approver) around the reused dispatch logic, and nothing else.

// Defaults to a sibling checkout of the (separately public) rockin-robin repo -- clone it
// next to this repo, or set AKCM_RR_SCRIPTS to point elsewhere.
const RR_SCRIPTS =
  process.env.AKCM_RR_SCRIPTS ??
  new URL("../../rockin-robin/scripts", import.meta.url).pathname;

// Measured spend-ledger rates (rockin-robin/docs/spend-ledger.md, 2026-07-30): batching a
// whole domain costs ~$0.20-0.27/control (13 dispatches load each expert's context once per
// DOMAIN, not once per control); a single contested control costs ~$6 in the worst case.
// This is an ESTIMATE for sign-off before any dispatch -- a real --submit run reports actual
// measured spend from usage tokens, the same way rr_aicm_batch.ts's own spend object does.
const ESTIMATED_COST_PER_CONTROL_BATCHED_USD = 0.27;
const DISPATCHES_PER_DOMAIN_BATCH = 13; // 6 CONTRIBUTE + 1 SYNTHESIZE + 6 REVIEW

export interface DryRunReport {
  domain: string;
  controlCount: number;
  dispatchCount: number;
  estimatedCostUsd: number;
}

/** Free -- no dispatch() call, no SSH, no docker exec. Just arithmetic over a control count
 * already known from the AICM control register (akcm_sources.py), so a sign-off decision can
 * be made before anything is billed. */
export function buildDryRunReport(domain: string, controlCount: number): DryRunReport {
  return {
    domain,
    controlCount,
    dispatchCount: DISPATCHES_PER_DOMAIN_BATCH,
    estimatedCostUsd: Math.round(controlCount * ESTIMATED_COST_PER_CONTROL_BATCHED_USD * 100) / 100,
  };
}

export class BudgetExceededError extends Error {}

/** Call after each dispatch with the running total spent so far (rr_aicm_batch.ts's own
 * `spend` object already tracks this). Modeled on B2's run_mapping.py CostGuard, applied here
 * to the from-scratch path, which docs/HANDOFF.md rule 8 states has none by default. */
export function checkBudget(spentUsd: number, maxCostUsd: number | undefined): void {
  if (maxCostUsd !== undefined && spentUsd > maxCostUsd) {
    throw new BudgetExceededError(
      `spend $${spentUsd.toFixed(2)} exceeds --max-cost $${maxCostUsd.toFixed(2)} — refusing to continue`,
    );
  }
}

export interface RunOptions {
  dryRun: boolean;
  approvedBy?: string;
  budgetUsd?: number;
  maxCostUsd?: number;
}

/**
 * A real (non-dry-run) dispatch REQUIRES a named approver. Deliberately NOT hardcoded to one
 * person (e.g. the budget owner named in HOW-TO-RUN-A-MAPPING.md) -- who signs off is a real,
 * per-run option: pass whoever actually approved the spend for THIS run via --approved-by.
 * Recorded in the run log (writeRunLog), not assumed.
 */
export function assertApprovedForRealRun(opts: RunOptions): void {
  if (opts.dryRun) return;
  if (!opts.approvedBy || !opts.approvedBy.trim()) {
    throw new Error(
      'refusing to dispatch for real: pass --approved-by "<name>" naming who signed off on ' +
        "this spend for this run — not assumed to be any one fixed person — or pass --dry-run.",
    );
  }
}

export interface RunLogEntry {
  domain: string;
  approvedBy?: string;
  budgetUsd?: number;
  maxCostUsd?: number;
  dryRun: boolean;
  startedAt: string;
}

export function buildRunLogEntry(domain: string, opts: RunOptions, startedAt: string): RunLogEntry {
  return {
    domain,
    approvedBy: opts.approvedBy,
    budgetUsd: opts.budgetUsd,
    maxCostUsd: opts.maxCostUsd,
    dryRun: opts.dryRun,
    startedAt,
  };
}

interface Cli {
  domain: string;
  dryRun: boolean;
  approvedBy?: string;
  budgetUsd?: number;
  maxCostUsd?: number;
  sourcesRoot?: string;
}

function parseArgs(argv: string[]): Cli {
  const domain = argv[0];
  if (!domain || domain.startsWith("--")) {
    console.error('usage: dispatch_domain.ts "<AICM domain>" [--dry-run] [--approved-by <name>] [--budget <$>] [--max-cost <$>]');
    process.exit(2);
  }
  const cli: Cli = { domain, dryRun: false };
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--dry-run") cli.dryRun = true;
    else if (a === "--approved-by") cli.approvedBy = argv[++i];
    else if (a === "--budget") cli.budgetUsd = Number(argv[++i]);
    else if (a === "--max-cost") cli.maxCostUsd = Number(argv[++i]);
    else if (a === "--sources-root") cli.sourcesRoot = argv[++i];
  }
  return cli;
}

/** Control count for a domain via the factory's own tested AICM 1.0.3 loader
 * (batch_harness/candidate_gen.py::load_aicm_by_domain), NOT the superseded repo's
 * catalog/sources.md — control identity should come from the loader HANDOFF.md's "Factory
 * operational" state already counts (243 controls), not a re-derivation. */
async function loadDomainControlCount(domain: string): Promise<number> {
  const { execFileSync } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const { dirname, join } = await import("node:path");
  const here = dirname(fileURLToPath(import.meta.url));
  const bridge = join(here, "akcm_sources.py");
  const python = process.env.AKCM_PYTHON ?? "python3";
  const out = execFileSync(python, [bridge, "--domain", domain], { encoding: "utf8" });
  const parsed = JSON.parse(out) as { id: string; title: string; domain: string }[];
  return parsed.length;
}

async function main(): Promise<void> {
  const cli = parseArgs(process.argv.slice(2));
  const opts: RunOptions = {
    dryRun: cli.dryRun,
    approvedBy: cli.approvedBy,
    budgetUsd: cli.budgetUsd,
    maxCostUsd: cli.maxCostUsd,
  };

  const controlCount = await loadDomainControlCount(cli.domain);

  if (opts.dryRun) {
    const report = buildDryRunReport(cli.domain, controlCount);
    console.log(JSON.stringify(report, null, 2));
    console.log(
      `\ndry-run only — no dispatch, no cost. To run for real: re-run with ` +
        `--approved-by "<name>" naming who signed off on this spend.`,
    );
    return;
  }

  assertApprovedForRealRun(opts);

  const startedAt = new Date().toISOString();
  console.log(JSON.stringify(buildRunLogEntry(cli.domain, opts, startedAt), null, 2));

  // Reuse the PROMPT/PARSE pure functions (already tested, rockin-robin/test/rrAicmRound.test.ts)
  // via dynamic import rather than duplicating them. The dispatch LOOP itself is new code here,
  // not reimplementation of existing behavior: rr_aicm_batch.ts's own main()/dispatch() are not
  // exported (module-private) and its loop has no per-dispatch budget checkpoint to hook into,
  // so the guard this file exists to add has nowhere to attach without a new loop. Every prompt,
  // parse, and tally call below is imported, never rewritten.
  const roundMod = await import(`${RR_SCRIPTS}/rr_aicm_round.ts`);
  const batchMod = await import(`${RR_SCRIPTS}/rr_aicm_batch.ts`);
  const { CONTAINER, MAPPER_CONTAINER, PRIMITIVES, buildReviewsJson, parseNote, parseSynthesis, parseVerdict, tally, withIndependenceNote } =
    roundMod;
  const { domainControls, batchContributePrompt, batchSynthesizePrompt, batchReviewPrompt, parseBatchLines } = batchMod;

  const { spawn } = await import("node:child_process");
  const { mkdirSync, writeFileSync } = await import("node:fs");
  const { join } = await import("node:path");

  // No default: this is a real host + key, not something to bake into a public repo. Both
  // are required env vars, and dispatch fails loudly rather than silently pointing at
  // whichever host happened to be hardcoded here before.
  const VPS = process.env.AKCM_VPS;
  const SSH_KEY = process.env.AKCM_SSH_KEY;
  if (!VPS || !SSH_KEY) {
    throw new Error("AKCM_VPS and AKCM_SSH_KEY must both be set (no default host is shipped here)");
  }

  const spend = { input: 0, output: 0, cacheCreate: 0, cacheRead: 0, dispatches: 0 };
  function estimatedUsd(): number {
    // Same rate table as rockin-robin/docs/spend-ledger.md; approximate, not invoiced.
    return (
      (spend.input / 1_000_000) * 5 +
      (spend.output / 1_000_000) * 25 +
      (spend.cacheCreate / 1_000_000) * 6.25 +
      (spend.cacheRead / 1_000_000) * 0.5
    );
  }

  // The container's own configured user -- documented as a real operational detail of
  // the expert-* containers this dispatches to, not a secret, but still not hardcoded so
  // a different deployment's containers aren't assumed to share this account name.
  const CONTAINER_USER = process.env.AKCM_CONTAINER_USER ?? "isme";

  async function dispatch(container: string, prompt: string): Promise<string> {
    const remote =
      `docker exec -i -u ${CONTAINER_USER} -w /home/${CONTAINER_USER} -e AKCM_MAX_TURNS=${process.env.AKCM_MAX_TURNS ?? 24} ` +
      `${container} node /home/${CONTAINER_USER}/sdk_runner_v2.js -`;
    const out = await new Promise<string>((resolve, reject) => {
      const child = spawn("ssh", ["-i", SSH_KEY, "-o", "BatchMode=yes", VPS, remote]);
      let buf = "";
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        reject(new Error("timeout"));
      }, 1_500_000);
      child.stdout.on("data", (d) => (buf += d));
      child.on("close", () => {
        clearTimeout(timer);
        resolve(buf);
      });
      child.stdin.write(prompt);
      child.stdin.end();
    });
    for (const line of out.split("\n").reverse()) {
      const s = line.trim();
      if (!s.startsWith("{")) continue;
      try {
        const g = JSON.parse(s);
        if (g.event === "final") {
          spend.input += g.usage?.input_tokens ?? 0;
          spend.output += g.usage?.output_tokens ?? 0;
          spend.cacheCreate += g.usage?.cache_creation_input_tokens ?? 0;
          spend.cacheRead += g.usage?.cache_read_input_tokens ?? 0;
          spend.dispatches += 1;
          checkBudget(estimatedUsd(), opts.maxCostUsd); // guard fires right after each dispatch
          return g.ok ? String(g.text ?? "") : "";
        }
      } catch {
        /* not the final event */
      }
    }
    return "";
  }

  // No default: sources.md lives in a separate, private repo this tooling does not vendor.
  // Pass --sources-root explicitly (or set AKCM_SOURCES_ROOT) to point at your own checkout.
  const sourcesPath = cli.sourcesRoot ?? process.env.AKCM_SOURCES_ROOT;
  if (!sourcesPath) {
    throw new Error("--sources-root or AKCM_SOURCES_ROOT must be set (no default path is shipped here)");
  }
  // sources.md consulted ONLY for control identity (id/title/domain) -- the selection record's
  // supersedes-clause explicitly allows this as Stage 1-2 acquisition material, never the
  // retracted entries themselves. loadDomainControlCount() above uses the factory's own tested
  // AICM loader for the authoritative count reported in the dry-run.
  const { readFileSync } = await import("node:fs");
  const sources = roundMod.parseSources(readFileSync(sourcesPath, "utf8"));
  const controls = domainControls(sources, cli.domain);
  if (controls.length === 0) {
    throw new Error(`no controls found for domain "${cli.domain}" in ${sourcesPath}`);
  }

  const outDir = process.env.AKCM_OUT ?? join(process.cwd(), "docs", "akcm-runs", cli.domain.replace(/[^A-Za-z0-9]+/g, "-"));
  mkdirSync(outDir, { recursive: true });

  const contributions: Record<string, string> = {};
  for (const primitive of PRIMITIVES as readonly string[]) {
    const raw = await dispatch(CONTAINER[primitive], batchContributePrompt(primitive, controls));
    writeFileSync(join(outDir, `contribute-${primitive}.txt`), raw);
    contributions[primitive] = raw;
  }

  const synRaw = await dispatch(MAPPER_CONTAINER, batchSynthesizePrompt(controls, contributions));
  writeFileSync(join(outDir, "synthesize.txt"), synRaw);
  const parsed = parseSynthesis(synRaw);
  const arr = Array.isArray(parsed) ? parsed : parsed ? [parsed] : [];
  if (arr.length === 0) throw new Error("SYNTHESIZE returned nothing parseable — raw saved, do not re-dispatch");
  const withNotes = arr.map((s: Record<string, unknown>) => withIndependenceNote(s, [...(PRIMITIVES as readonly string[])]));
  writeFileSync(join(outDir, "synthesis.json"), JSON.stringify(withNotes, null, 2) + "\n");

  const perControl = new Map<string, unknown[]>();
  for (const primitive of PRIMITIVES as readonly string[]) {
    const raw = await dispatch(CONTAINER[primitive], batchReviewPrompt(controls, JSON.stringify(withNotes, null, 2)));
    writeFileSync(join(outDir, `review-${primitive}.txt`), raw);
    const lines = parseBatchLines(raw);
    for (const [id, parts] of lines) {
      const verdict = parseVerdict(`VERDICT: ${parts[0]}`);
      if (!verdict) continue;
      if (!perControl.has(id)) perControl.set(id, []);
      perControl.get(id)!.push({ reviewer: primitive, verdict, note: parts[1] ?? parseNote(raw) });
    }
  }

  const reviews: Record<string, unknown> = {};
  for (const c of controls) {
    Object.assign(reviews, buildReviewsJson(c.id, perControl.get(c.id) ?? [], startedAt.slice(0, 10)));
  }
  writeFileSync(join(outDir, "reviews.json"), JSON.stringify(reviews, null, 2) + "\n");

  console.log(`\nspend (approx): $${estimatedUsd().toFixed(2)} over ${spend.dispatches} dispatches`);
  console.log(
    `\nnext (not done by this script): emit_akcm_entry.py --synthesis ${join(outDir, "synthesis.json")} ` +
      `--reviews ${join(outDir, "reviews.json")} --run-id <id> --approved-by "${opts.approvedBy}"`,
  );
}

if (process.argv[1] && process.argv[1].endsWith("dispatch_domain.ts")) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
