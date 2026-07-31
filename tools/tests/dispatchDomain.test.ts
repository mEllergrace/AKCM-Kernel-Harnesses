// Tests for the new dry-run/budget/approval guard around the reused rr_aicm_batch.ts
// dispatch logic. No dispatch here either, same reasoning as
// rockin-robin/test/rrAicmRound.test.ts: these would otherwise cost real money to check,
// and the spend gate (docs/HANDOFF.md rule 8) is exactly the thing under test.

import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  BudgetExceededError,
  assertApprovedForRealRun,
  buildDryRunReport,
  checkBudget,
} from "../dispatch_domain.ts";

test("dry-run report: 13 dispatches regardless of control count (batched, not per-control)", () => {
  const r1 = buildDryRunReport("Universal Endpoint Management", 14);
  const r2 = buildDryRunReport("Audit & Assurance", 3);
  assert.equal(r1.dispatchCount, 13);
  assert.equal(r2.dispatchCount, 13);
});

test("dry-run report: estimated cost scales with control count at the measured batched rate", () => {
  const r = buildDryRunReport("Universal Endpoint Management", 14);
  assert.equal(r.controlCount, 14);
  assert.ok(r.estimatedCostUsd > 0);
  // measured ~$0.20-0.27/control batched (spend-ledger.md) -- 14 controls should land
  // well under the ~$6/control CONTESTED-single-control rate, or the estimate is wrong
  // in a way that would spook a real sign-off decision.
  assert.ok(r.estimatedCostUsd < 14 * 1.0, "batched estimate should not resemble the contested single-control rate");
});

test("checkBudget: no max-cost set never throws", () => {
  assert.doesNotThrow(() => checkBudget(999, undefined));
});

test("checkBudget: under the cap does not throw", () => {
  assert.doesNotThrow(() => checkBudget(5, 10));
});

test("checkBudget: over the cap throws BudgetExceededError", () => {
  assert.throws(() => checkBudget(15, 10), BudgetExceededError);
});

test("assertApprovedForRealRun: dry-run never requires an approver", () => {
  assert.doesNotThrow(() => assertApprovedForRealRun({ dryRun: true }));
});

test("assertApprovedForRealRun: a real run with no approver refuses", () => {
  assert.throws(() => assertApprovedForRealRun({ dryRun: false }));
});

test("assertApprovedForRealRun: a real run with a blank approver still refuses", () => {
  assert.throws(() => assertApprovedForRealRun({ dryRun: false, approvedBy: "   " }));
});

test("assertApprovedForRealRun: who approves is a real, per-run option -- any named approver works", () => {
  assert.doesNotThrow(() => assertApprovedForRealRun({ dryRun: false, approvedBy: "Kurt Seifried" }));
  assert.doesNotThrow(() => assertApprovedForRealRun({ dryRun: false, approvedBy: "Grace" }));
});
