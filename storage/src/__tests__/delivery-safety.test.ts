import { describe, expect, test } from "bun:test";

import { DEFAULT_DELIVERY_SAFETY_POLICY, parseDeliverySafetyPolicy } from "../delivery-safety";

describe("delivery safety policy", () => {
  test("returns finite non-zero fail-safe defaults", () => {
    const policy = parseDeliverySafetyPolicy(undefined);
    expect(policy).toEqual(DEFAULT_DELIVERY_SAFETY_POLICY);
    for (const value of [...Object.values(policy.recommended), ...Object.values(policy.hard)]) {
      expect(Number.isFinite(value)).toBe(true);
      expect(value).toBeGreaterThan(0);
    }
  });

  test("accepts a stricter complete policy and returns an immutable clone", () => {
    const input = {
      recommended: { queuedBytes: 1_000, rollingSendBytes: 500 },
      hard: {
        batchBytes: 2_000,
        queuedBytes: 4_000,
        rollingSendBytes: 2_000,
        rollingRequests: 2,
        windowMs: 60_000,
        automaticReplayBatches: 1,
      },
    };
    const parsed = parseDeliverySafetyPolicy(input);
    expect(parsed).toEqual(input);
    expect(parsed).not.toBe(input);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.hard)).toBe(true);
  });

  test("rejects zero, infinity, fractions, excess recommendations, and unbounded replay", () => {
    const base = structuredClone(DEFAULT_DELIVERY_SAFETY_POLICY);
    for (const bad of [0, -1, Number.POSITIVE_INFINITY, 1.5]) {
      expect(() => parseDeliverySafetyPolicy({ ...base, hard: { ...base.hard, rollingRequests: bad } })).toThrow();
    }
    expect(() =>
      parseDeliverySafetyPolicy({
        ...base,
        recommended: { ...base.recommended, queuedBytes: base.hard.queuedBytes + 1 },
      }),
    ).toThrow("recommended.queuedBytes");
    expect(() => parseDeliverySafetyPolicy({ ...base, hard: { ...base.hard, automaticReplayBatches: 2 } })).toThrow(
      "automaticReplayBatches",
    );
  });
});
