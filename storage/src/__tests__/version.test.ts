import { expect, test } from "bun:test";
import { VERITIO_CORE_VERSION } from "@veritio/core";
import { RETENTION_COORDINATOR_CAPABILITY, VERITIO_STORAGE_VERSION } from "../index";

test("exports exact coordinated package identities and the immutable retention capability", () => {
  expect(VERITIO_CORE_VERSION).toBe("0.4.8");
  expect(VERITIO_STORAGE_VERSION).toBe("0.4.8");
  expect(RETENTION_COORDINATOR_CAPABILITY).toEqual({
    api: "runRetentionEpoch",
    apiVersion: "1.0",
    protocol: "veritio.retention",
    schemaVersion: "1.0",
    resolvesDisposedAtAfterConfirmedAbsence: true,
    requiresAttemptIdempotentDisposedAtResolver: true,
    mayReinvokeDisposedAtAfterReceiptPersistenceFailure: true,
    replaysAcceptedDispositionWithoutResolvingDisposedAt: true,
  });
  expect(Object.isFrozen(RETENTION_COORDINATOR_CAPABILITY)).toBe(true);
});
