import type { AuditEvent } from "@veritio/core";

import { saveToSpool } from "../../spool.js";

/** Writes one deterministic batch from a separate process for lock conformance testing. */
function main(): void {
  const localDir = process.argv[2];
  const id = process.argv[3];
  if (!localDir || !id) {
    throw new Error("spool writer requires localDir and event id");
  }
  const event = {
    id,
    schemaVersion: "1.0",
    occurredAt: "2026-08-02T00:00:00.000Z",
    actor: { id: "writer", type: "agent" },
    action: "debug.spool.concurrent",
    target: { id: "queue", type: "diagnostic" },
    metadata: {},
  } as unknown as AuditEvent;
  if (saveToSpool(localDir, { events: [event], edges: [] }) === "failed") {
    process.exit(1);
  }
}

main();
