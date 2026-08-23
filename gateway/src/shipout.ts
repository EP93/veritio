/**
 * Optional cloud ship-out: wraps the local evidence sink so every locally
 * committed gateway event is also enqueued into a durable outbox for async
 * delivery to a Veritio ingest endpoint (`@veritio/storage`'s HTTP outbox
 * dispatcher drains it on the host's retry interval).
 *
 * Ordering invariant (rule 09): the LOCAL append is the authoritative write
 * and must succeed first; the enqueue is a best-effort post-success
 * follow-up. An enqueue failure never fails the request, never touches the
 * health gate, and logs one sanitized warning — the local chain remains
 * complete, so nothing is lost, only not mirrored. Retries are idempotent:
 * the enqueued event carries the locally assigned record id, and the ingest
 * endpoint deduplicates by record id (server re-redacts and re-chains).
 */
import type { AuditEventInput, AuditRecord } from "@veritio/core";
import { type OutboxAdapter, OutboxQueueFullError } from "@veritio/storage";
import type { GatewayEvidenceSink } from "./evidence";

/** Why one remote-delivery copy was dropped; the local record is always kept. */
export type ShipOutEnqueueFailure = "error" | "queue_full";

/** Options for the ship-out wrapper; the host injects the configured outbox. */
export interface ShipOutSinkOptions {
  outbox: OutboxAdapter;
  tenantId: string;
  /** Sanitized warning hook; defaults to a value-free console.error line. */
  onEnqueueError?: (eventId: string, reason: ShipOutEnqueueFailure) => void;
}

/**
 * Wraps `local` so each recorded event is mirrored into the outbox as one
 * entry (one entry → one ingest POST). Entry id derives from the event id,
 * so an enqueue retry after a crash cannot double-queue the same event.
 */
export function createShipOutSink(local: GatewayEvidenceSink, options: ShipOutSinkOptions): GatewayEvidenceSink {
  const warn =
    options.onEnqueueError ??
    ((eventId: string, reason: ShipOutEnqueueFailure) => {
      console.error(
        reason === "queue_full"
          ? `veritio-gateway: cloud ship-out outbox is full; holding new remote copies (event ${eventId} kept locally)`
          : `veritio-gateway: cloud ship-out enqueue failed for event ${eventId}; local record kept`,
      );
    });

  return {
    async recordEvent(input: AuditEventInput): Promise<AuditRecord> {
      const record = await local.recordEvent(input);
      try {
        await options.outbox.transaction((tx) =>
          tx.enqueue({
            id: `obx_${record.event.id}`,
            tenantId: options.tenantId,
            payload: {
              schemaVersion: "2026-06-23",
              mutationBinding: "best_effort",
              records: [record.event],
              edges: [],
            },
          }),
        );
      } catch (error) {
        warn(record.event.id, error instanceof OutboxQueueFullError ? "queue_full" : "error");
      }
      return record;
    },
  };
}
