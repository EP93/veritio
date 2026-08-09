import { describe, expect, test } from "bun:test";
import type {
  AuditEventInput,
  AuditRecord,
  EvidenceEdgeInput,
  EvidenceEdgeRecord,
  EvidenceEntity,
  ProvenanceSession,
} from "../index";
import {
  createAuditEvent,
  createEvidenceEdge,
  createProvenanceRecorder,
  HASH_ALGORITHM,
  hashEvidenceEdgeRecord,
  hashIdempotencyKey,
  MemoryAuditStore,
} from "../index";

/**
 * Conformance fixture pinning the provenance id derivations documented in
 * spec/provenance-identity.md. The cases are executed through the PUBLIC
 * recorder surface (link / recordFileChange / recordPrompt) — never through a
 * reimplementation of the derivation — so the fixture pins what the recorder
 * actually emits.
 */
const fixture = (await Bun.file(
  new URL("../../../../spec/conformance/provenance-ids.json", import.meta.url).pathname,
).json()) as {
  session: { sessionId: string; sessionEntity: EvidenceEntity };
  edgeCases: {
    name: string;
    ownerEventId: string | null;
    from: EvidenceEntity;
    relation: string;
    to: EvidenceEntity;
    expected: string;
  }[];
  promptEventCases: {
    name: string;
    promptHash: string;
    occurredAt: string | null;
    expected: string;
  }[];
  defaultEventIdCases: {
    name: string;
    kind: "file_change" | "tool";
    sourceTreeId?: string;
    resultVersion?: number | null;
    toolCallId?: string;
    expected: string;
  }[];
};

const SCOPE = { tenantId: "org_fixture_123", workspaceId: "wks_fixture_456", environment: "test" };

/**
 * Minimal sinks built only from exported SDK primitives, mirroring the harness
 * in provenance.test.ts: real MemoryAuditStore for events, tenant-chained
 * in-memory recorder for edges.
 */
function makeSinks() {
  const store = new MemoryAuditStore();
  let tip: EvidenceEdgeRecord | undefined;
  return {
    async recordEvent(input: AuditEventInput): Promise<AuditRecord> {
      return store.append(createAuditEvent(input));
    },
    async recordEdge(input: EvidenceEdgeInput): Promise<EvidenceEdgeRecord> {
      const edge = createEvidenceEdge(input);
      const recordWithoutHash: Omit<EvidenceEdgeRecord, "hash"> = {
        edge,
        sequence: (tip?.sequence ?? 0) + 1,
        previousHash: tip?.hash ?? null,
        hashAlgorithm: HASH_ALGORITHM,
        canonicalization: "veritio-json-v1",
        appendedAt: "2026-07-16T00:00:00.000Z",
        idempotencyKeyHash: hashIdempotencyKey(SCOPE.tenantId, edge.id),
      };
      const record: EvidenceEdgeRecord = {
        ...recordWithoutHash,
        hash: hashEvidenceEdgeRecord(recordWithoutHash),
      };
      tip = record;
      return record;
    },
  };
}

/**
 * Starts a session whose identity matches the fixture's `session` block so the
 * recorder-derived ids can be compared verbatim against fixture expectations.
 */
async function startFixtureSession(): Promise<ProvenanceSession> {
  const recorder = createProvenanceRecorder(makeSinks());
  const { session } = await recorder.startSession({
    scope: SCOPE,
    sessionId: fixture.session.sessionId,
    occurredAt: "2026-07-16T00:00:00.000Z",
    initiatedBy: { type: "user", id: "usr_fixture" },
    agentActor: { type: "ai_agent", id: "agent_fixture" },
    agent: { name: "fixture-agent", version: "1.0" },
    model: { provider: "anthropic", name: "claude-fable-5" },
  });
  return session;
}

describe("provenance id conformance (spec/conformance/provenance-ids.json)", () => {
  test("edge ids: singleton link() vs occurrence-scoped record-method edges", async () => {
    const session = await startFixtureSession();
    for (const edgeCase of fixture.edgeCases) {
      if (edgeCase.ownerEventId === null) {
        const record = await session.link(
          edgeCase.from,
          edgeCase.relation as never,
          edgeCase.to,
          {},
          "2026-07-16T00:01:00.000Z",
        );
        expect(record.edge.id).toBe(edgeCase.expected);
        continue;
      }
      // Occurrence-scoped cases replay a file modification under a
      // caller-supplied owning event id; the recorder's changedBy default is
      // the session entity, which the fixture's `from` must therefore equal.
      expect(edgeCase.from).toEqual(fixture.session.sessionEntity);
      const result = await session.recordFileChange({
        id: edgeCase.ownerEventId,
        sourceTreeId: "tree_fixture",
        resultVersion: 1,
        occurredAt: "2026-07-16T00:02:00.000Z",
        files: [
          {
            id: edgeCase.to.id,
            pathHash: edgeCase.to.pathHash as string,
            afterHash: "sha256:after_fixture",
            action: "upsert",
          },
        ],
      });
      expect(result.edges[0]!.edge.id).toBe(edgeCase.expected);
    }
  });

  test("prompt event ids: constant without occurredAt, normalized UTC suffix with it", async () => {
    const session = await startFixtureSession();
    for (const promptCase of fixture.promptEventCases) {
      const result = await session.recordPrompt({
        promptHash: promptCase.promptHash,
        ...(promptCase.occurredAt === null ? {} : { occurredAt: promptCase.occurredAt }),
      });
      expect(result.event.event.id).toBe(promptCase.expected);
    }
  });

  test("default event ids: file-change (present + absent resultVersion sentinel) and tool occurrence", async () => {
    const session = await startFixtureSession();
    for (const eventCase of fixture.defaultEventIdCases) {
      if (eventCase.kind === "tool") {
        const result = await session.recordToolCall({
          toolCallId: eventCase.toolCallId as string,
          tool: "fixture_tool",
          status: "succeeded",
          occurredAt: "2026-07-16T00:03:00.000Z",
        });
        expect(result.event.event.id).toBe(eventCase.expected);
        continue;
      }
      const result = await session.recordFileChange({
        sourceTreeId: eventCase.sourceTreeId as string,
        // A null fixture resultVersion pins the absent-field `x` sentinel.
        ...(eventCase.resultVersion === null ? {} : { resultVersion: eventCase.resultVersion }),
        occurredAt: "2026-07-16T00:03:00.000Z",
        files: [
          {
            id: "file_fixture_a",
            pathHash: "sha256:pathdigest_fixture",
            afterHash: "sha256:after_fixture",
            action: "upsert",
          },
        ],
      });
      expect(result.event.event.id).toBe(eventCase.expected);
    }
  });
});
