import { describe, expect, test } from "bun:test";
import { parseExportBundle, verifyExportBundle } from "@veritio/core";
import {
  LocalEvidenceStore,
  type SecurityRiskAssertion,
  createWorkbenchApp,
  handleMcpRequest,
  runGovernedChangeScenario,
  runChangeProvenanceScenario,
  runIntegrationScenario,
  runRecorderProvenanceScenario,
} from "../index";

const tenantId = "org_local_123";

function eventInput(id = "evt_local_01") {
  return {
    id,
    occurredAt: "2026-06-14T00:00:00.000Z",
    actor: { type: "user" as const, id: "usr_123" },
    action: "org.member.invited",
    target: { type: "organization", id: tenantId },
    scope: { tenantId, environment: "test" },
    purpose: "access_management",
    dataCategories: ["account"],
    retention: "security_1y",
    metadata: { invitedEmail: "member@example.invalid", role: "viewer" },
  };
}

function edgeInput(id = "edge_local_01") {
  return {
    id,
    occurredAt: "2026-06-14T00:00:01.000Z",
    scope: { tenantId, environment: "test" },
    from: { type: "actor" as const, id: "usr_123", actorType: "user" as const },
    relation: "created" as const,
    to: { type: "runtime_event" as const, id: "evt_local_01" },
    metadata: { reason: "member_invite" },
  };
}

async function json(response: Response) {
  return (await response.json()) as Record<string, unknown>;
}

describe("LocalEvidenceStore", () => {
  test("records events and edges, projects a graph, verifies chains, and previews an export bundle", async () => {
    const store = new LocalEvidenceStore();

    const eventRecord = await store.recordEvent(eventInput(), { idempotencyKey: "invite:usr_123" });
    const edgeRecord = await store.recordEdge(edgeInput(), { idempotencyKey: "edge:usr_123:evt_local_01" });

    expect(eventRecord.event.metadata).toEqual({ invitedEmail: "[redacted]", role: "viewer" });
    expect(edgeRecord.edge.relation).toBe("created");
    expect(await store.listEvents({ tenantId })).toEqual([eventRecord]);
    expect(await store.listEdges({ tenantId })).toEqual([edgeRecord]);
    expect(await store.getEvent("evt_local_01")).toEqual(eventRecord);

    const verification = await store.verify({ tenantId });
    expect(verification.ok).toBe(true);
    expect(verification.audit).toEqual({ ok: true });
    expect(verification.edges).toEqual({ ok: true });
    expect(verification.commits).toEqual({ ok: true });

    const graph = await store.getEvidenceGraph({ tenantId, rootId: "evt_local_01" });
    expect(graph.nodes.map((node) => node.id).sort()).toEqual(["evt_local_01", "usr_123"]);
    expect(graph.edges).toEqual([
      {
        id: "edge_local_01",
        from: "usr_123",
        to: "evt_local_01",
        relation: "created",
        source: "edge_record",
        recordHash: edgeRecord.hash,
      },
    ]);

    const bundle = await store.previewExportBundle({ tenantId });
    expect(bundle.manifest.recordCounts).toEqual({ events: 1, edges: 1, commits: 0 });
    expect(bundle.manifest.verification.ok).toBe(true);
    expect(bundle.eventsJsonl).toContain('"id":"evt_local_01"');
    expect(bundle.edgesJsonl).toContain('"id":"edge_local_01"');
    expect(bundle.redactionManifest.rules).toContain(
      "metadata keys matching password|secret|token|api[_-]?key|authorization|email|phone|ssn are replaced with [redacted]",
    );

    await store.reset();
    expect(await store.listEvents({ tenantId })).toEqual([]);
    expect(await store.listEdges({ tenantId })).toEqual([]);
  });

  test("batch records event and edge members with an EvidenceCommit", async () => {
    const store = new LocalEvidenceStore();

    const batch = await store.recordBatch({
      commitId: "cmt_local_memory_01",
      streamId: "str_local_memory",
      events: [eventInput("evt_batch_memory")],
      edges: [edgeInput("edge_batch_memory")],
      committedAt: "2026-06-23T10:15:31.000Z",
    });

    expect(batch.commit.recordCount).toBe(2);
    expect(batch.commit.members.map((member) => member.recordType)).toEqual(["audit.record", "evidence.edge.record"]);
    const replay = await store.recordBatch({
      commitId: "cmt_local_memory_01",
      streamId: "str_local_memory",
      events: [eventInput("evt_batch_memory")],
      edges: [edgeInput("edge_batch_memory")],
      committedAt: "2026-06-23T10:15:31.000Z",
    });
    expect(replay.commit).toEqual(batch.commit);
    expect(await store.listCommits({ streamId: "str_local_memory" })).toEqual([batch.commit]);
    expect(await store.verify({ tenantId })).toMatchObject({ ok: true, commits: { ok: true } });
  });

  test("runs the local integration scenario from agent session to runtime audit event", async () => {
    const store = new LocalEvidenceStore();

    const result = await runIntegrationScenario(store, { tenantId });

    expect(result.verification.ok).toBe(true);
    expect(result.graph.nodes.map((node) => node.type)).toContain("agent_session");
    expect(result.graph.nodes.map((node) => node.type)).toContain("runtime_event");
    expect(result.graph.edges.map((edge) => edge.relation)).toEqual(["created", "deployed_as", "observed_in"]);
  });

  test("runs the detailed change provenance scenario across agent, review, CI, deploy, and runtime evidence", async () => {
    const store = new LocalEvidenceStore();

    const result = await runChangeProvenanceScenario(store, { tenantId });

    expect(result.verification.ok).toBe(true);
    expect(result.exportPreview.manifest.recordCounts).toEqual({ events: 9, edges: 14, commits: 0 });
    expect(result.graph.nodes.map((node) => node.type)).toEqual(
      expect.arrayContaining([
        "actor",
        "agent_session",
        "tool_call",
        "file",
        "diff_hunk",
        "artifact",
        "ci_run",
        "deployment",
        "policy",
        "runtime_event",
      ]),
    );
    expect(result.graph.edges.map((edge) => edge.relation)).toEqual(
      expect.arrayContaining([
        "caused_by",
        "modified",
        "approved_by",
        "derived_from",
        "built_by",
        "deployed_as",
        "satisfies_policy",
        "observed_in",
      ]),
    );
  });

  test("runs the same provenance graph through the createProvenanceRecorder API", async () => {
    const store = new LocalEvidenceStore();

    const result = await runRecorderProvenanceScenario(store, { tenantId });

    expect(result.verification.ok).toBe(true);
    expect(result.graph.nodes.map((node) => node.type)).toEqual(
      expect.arrayContaining([
        "actor",
        "agent_session",
        "tool_call",
        "file",
        "diff_hunk",
        "deployment",
        "runtime_event",
      ]),
    );
    // The enforcing human is reachable from the session via a caused_by edge, and
    // the recorder emits the full downstream relation set without a schema change.
    expect(result.graph.edges.map((edge) => edge.relation)).toEqual(
      expect.arrayContaining([
        "caused_by",
        "created",
        "read",
        "modified",
        "part_of",
        "approved_by",
        "built_by",
        "deployed_as",
        "satisfies_policy",
        "observed_in",
      ]),
    );
    const sessionToHuman = result.graph.edges.some(
      (edge) => edge.from === "agt_sess_recorder_01" && edge.relation === "caused_by" && edge.to === "usr_builder",
    );
    expect(sessionToHuman).toBe(true);
  });

  test("projects governed changes, entity timelines, explain, and diff from current protocol evidence", async () => {
    const store = new LocalEvidenceStore();

    const result = await runGovernedChangeScenario(store, { tenantId });

    expect(result.verification.ok).toBe(true);
    expect(result.exportPreview.manifest.recordCounts.commits).toBe(2);
    expect(result.changes).toHaveLength(2);
    expect(result.changes[0]).toMatchObject({
      id: "chg_project_entry_revert_01",
      status: "declared",
      title: "project.entry.rollback",
      outputRevisionIds: expect.arrayContaining([expect.stringContaining("rev_project_entry_42_")]),
    });
    expect(result.entityTimeline.revisions).toHaveLength(2);
    expect(result.explain.changeId).toBe("chg_project_entry_price_01");
    expect(result.explain.evidenceAssurance).toEqual(["current-protocol relation links present"]);
    expect(result.explain.knownCoverage).toEqual(["change", "activity", "revision", "relations", "audit_records"]);
    expect(result.explain.notCaptured).toEqual([
      "raw full row",
      "business transaction proof",
      "independent state verification",
    ]);
    expect(result.diff.changedPaths).toEqual(["/monthlyPrice", "/quantity"]);
    expect(result.diff.after.monthlyPrice).toBe(148220);
    expect(JSON.stringify(result.entityTimeline)).not.toContain("buyer@example.com");
  });

  test("records an activity.episode.started event, threads activityEpisodeId, and never scores", async () => {
    const store = new LocalEvidenceStore();
    const activityEpisodeId = "ae_sess_demo_01";

    const record = await store.recordEvent(
      {
        id: "evt_episode_started_01",
        occurredAt: "2026-06-23T10:00:00.000Z",
        actor: { type: "ai_agent", id: "agent_cc" },
        action: "activity.episode.started",
        target: { type: "activity_episode", id: activityEpisodeId },
        scope: { tenantId, environment: "test" },
        purpose: "agent_provenance",
        retention: "security_1y",
        metadata: { activityEpisodeId, domain: "code", startReason: "session_start" },
      },
      { idempotencyKey: `episode:${activityEpisodeId}` },
    );

    expect(record.event.action).toBe("activity.episode.started");
    expect(record.event.target).toEqual({ type: "activity_episode", id: activityEpisodeId });
    expect(record.event.metadata).toMatchObject({ activityEpisodeId, domain: "code", startReason: "session_start" });
    // The local server is a sink, not a detector: no score is added.
    expect(record.event.metadata).not.toHaveProperty("score");
    expect(record.event.metadata).not.toHaveProperty("level");

    const listed = await store.listEvents({ tenantId });
    expect(listed.map((entry) => entry.event.id)).toContain("evt_episode_started_01");
    expect(await store.verify({ tenantId })).toMatchObject({ ok: true });
  });

  test("stores a precomputed security.risk assertion verbatim, links it by based_on, and never scores", async () => {
    const store = new LocalEvidenceStore();
    const assertion: SecurityRiskAssertion = {
      recordType: "assertion.recorded",
      schemaVersion: "2026-06-23",
      recordAuthority: "veritio",
      id: "risk_01jz_concurrent_activity",
      type: "security.risk",
      scope: { tenantId, environment: "test" },
      occurredAt: "2026-06-23T10:15:32.000Z",
      producer: {
        authority: "veritio.detectors",
        kind: "principal",
        type: "service",
        id: "concurrent-activity-detector",
      },
      idempotencyKeyHash: `sha256:${"0".repeat(64)}`,
      subject: { authority: "veritio", kind: "activity", type: "activity_episode", id: "ae_sess_demo_01" },
      conclusion: { score: 0.86, level: "high", policyVersion: "veritio.reference.v1", assessment: "episode_rollup" },
      factors: [{ key: "velocityScore", value: 0.4, kind: "additive", weight: 1, contribution: 0.4 }],
    };

    const result = await store.recordAssertion(assertion);
    // Sink, not detector: the conclusion is preserved byte-for-byte.
    expect(result.assertion.conclusion.score).toBe(0.86);
    expect(result.assertion).toEqual(assertion);
    expect(result.hash.startsWith("sha256:")).toBe(true);

    expect(result.edge.edge.relation).toBe("based_on");
    expect(result.edge.edge.from).toMatchObject({ type: "assertion", id: assertion.id });
    expect(result.edge.edge.to).toMatchObject({ type: "activity", id: "ae_sess_demo_01" });

    expect(await store.listAssertions({ tenantId })).toEqual([assertion]);

    // Idempotent replay returns the same linkage and does not duplicate the edge.
    const replay = await store.recordAssertion(assertion);
    expect(replay.edge.edge.id).toBe(result.edge.edge.id);
    expect(await store.listAssertions({ tenantId })).toEqual([assertion]);
    expect(await store.verify({ tenantId })).toMatchObject({ ok: true });
  });

  test("fails closed when a same-tenant same-id assertion arrives with a changed conclusion.score", async () => {
    const store = new LocalEvidenceStore();
    const assertion: SecurityRiskAssertion = {
      recordType: "assertion.recorded",
      schemaVersion: "2026-06-23",
      recordAuthority: "veritio",
      id: "risk_01jz_conflict",
      type: "security.risk",
      scope: { tenantId, environment: "test" },
      occurredAt: "2026-06-23T10:15:32.000Z",
      producer: {
        authority: "veritio.detectors",
        kind: "principal",
        type: "service",
        id: "concurrent-activity-detector",
      },
      idempotencyKeyHash: `sha256:${"0".repeat(64)}`,
      subject: { authority: "veritio", kind: "activity", type: "activity_episode", id: "ae_sess_demo_01" },
      conclusion: { score: 0.86, level: "high", policyVersion: "veritio.reference.v1", assessment: "episode_rollup" },
      factors: [{ key: "velocityScore", value: 0.4, kind: "additive", weight: 1, contribution: 0.4 }],
    };

    await store.recordAssertion(assertion);
    const mutated: SecurityRiskAssertion = {
      ...assertion,
      conclusion: { ...assertion.conclusion, score: 0.42 },
    };
    expect(store.recordAssertion(mutated)).rejects.toThrow("assertion id conflict");
    // Fail-closed: the rejected body adds no assertion, edge, or chain state.
    expect(await store.listAssertions({ tenantId })).toEqual([assertion]);
    expect((await store.listEdges({ tenantId })).length).toBe(1);
    expect(await store.verify({ tenantId })).toMatchObject({ ok: true });
  });

  test("accepts the same assertion id under a different tenant (dedup is tenant-scoped)", async () => {
    const store = new LocalEvidenceStore();
    const otherTenant = "org_other_999";
    const assertion: SecurityRiskAssertion = {
      recordType: "assertion.recorded",
      schemaVersion: "2026-06-23",
      recordAuthority: "veritio",
      id: "risk_shared_id",
      type: "security.risk",
      scope: { tenantId, environment: "test" },
      occurredAt: "2026-06-23T10:15:32.000Z",
      producer: {
        authority: "veritio.detectors",
        kind: "principal",
        type: "service",
        id: "concurrent-activity-detector",
      },
      idempotencyKeyHash: `sha256:${"0".repeat(64)}`,
      subject: { authority: "veritio", kind: "activity", type: "activity_episode", id: "ae_sess_demo_01" },
      conclusion: { score: 0.86, level: "high", policyVersion: "veritio.reference.v1", assessment: "episode_rollup" },
      factors: [{ key: "velocityScore", value: 0.4, kind: "additive", weight: 1, contribution: 0.4 }],
    };
    const otherTenantAssertion: SecurityRiskAssertion = {
      ...assertion,
      scope: { tenantId: otherTenant, environment: "test" },
    };

    const first = await store.recordAssertion(assertion);
    const second = await store.recordAssertion(otherTenantAssertion);

    // Same id, different tenant => not a conflict; each tenant sees only its own.
    expect(await store.listAssertions({ tenantId })).toEqual([assertion]);
    expect(await store.listAssertions({ tenantId: otherTenant })).toEqual([otherTenantAssertion]);
    expect(first.edge.edge.scope.tenantId).toBe(tenantId);
    expect(second.edge.edge.scope.tenantId).toBe(otherTenant);
    expect(await store.verify({ tenantId })).toMatchObject({ ok: true });
    expect(await store.verify({ tenantId: otherTenant })).toMatchObject({ ok: true });
  });

  test("fails closed when an assertion scope is missing tenantId", async () => {
    const store = new LocalEvidenceStore();
    const assertion = {
      recordType: "assertion.recorded",
      schemaVersion: "2026-06-23",
      recordAuthority: "veritio",
      id: "risk_missing_tenant",
      type: "security.risk",
      scope: { environment: "test" },
      occurredAt: "2026-06-23T10:15:32.000Z",
      producer: {
        authority: "veritio.detectors",
        kind: "principal",
        type: "service",
        id: "concurrent-activity-detector",
      },
      idempotencyKeyHash: `sha256:${"0".repeat(64)}`,
      subject: { authority: "veritio", kind: "activity", type: "activity_episode", id: "ae_sess_demo_01" },
      conclusion: { score: 0.86, level: "high", policyVersion: "veritio.reference.v1", assessment: "episode_rollup" },
      factors: [{ key: "velocityScore", value: 0.4, kind: "additive", weight: 1, contribution: 0.4 }],
    } as unknown as SecurityRiskAssertion;

    expect(store.recordAssertion(assertion)).rejects.toThrow("assertion.scope.tenantId is required");
    expect(await store.listAssertions({ tenantId })).toEqual([]);
  });
});

describe("Workbench HTTP app", () => {
  test("serves Workbench UI and local evidence API routes", async () => {
    const store = new LocalEvidenceStore();
    const app = createWorkbenchApp({ store, allowWriteTools: true });

    const home = await app.fetch(new Request("http://veritio.local/"));
    expect(home.headers.get("content-type")).toContain("text/html");
    const homeText = await home.text();
    expect(homeText).toContain("Veritio Workbench");
    expect(homeText).toContain("Evidence Commits");

    const favicon = await app.fetch(new Request("http://veritio.local/favicon.ico"));
    expect(favicon.status).toBe(204);

    const eventResponse = await app.fetch(
      new Request("http://veritio.local/v1/events", {
        method: "POST",
        body: JSON.stringify(eventInput()),
      }),
    );
    expect(eventResponse.status).toBe(201);

    const edgeResponse = await app.fetch(
      new Request("http://veritio.local/v1/edges", {
        method: "POST",
        body: JSON.stringify(edgeInput()),
      }),
    );
    expect(edgeResponse.status).toBe(201);

    const graphResponse = await app.fetch(new Request(`http://veritio.local/v1/graph?tenantId=${tenantId}`));
    const graph = await json(graphResponse);
    expect((graph.nodes as unknown[]).length).toBeGreaterThanOrEqual(2);

    const verifyResponse = await app.fetch(new Request(`http://veritio.local/v1/verify?tenantId=${tenantId}`));
    expect(await json(verifyResponse)).toMatchObject({ ok: true });

    const exportResponse = await app.fetch(
      new Request("http://veritio.local/v1/exports/preview", {
        method: "POST",
        body: JSON.stringify({ tenantId }),
      }),
    );
    expect((await json(exportResponse)).manifest).toMatchObject({ recordCounts: { events: 1, edges: 1 } });

    const changeScenarioResponse = await app.fetch(
      new Request("http://veritio.local/v1/scenarios/change-provenance", {
        method: "POST",
        body: JSON.stringify({ tenantId: "tenant_change_http" }),
      }),
    );
    expect(changeScenarioResponse.status).toBe(200);
    expect(await json(changeScenarioResponse)).toMatchObject({
      verification: { ok: true },
      exportPreview: { manifest: { recordCounts: { events: 9, edges: 14 } } },
    });

    const governedScenarioResponse = await app.fetch(
      new Request("http://veritio.local/v1/scenarios/governed-change", {
        method: "POST",
        body: JSON.stringify({ tenantId: "tenant_governed_http" }),
      }),
    );
    expect(governedScenarioResponse.status).toBe(200);
    const governedScenario = await json(governedScenarioResponse);
    expect(governedScenario).toMatchObject({
      verification: { ok: true },
      exportPreview: { manifest: { recordCounts: { commits: 2 } } },
      changes: [{ id: "chg_project_entry_revert_01" }, { id: "chg_project_entry_price_01" }],
    });
    const changesResponse = await app.fetch(
      new Request("http://veritio.local/v1/changes?tenantId=tenant_governed_http"),
    );
    expect((await json(changesResponse)).records).toHaveLength(2);
    const commitsResponse = await app.fetch(new Request("http://veritio.local/v1/commits"));
    expect((await json(commitsResponse)).records).toHaveLength(2);
  });
});

describe("MCP JSON-RPC handler", () => {
  test("create_export_bundle selects vevb-2 only from injected checkpoint inputs", async () => {
    const store = new LocalEvidenceStore();
    const fixture = await Bun.file(
      new URL("../../../../spec/conformance/export-bundle-v2-golden.json", import.meta.url).pathname,
    ).json();
    const checkpointLines = fixture.bundle.files["records/retention-checkpoints.jsonl"].trim().split("\n");
    const dispositionLines = fixture.bundle.files["records/retention-dispositions.jsonl"].trim().split("\n");
    const exportTenantId = fixture.bundle.manifest.scope.tenantId;
    const response = await handleMcpRequest(
      store,
      {
        jsonrpc: "2.0",
        id: 10,
        method: "tools/call",
        params: {
          name: "veritio.create_export_bundle",
          arguments: {
            tenantId: exportTenantId,
            createdAt: "2026-08-24T00:12:02.000Z",
            bundleVersion: "vevb-2",
            auditOrigin: fixture.bundle.manifest.chainClaims.audit.origin,
            checkpoints: checkpointLines.map((line: string) => JSON.parse(line)),
            dispositions: dispositionLines.map((line: string) => JSON.parse(line)),
          },
        },
      },
      { allowWriteTools: true },
    );
    expect(response.error).toBeUndefined();
    expect(response.result.bundleVersion).toBe("vevb-2");
    expect(response.result.verification.checks).toMatchObject({
      checkpoints: true,
      dispositions: true,
      audit: true,
      edges: true,
      commits: true,
    });
    const bundle = parseExportBundle(response.result.bundle as string);
    expect(bundle.bundleVersion).toBe("vevb-2");
    expect((await verifyExportBundle(bundle)).valid).toBe(true);
  });

  test("create_export_bundle refuses to hide existing EvidenceCommit records in vevb-2", async () => {
    const store = new LocalEvidenceStore();
    await store.recordBatch({
      commitId: "cmt_v2_rejected",
      streamId: "str_v2_rejected",
      events: [eventInput("evt_v2_rejected")],
      edges: [],
      committedAt: "2026-08-24T00:00:00.000Z",
    });
    const response = await handleMcpRequest(
      store,
      {
        jsonrpc: "2.0",
        id: 11,
        method: "tools/call",
        params: {
          name: "veritio.create_export_bundle",
          arguments: {
            tenantId,
            createdAt: "2026-08-24T00:12:02.000Z",
            bundleVersion: "vevb-2",
            auditOrigin: { kind: "genesis" },
            checkpoints: [],
            dispositions: [],
          },
        },
      },
      { allowWriteTools: true },
    );
    expect(response.error.message).toBe("vevb-2 requires an empty EvidenceCommit list");
  });

  test("lists read tools by default and hides write tools", async () => {
    const store = new LocalEvidenceStore();

    const response = await handleMcpRequest(store, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
      params: {},
    });

    expect(response).toMatchObject({ jsonrpc: "2.0", id: 1 });
    const toolNames = response.result.tools.map((tool: { name: string }) => tool.name);
    expect(toolNames).toContain("veritio.list_events");
    expect(toolNames).toContain("veritio.preview_export_bundle");
    expect(toolNames).toContain("veritio.run_change_provenance_scenario");
    expect(toolNames).not.toContain("veritio.record_event");
  });

  test("allows write tools only when explicitly enabled", async () => {
    const store = new LocalEvidenceStore();
    const blocked = await handleMcpRequest(store, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "veritio.record_event", arguments: eventInput() },
    });
    expect(blocked.error.message).toBe("MCP write tools are disabled");

    const written = await handleMcpRequest(
      store,
      {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "veritio.record_event", arguments: eventInput() },
      },
      { allowWriteTools: true },
    );
    expect(written.result.record.event.id).toBe("evt_local_01");

    const listed = await handleMcpRequest(store, {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "veritio.list_events", arguments: { tenantId } },
    });
    expect(listed.result.records).toHaveLength(1);
  });

  test("runs the change provenance scenario through MCP", async () => {
    const store = new LocalEvidenceStore();

    const response = await handleMcpRequest(store, {
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: {
        name: "veritio.run_change_provenance_scenario",
        arguments: { tenantId: "tenant_change_mcp" },
      },
    });

    expect(response.result.verification.ok).toBe(true);
    expect(response.result.exportPreview.manifest.recordCounts).toEqual({ events: 9, edges: 14, commits: 0 });
  });

  test("create_export_bundle emits a verifiable vevb-1 bundle only when write tools are enabled", async () => {
    const store = new LocalEvidenceStore();
    await store.recordEvent(eventInput(), { idempotencyKey: "invite:usr_123" });
    await store.recordEdge(edgeInput(), { idempotencyKey: "edge:usr_123:evt_local_01" });

    const blocked = await handleMcpRequest(store, {
      jsonrpc: "2.0",
      id: 6,
      method: "tools/call",
      params: { name: "veritio.create_export_bundle", arguments: { tenantId, createdAt: "2026-07-06T00:00:00.000Z" } },
    });
    expect(blocked.error.message).toBe("MCP write tools are disabled");

    const response = await handleMcpRequest(
      store,
      {
        jsonrpc: "2.0",
        id: 7,
        method: "tools/call",
        params: { name: "veritio.create_export_bundle", arguments: { tenantId, createdAt: "2026-07-06T00:00:00.000Z" } },
      },
      { allowWriteTools: true },
    );

    const bundle = parseExportBundle(response.result.bundle as string);
    expect(bundle.bundleVersion).toBe("vevb-1");
    expect(bundle.manifest.createdAt).toBe("2026-07-06T00:00:00.000Z");
    expect(bundle.manifest.scope.tenantId).toBe(tenantId);
    expect(bundle.manifest.producer.type).toBe("service");

    const report = await verifyExportBundle(bundle);
    expect(report.valid).toBe(true);
    expect(report.checks.signature).toBe("absent");
  });

  test("create_export_bundle requires an explicit createdAt", async () => {
    const store = new LocalEvidenceStore();
    const response = await handleMcpRequest(
      store,
      {
        jsonrpc: "2.0",
        id: 8,
        method: "tools/call",
        params: { name: "veritio.create_export_bundle", arguments: { tenantId } },
      },
      { allowWriteTools: true },
    );
    expect(response.error.message).toBe("createdAt is required");
  });

  test("create_export_bundle rejects a non-ISO createdAt", async () => {
    const store = new LocalEvidenceStore();
    const response = await handleMcpRequest(
      store,
      {
        jsonrpc: "2.0",
        id: 9,
        method: "tools/call",
        params: { name: "veritio.create_export_bundle", arguments: { tenantId, createdAt: "07/06/2026" } },
      },
      { allowWriteTools: true },
    );
    expect(response.error.message).toBe("createdAt must be an ISO-8601 timestamp");
  });
});
