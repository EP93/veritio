import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  HASH_ALGORITHM,
  buildExportBundle,
  buildExportBundleV2,
  canonicalJson,
  createAuditEvent,
  createEvidenceCommit,
  createEvidenceEdge,
  createGovernedChangeDraft,
  createProvenanceRecorder,
  defineEntity,
  hashAssertionRecord,
  hashAuditRecord,
  hashEvidenceEdgeRecord,
  hashIdempotencyKey,
  parseExportBundle,
  serializeExportBundle,
  verifyAuditRecords,
  verifyEvidenceCommits,
  verifyEvidenceEdgeRecords,
  verifyExportBundle,
  type AuditEvent,
  type AuditEventInput,
  type AuditRecord,
  type AuditStoreAppendOptions,
  type AuditOriginClaim,
  type EvidenceCommit,
  type EvidenceCommitInput,
  type EvidenceCommitVerificationResult,
  type EvidenceEdge,
  type EvidenceEdgeInput,
  type EvidenceEdgeRecord,
  type EvidenceEntity,
  type EvidenceRef,
  type EvidenceScope,
  type GovernedChangeDraft,
  type JsonObject,
  type SecurityRiskAssertion,
  type VerificationResult,
} from "@veritio/core";

// Re-exported so consumers of recordAssertion/listAssertions can name the
// stored security-risk assertion type from this server package directly.
export type { SecurityRiskAssertion } from "@veritio/core";

export interface LocalEvidenceStoreListOptions {
  afterSequence?: number;
  limit?: number;
}

export interface EvidenceGraphQuery {
  tenantId: string;
  rootId?: string;
  limit?: number;
}

export interface EvidenceGraphNode {
  id: string;
  type: string;
  label?: string;
}

export interface EvidenceGraphEdge {
  id: string;
  from: string;
  to: string;
  relation: string;
  source: "edge_record";
  recordHash: string;
}

export interface EvidenceGraph {
  tenantId: string;
  rootId?: string;
  nodes: EvidenceGraphNode[];
  edges: EvidenceGraphEdge[];
}

export interface ChangeView {
  id: string;
  title: string;
  status: "declared";
  occurredAt: string;
  initiatedBy?: EvidenceRef;
  activityIds: string[];
  outputRevisionIds: string[];
  supportingRecordIds: string[];
  assurance: string[];
}

export interface EntityTimeline {
  tenantId: string;
  entityId: string;
  entityType: string;
  revisions: Array<{
    id: string;
    occurredAt: string;
    changedPaths: string[];
    stateCommitment: JsonObject;
    generatedBy?: EvidenceRef;
    supportingRecordId: string;
  }>;
}

export interface ExplainResult {
  changeId: string;
  actor?: string;
  activityIds: string[];
  outputRevisionIds: string[];
  supportingRecordIds: string[];
  evidenceAssurance: string[];
  knownCoverage: string[];
  notCaptured: string[];
}

export interface RevisionDiff {
  revisionId: string;
  changedPaths: string[];
  after: JsonObject;
}

export interface VerificationReport {
  ok: boolean;
  audit: VerificationResult;
  edges: VerificationResult;
  commits: EvidenceCommitVerificationResult;
}

export interface ExportBundlePreview {
  manifest: {
    schemaVersion: "2026-06-14";
    tenantId: string;
    createdAt: string;
    canonicalization: "veritio-json-v1";
    hashAlgorithm: typeof HASH_ALGORITHM;
    recordCounts: { events: number; edges: number; commits: number };
    verification: VerificationReport;
    files: Array<{ name: string; sha256: string }>;
  };
  eventsJsonl: string;
  edgesJsonl: string;
  commitsJsonl: string;
  verificationReport: VerificationReport;
  redactionManifest: {
    rules: string[];
  };
}

export type CreateExportBundleOptions =
  | { createdAt: string; bundleVersion?: "vevb-1" }
  | {
      createdAt: string;
      bundleVersion: "vevb-2";
      auditOrigin: AuditOriginClaim;
      checkpoints: unknown[];
      dispositions?: unknown[];
    };

export interface ScenarioResult {
  tenantId: string;
  graph: EvidenceGraph;
  verification: VerificationReport;
  exportPreview: ExportBundlePreview;
}

export interface LocalEvidenceBatchInput {
  commitId: string;
  streamId: string;
  events: AuditEventInput[];
  edges: EvidenceEdgeInput[];
  committedAt?: string | Date;
}

export interface LocalEvidenceBatchResult {
  auditRecords: AuditRecord[];
  edgeRecords: EvidenceEdgeRecord[];
  commit: EvidenceCommit;
}

export interface LocalEvidenceCommitListOptions extends LocalEvidenceStoreListOptions {
  streamId?: string;
}

export interface GovernedChangeScenarioResult extends ScenarioResult {
  changes: ChangeView[];
  entityTimeline: EntityTimeline;
  explain: ExplainResult;
  diff: RevisionDiff;
}

export interface WorkbenchAppOptions {
  store?: LocalEvidenceStore;
  allowWriteTools?: boolean;
}

export interface WorkbenchApp {
  store: LocalEvidenceStore;
  fetch(request: Request): Promise<Response>;
}

export interface StartWorkbenchServerOptions extends WorkbenchAppOptions {
  host?: string;
  port?: number;
}

export interface StartedWorkbenchServer {
  app: WorkbenchApp;
  server: Server;
  host: string;
  port: number;
  url: string;
  close(): Promise<void>;
}

export interface McpRequest {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
}

export interface McpHandlerOptions {
  allowWriteTools?: boolean;
}

const REDACTION_RULE =
  "metadata keys matching password|secret|token|api[_-]?key|authorization|email|phone|ssn are replaced with [redacted]";

/**
 * The service principal this local server records as the producer of every
 * vevb-1 export bundle it emits, mirroring the `veritio-local` identity it
 * advertises over MCP `initialize`.
 */
const EXPORT_BUNDLE_PRODUCER = {
  authority: "veritio-local",
  kind: "principal",
  type: "service",
  id: "veritio-local",
} as const;

const READ_TOOLS = [
  "veritio.list_events",
  "veritio.get_event",
  "veritio.list_edges",
  "veritio.list_commits",
  "veritio.list_changes",
  "veritio.get_evidence_graph",
  "veritio.verify_chain",
  "veritio.preview_export_bundle",
  "veritio.run_integration_scenario",
  "veritio.run_change_provenance_scenario",
  "veritio.run_recorder_provenance_scenario",
] as const;

const WRITE_TOOLS = [
  "veritio.record_event",
  "veritio.record_edge",
  "veritio.record_batch",
  "veritio.reset_dev_store",
  "veritio.create_export_bundle",
] as const;

/**
 * In-memory evidence store for local Workbench and MCP development. It keeps
 * audit records and evidence-edge records in separate tenant-scoped chains so
 * local workflows can model production evidence without hosted services.
 */
export class LocalEvidenceStore {
  #auditRecords: AuditRecord[] = [];
  #edgeRecords: EvidenceEdgeRecord[] = [];
  #commits: EvidenceCommit[] = [];
  #auditIdempotency = new Map<string, { canonical: string; record: AuditRecord }>();
  #edgeIdempotency = new Map<string, { canonical: string; record: EvidenceEdgeRecord }>();
  #auditTips = new Map<string, AuditRecord>();
  #edgeTips = new Map<string, EvidenceEdgeRecord>();
  #commitTips = new Map<string, EvidenceCommit>();
  #assertions: { assertion: SecurityRiskAssertion; hash: string }[] = [];

  /**
   * Records an audit event or normalized event input into the tenant audit
   * chain. Idempotency and expected-tip checks mirror the SDK AuditStore rules.
   */
  async recordEvent(input: AuditEventInput | AuditEvent, options: AuditStoreAppendOptions = {}): Promise<AuditRecord> {
    const event = isAuditEvent(input) ? clone(input) : createAuditEvent(input);
    const tenantId = requireTenantId(event.scope, "scope.tenantId");
    const idempotencyKeyHash = hashIdempotencyKey(tenantId, options.idempotencyKey ?? event.id);
    const canonical = canonicalJson(event);
    const existing = this.#auditIdempotency.get(idempotencyKeyHash);
    if (existing) {
      if (existing.canonical !== canonical) {
        throw new TypeError("idempotency conflict");
      }
      return clone(existing.record);
    }

    const tip = this.#auditTips.get(tenantId);
    const previousHash = tip?.hash ?? null;
    if (options.expectedPreviousHash !== undefined && options.expectedPreviousHash !== previousHash) {
      throw new TypeError("expectedPreviousHash does not match tenant chain tip");
    }

    const recordWithoutHash: Omit<AuditRecord, "hash"> = {
      event: clone(event),
      sequence: (tip?.sequence ?? 0) + 1,
      previousHash,
      hashAlgorithm: HASH_ALGORITHM,
      canonicalization: "veritio-json-v1",
      appendedAt: new Date().toISOString(),
      idempotencyKeyHash,
    };
    const record: AuditRecord = { ...recordWithoutHash, hash: hashAuditRecord(recordWithoutHash) };

    this.#auditRecords.push(record);
    this.#auditTips.set(tenantId, record);
    this.#auditIdempotency.set(idempotencyKeyHash, { canonical, record });
    return clone(record);
  }

  /**
   * Records an evidence graph edge into its separate tenant edge chain. Audit
   * events and graph edges stay independent so graph projection never mutates
   * the protocol audit record contract.
   */
  async recordEdge(
    input: EvidenceEdgeInput | EvidenceEdge,
    options: AuditStoreAppendOptions = {},
  ): Promise<EvidenceEdgeRecord> {
    const edge = isEvidenceEdge(input) ? clone(input) : createEvidenceEdge(input);
    const tenantId = requireTenantId(edge.scope, "scope.tenantId");
    const idempotencyKeyHash = hashIdempotencyKey(tenantId, options.idempotencyKey ?? edge.id);
    const canonical = canonicalJson(edge);
    const existing = this.#edgeIdempotency.get(idempotencyKeyHash);
    if (existing) {
      if (existing.canonical !== canonical) {
        throw new TypeError("idempotency conflict");
      }
      return clone(existing.record);
    }

    const tip = this.#edgeTips.get(tenantId);
    const previousHash = tip?.hash ?? null;
    if (options.expectedPreviousHash !== undefined && options.expectedPreviousHash !== previousHash) {
      throw new TypeError("expectedPreviousHash does not match tenant edge chain tip");
    }

    const recordWithoutHash: Omit<EvidenceEdgeRecord, "hash"> = {
      edge: clone(edge),
      sequence: (tip?.sequence ?? 0) + 1,
      previousHash,
      hashAlgorithm: HASH_ALGORITHM,
      canonicalization: "veritio-json-v1",
      appendedAt: new Date().toISOString(),
      idempotencyKeyHash,
    };
    const record: EvidenceEdgeRecord = { ...recordWithoutHash, hash: hashEvidenceEdgeRecord(recordWithoutHash) };

    this.#edgeRecords.push(record);
    this.#edgeTips.set(tenantId, record);
    this.#edgeIdempotency.set(idempotencyKeyHash, { canonical, record });
    return clone(record);
  }

  /**
   * Stores a precomputed security-risk assertion (recordType 'assertion.recorded')
   * and links it to its subject through a `based_on` edge. The local server is a
   * SINK, not a detector: it persists the conclusion verbatim and MUST NOT
   * recompute the score (risk scoring lives in the SDK risk module / Cloud
   * detectors). Idempotent on assertion id; conflicting bodies fail closed.
   * Evidence linkage is by edge, never an inline evidence[] field.
   */
  async recordAssertion(
    assertion: SecurityRiskAssertion,
  ): Promise<{ assertion: SecurityRiskAssertion; hash: string; edge: EvidenceEdgeRecord }> {
    requireTenantId(assertion.scope, "assertion.scope.tenantId");
    const hash = `sha256:${hashAssertionRecord(assertion)}`;
    // Dedup is tenant-scoped (mirrors the based_on edge idempotency key and the
    // listAssertions tenant filter): the same assertion id under two different
    // tenants must not collide into a false fail-closed conflict.
    const existing = this.#assertions.find(
      (entry) => entry.assertion.scope.tenantId === assertion.scope.tenantId && entry.assertion.id === assertion.id,
    );
    if (existing && canonicalJson(existing.assertion) !== canonicalJson(assertion)) {
      throw new TypeError("assertion id conflict");
    }
    if (!existing) {
      this.#assertions.push({ assertion: clone(assertion), hash });
    }
    const subject: EvidenceRef = assertion.subject;
    const edge = await this.recordEdge(
      {
        id: `edge_based_on_${assertion.id}`,
        occurredAt: assertion.occurredAt,
        scope: assertion.scope,
        from: { type: "assertion", id: assertion.id },
        relation: "based_on",
        to: { type: subject.kind as EvidenceEntity["type"], id: subject.id },
        metadata: { assertionType: assertion.type, level: assertion.conclusion.level },
      },
      { idempotencyKey: `based_on:${assertion.scope.tenantId}:${assertion.id}` },
    );
    return { assertion: clone(assertion), hash, edge };
  }

  /** Lists stored security-risk assertions for one tenant (read-model order). */
  async listAssertions(scope: EvidenceScope & { tenantId: string }): Promise<SecurityRiskAssertion[]> {
    const tenantId = requireTenantId(scope, "scope.tenantId");
    return this.#assertions
      .filter((entry) => entry.assertion.scope.tenantId === tenantId)
      .map((entry) => clone(entry.assertion));
  }

  /**
   * Records one local batch of audit events and graph edges, then appends an
   * EvidenceCommit manifest that binds the resulting record hashes in order.
   * The commit stream is separate from tenant chains and models ordered
   * membership; this in-memory store does not claim host transaction binding.
   */
  async recordBatch(input: LocalEvidenceBatchInput): Promise<LocalEvidenceBatchResult> {
    if (input.events.length + input.edges.length === 0) {
      throw new TypeError("batch must include at least one event or edge");
    }

    const existingCommit = this.#commits.find(
      (commit) => commit.streamId === input.streamId && commit.commitId === input.commitId,
    );
    if (existingCommit) {
      const auditRecords = input.events.map((eventInput) => {
        const event = createAuditEvent(eventInput);
        const record = this.#auditRecords.find((candidate) => candidate.event.id === event.id);
        if (!record || canonicalJson(record.event) !== canonicalJson(event)) {
          throw new TypeError("commit id conflict");
        }
        return record;
      });
      const edgeRecords = input.edges.map((edgeInput) => {
        const edge = createEvidenceEdge(edgeInput);
        const record = this.#edgeRecords.find((candidate) => candidate.edge.id === edge.id);
        if (!record || canonicalJson(record.edge) !== canonicalJson(edge)) {
          throw new TypeError("commit id conflict");
        }
        return record;
      });
      const members = buildEvidenceCommitMembers(auditRecords, edgeRecords);
      if (canonicalJson(existingCommit.members) !== canonicalJson(members)) {
        throw new TypeError("commit id conflict");
      }
      return {
        auditRecords: auditRecords.map(clone),
        edgeRecords: edgeRecords.map(clone),
        commit: clone(existingCommit),
      };
    }

    const auditRecords: AuditRecord[] = [];
    const edgeRecords: EvidenceEdgeRecord[] = [];
    for (const event of input.events) {
      auditRecords.push(await this.recordEvent(event));
    }
    for (const edge of input.edges) {
      edgeRecords.push(await this.recordEdge(edge));
    }

    const previousCommit = this.#commitTips.get(input.streamId);
    const commitInput: EvidenceCommitInput = {
      commitId: input.commitId,
      streamId: input.streamId,
      sequence: (previousCommit?.sequence ?? 0) + 1,
      previousCommitHash: previousCommit?.hash ?? null,
      members: buildEvidenceCommitMembers(auditRecords, edgeRecords),
    };
    if (input.committedAt !== undefined) {
      commitInput.committedAt = input.committedAt;
    }
    const commit = createEvidenceCommit(commitInput);
    this.#commits.push(commit);
    this.#commitTips.set(input.streamId, commit);
    return { auditRecords: auditRecords.map(clone), edgeRecords: edgeRecords.map(clone), commit: clone(commit) };
  }

  /**
   * Appends a governed-change draft through the v1 compatibility record shape.
   * Callers that need an explicit multi-record commit should use `recordBatch`
   * so the EvidenceCommit stream is created deliberately.
   */
  async recordGovernedChangeDraft(
    draft: GovernedChangeDraft,
  ): Promise<{ auditRecords: AuditRecord[]; edgeRecords: EvidenceEdgeRecord[] }> {
    const auditRecords: AuditRecord[] = [];
    const edgeRecords: EvidenceEdgeRecord[] = [];
    for (const event of draft.events) {
      auditRecords.push(await this.recordEvent(event));
    }
    for (const edge of draft.edges) {
      edgeRecords.push(await this.recordEdge(edge));
    }
    return { auditRecords, edgeRecords };
  }

  /**
   * Lists audit records for one tenant with optional sequence and limit controls.
   */
  async listEvents(
    scope: EvidenceScope & { tenantId: string },
    options: LocalEvidenceStoreListOptions = {},
  ): Promise<AuditRecord[]> {
    const tenantId = requireTenantId(scope, "scope.tenantId");
    validateListOptions(options);
    const records = this.#auditRecords.filter((record) => {
      return record.event.scope?.tenantId === tenantId && record.sequence > (options.afterSequence ?? 0);
    });
    return limited(records, options.limit).map(clone);
  }

  /**
   * Lists evidence-edge records for one tenant with optional sequence and limit
   * controls.
   */
  async listEdges(
    scope: EvidenceScope & { tenantId: string },
    options: LocalEvidenceStoreListOptions = {},
  ): Promise<EvidenceEdgeRecord[]> {
    const tenantId = requireTenantId(scope, "scope.tenantId");
    validateListOptions(options);
    const records = this.#edgeRecords.filter((record) => {
      return record.edge.scope?.tenantId === tenantId && record.sequence > (options.afterSequence ?? 0);
    });
    return limited(records, options.limit).map(clone);
  }

  /**
   * Lists EvidenceCommit manifests by optional stream and sequence cursor. Commit
   * streams are not tenant-scoped in PR5, so callers must choose tenant evidence
   * records separately when building export bundles.
   */
  async listCommits(options: LocalEvidenceCommitListOptions = {}): Promise<EvidenceCommit[]> {
    validateListOptions(options);
    if (options.streamId !== undefined) {
      requireString(options.streamId, "streamId");
    }
    const commits = this.#commits.filter((commit) => {
      return (
        (options.streamId === undefined || commit.streamId === options.streamId) &&
        commit.sequence > (options.afterSequence ?? 0)
      );
    });
    return limited(commits, options.limit).map(clone);
  }

  /**
   * Looks up a cloned audit record by event id for Workbench detail views.
   */
  async getEvent(id: string): Promise<AuditRecord | null> {
    const record = this.#auditRecords.find((candidate) => candidate.event.id === id);
    return record ? clone(record) : null;
  }

  /**
   * Looks up a cloned evidence-edge record by edge id for Workbench detail views.
   */
  async getEdge(id: string): Promise<EvidenceEdgeRecord | null> {
    const record = this.#edgeRecords.find((candidate) => candidate.edge.id === id);
    return record ? clone(record) : null;
  }

  /**
   * Verifies both local audit and edge chains for a tenant and returns separate
   * reports so graph failures do not hide audit-chain failures.
   */
  async verify(scope: EvidenceScope & { tenantId: string }): Promise<VerificationReport> {
    const tenantId = requireTenantId(scope, "scope.tenantId");
    const audit = verifyAuditRecords(await this.listEvents({ tenantId }));
    const edges = verifyEvidenceEdgeRecords(await this.listEdges({ tenantId }));
    const commits = verifyEvidenceCommits(await this.listCommits());
    return { ok: audit.ok && edges.ok && commits.ok, audit, edges, commits };
  }

  /**
   * Projects tenant-scoped edge records into a sorted graph that the Workbench can
   * inspect without changing stored records.
   */
  async getEvidenceGraph(query: EvidenceGraphQuery): Promise<EvidenceGraph> {
    const tenantId = requireTenantId({ tenantId: query.tenantId }, "tenantId");
    const listOptions: LocalEvidenceStoreListOptions = {};
    if (query.limit !== undefined) {
      listOptions.limit = query.limit;
    }
    const records = await this.listEdges({ tenantId }, listOptions);
    const edges = records
      .filter((record) => !query.rootId || record.edge.from.id === query.rootId || record.edge.to.id === query.rootId)
      .map((record) => edgeRecordToGraphEdge(record));
    const nodes = new Map<string, EvidenceGraphNode>();
    for (const record of records) {
      if (query.rootId && record.edge.from.id !== query.rootId && record.edge.to.id !== query.rootId) {
        continue;
      }
      addGraphNode(nodes, record.edge.from);
      addGraphNode(nodes, record.edge.to);
    }

    const graph: EvidenceGraph = { tenantId, nodes: [...nodes.values()].sort(compareNodes), edges };
    if (query.rootId) {
      graph.rootId = query.rootId;
    }
    return graph;
  }

  /**
   * Rebuilds Change views from v1 audit events and edge records. The projection
   * is disposable read-model state; canonical evidence remains the stored records.
   */
  async listChanges(scope: EvidenceScope & { tenantId: string }): Promise<ChangeView[]> {
    const tenantId = requireTenantId(scope, "scope.tenantId");
    const events = await this.listEvents({ tenantId });
    const edges = await this.listEdges({ tenantId });
    return events
      .filter((record) => record.event.action === "change.declared")
      .map((record) => changeViewFromRecord(record, edges))
      .sort((left, right) => right.occurredAt.localeCompare(left.occurredAt));
  }

  /**
   * Rebuilds one entity revision timeline from revision compatibility events.
   * Payloads show minimized governed fields only, never raw omitted fields.
   */
  async getEntityTimeline(query: { tenantId: string; entityType: string; entityId: string }): Promise<EntityTimeline> {
    const tenantId = requireTenantId({ tenantId: query.tenantId }, "tenantId");
    const events = await this.listEvents({ tenantId });
    const revisions = events
      .filter((record) => {
        return (
          record.event.action === "entity.revision.created" &&
          record.event.target.type === query.entityType &&
          record.event.target.id === query.entityId
        );
      })
      .map(revisionFromRecord)
      .sort((left, right) => left.occurredAt.localeCompare(right.occurredAt));
    return { tenantId, entityType: query.entityType, entityId: query.entityId, revisions };
  }

  /**
   * Explains a change by joining the declared change event with its current v1
   * relation edges and listing evidence gaps that the current protocol cannot
   * truthfully prove yet.
   */
  async explainChange(scope: EvidenceScope & { tenantId: string }, changeId: string): Promise<ExplainResult> {
    const tenantId = requireTenantId(scope, "scope.tenantId");
    const events = await this.listEvents({ tenantId });
    const edges = await this.listEdges({ tenantId });
    const changeRecord = events.find(
      (record) => record.event.action === "change.declared" && record.event.target.id === changeId,
    );
    if (!changeRecord) {
      throw new TypeError("change not found");
    }
    const outgoing = edges.filter((record) => record.edge.from.id === changeId);
    return {
      changeId,
      actor: changeRecord.event.actor.id,
      activityIds: outgoing
        .filter((record) => record.edge.relation === "has_activity")
        .map((record) => record.edge.to.id),
      outputRevisionIds: outgoing
        .filter((record) => record.edge.relation === "has_output")
        .map((record) => record.edge.to.id),
      supportingRecordIds: [changeRecord.event.id, ...outgoing.map((record) => record.edge.id)],
      evidenceAssurance: ["current-protocol relation links present"],
      knownCoverage: ["change", "activity", "revision", "relations", "audit_records"],
      notCaptured: ["raw full row", "business transaction proof", "independent state verification"],
    };
  }

  /**
   * Returns the captured governed-field diff for a revision. Hash-only fields are
   * surfaced as digest metadata because the original value was intentionally not
   * captured.
   */
  async diffRevision(scope: EvidenceScope & { tenantId: string }, revisionId: string): Promise<RevisionDiff> {
    const tenantId = requireTenantId(scope, "scope.tenantId");
    const events = await this.listEvents({ tenantId });
    const revision = events.map(revisionFromRecordOrNull).find((candidate) => candidate?.id === revisionId);
    if (!revision) {
      throw new TypeError("revision not found");
    }
    return { revisionId, changedPaths: revision.changedPaths, after: revision.stateCommitment.fields as JsonObject };
  }

  /**
   * Builds a deterministic preview of exportable JSONL artifacts for one tenant.
   */
  async previewExportBundle(scope: EvidenceScope & { tenantId: string }): Promise<ExportBundlePreview> {
    const tenantId = requireTenantId(scope, "scope.tenantId");
    const events = await this.listEvents({ tenantId });
    const edges = await this.listEdges({ tenantId });
    const commits = await this.listCommits();
    const verification = await this.verify({ tenantId });
    const eventsJsonl = toJsonl(events);
    const edgesJsonl = toJsonl(edges);
    const commitsJsonl = toJsonl(commits);
    const verificationJson = canonicalJson(verification);
    const redactionManifest = { rules: [REDACTION_RULE] };
    const redactionJson = canonicalJson(redactionManifest);

    return {
      manifest: {
        schemaVersion: "2026-06-14",
        tenantId,
        createdAt: new Date().toISOString(),
        canonicalization: "veritio-json-v1",
        hashAlgorithm: HASH_ALGORITHM,
        recordCounts: { events: events.length, edges: edges.length, commits: commits.length },
        verification,
        files: [
          { name: "events.jsonl", sha256: sha256Hex(eventsJsonl) },
          { name: "edges.jsonl", sha256: sha256Hex(edgesJsonl) },
          { name: "commits.jsonl", sha256: sha256Hex(commitsJsonl) },
          { name: "verification.json", sha256: sha256Hex(verificationJson) },
          { name: "redaction-manifest.json", sha256: sha256Hex(redactionJson) },
        ],
      },
      eventsJsonl,
      edgesJsonl,
      commitsJsonl,
      verificationReport: verification,
      redactionManifest,
    };
  }

  /**
   * Assembles the default byte-compatible vevb-1 export or an explicitly
   * selected vevb-2 checkpoint export. V2 checkpoint/disposition records and
   * audit origin are host inputs; the local server never infers retention state,
   * reads a clock, or invents hosted semantics.
   */
  async createExportBundle(
    scope: EvidenceScope & { tenantId: string },
    options: CreateExportBundleOptions,
  ): Promise<string> {
    const tenantId = requireTenantId(scope, "scope.tenantId");
    const events = await this.listEvents({ tenantId });
    const edges = await this.listEdges({ tenantId });
    const commits = await this.listCommits();
    if (options.bundleVersion === "vevb-2") {
      if (commits.length !== 0) throw new TypeError("vevb-2 requires an empty EvidenceCommit list");
      const bundle = await buildExportBundleV2({
        scope: { tenantId },
        range: exportBundleRange(events, edges, [], options.createdAt),
        producer: EXPORT_BUNDLE_PRODUCER,
        createdAt: options.createdAt,
        auditOrigin: options.auditOrigin,
        events,
        edges,
        commits: [],
        checkpoints: options.checkpoints,
        dispositions: options.dispositions ?? [],
      });
      return serializeExportBundle(bundle);
    }
    const bundle = await buildExportBundle({
      scope: { tenantId },
      range: exportBundleRange(events, edges, commits, options.createdAt),
      producer: EXPORT_BUNDLE_PRODUCER,
      createdAt: options.createdAt,
      events,
      edges,
      commits,
    });
    return serializeExportBundle(bundle);
  }

  /**
   * Clears all in-memory state for repeatable local tests and demos.
   */
  async reset(): Promise<void> {
    this.#auditRecords = [];
    this.#edgeRecords = [];
    this.#commits = [];
    this.#auditIdempotency.clear();
    this.#edgeIdempotency.clear();
    this.#auditTips.clear();
    this.#edgeTips.clear();
    this.#commitTips.clear();
  }
}

/**
 * Seeds a local store with an agent-session-to-runtime-event scenario that
 * demonstrates how audit records and graph edges connect code changes to runtime
 * evidence.
 */
export async function runIntegrationScenario(
  store: LocalEvidenceStore,
  options: { tenantId?: string } = {},
): Promise<ScenarioResult> {
  const tenantId = options.tenantId ?? "tenant_local_demo";
  await store.recordEvent({
    id: "evt_agent_session_started",
    occurredAt: "2026-06-14T00:00:00.000Z",
    actor: { type: "ai_agent", id: "agent_opencode" },
    action: "agent.session.started",
    target: { type: "agent_session", id: "agt_sess_local_demo" },
    scope: { tenantId, environment: "dev" },
    purpose: "change_provenance",
    dataCategories: ["source_reference"],
    retention: "change_1y",
    metadata: { model: "local-fixture", promptHash: "sha256:prompt_fixture" },
  });
  await store.recordEvent({
    id: "evt_runtime_member_invited",
    occurredAt: "2026-06-14T00:00:03.000Z",
    actor: { type: "user", id: "usr_reviewer" },
    action: "org.member.invited",
    target: { type: "organization", id: tenantId },
    scope: { tenantId, environment: "dev" },
    purpose: "access_management",
    dataCategories: ["account"],
    retention: "security_1y",
    metadata: { role: "viewer" },
  });
  await store.recordEdge({
    id: "edge_agent_created_file",
    occurredAt: "2026-06-14T00:00:01.000Z",
    scope: { tenantId, environment: "dev" },
    from: { type: "agent_session", id: "agt_sess_local_demo" },
    relation: "created",
    to: { type: "file", id: "file_invite_route", pathHash: "sha256:file_invite_route" },
    metadata: { reason: "ai_agent" },
  });
  await store.recordEdge({
    id: "edge_file_deployed",
    occurredAt: "2026-06-14T00:00:02.000Z",
    scope: { tenantId, environment: "dev" },
    from: { type: "file", id: "file_invite_route", pathHash: "sha256:file_invite_route" },
    relation: "deployed_as",
    to: { type: "deployment", id: "dep_local_demo" },
    metadata: { artifactHash: "sha256:artifact_fixture" },
  });
  await store.recordEdge({
    id: "edge_deploy_observed_runtime",
    occurredAt: "2026-06-14T00:00:03.000Z",
    scope: { tenantId, environment: "dev" },
    from: { type: "deployment", id: "dep_local_demo" },
    relation: "observed_in",
    to: { type: "runtime_event", id: "evt_runtime_member_invited" },
    metadata: { route: "/api/invitations" },
  });

  return {
    tenantId,
    graph: await store.getEvidenceGraph({ tenantId }),
    verification: await store.verify({ tenantId }),
    exportPreview: await store.previewExportBundle({ tenantId }),
  };
}

/**
 * Seeds a detailed app-builder-style provenance tree. The records model a user
 * request flowing through an AI agent session, tool calls, accepted and rejected
 * file changes, review, CI, deployment, and runtime evidence without storing raw
 * prompts, file contents, diffs, or command output.
 */
export async function runChangeProvenanceScenario(
  store: LocalEvidenceStore,
  options: { tenantId?: string } = {},
): Promise<ScenarioResult> {
  const tenantId = options.tenantId ?? "tenant_change_provenance_demo";
  const scope = { tenantId, workspaceId: "workspace_app_builder", environment: "dev" };
  const occurredAt = [
    "2026-06-14T00:10:00.000Z",
    "2026-06-14T00:10:02.000Z",
    "2026-06-14T00:10:04.000Z",
    "2026-06-14T00:10:06.000Z",
    "2026-06-14T00:10:08.000Z",
    "2026-06-14T00:10:10.000Z",
    "2026-06-14T00:10:12.000Z",
    "2026-06-14T00:10:14.000Z",
    "2026-06-14T00:10:16.000Z",
  ] as const;

  await store.recordEvent({
    id: "evt_change_request_received",
    occurredAt: occurredAt[0],
    actor: { type: "user", id: "usr_builder" },
    action: "change.requested",
    target: { type: "change_request", id: "req_track_error_toasts" },
    scope,
    purpose: "change_provenance",
    dataCategories: ["source_reference"],
    retention: "change_1y",
    metadata: {
      requestHash: "sha256:req_track_error_toasts",
      summary: "Track a Studio build/deployment UI change without raw prompt text.",
    },
  });
  await store.recordEvent({
    id: "evt_agent_session_started_detailed",
    occurredAt: occurredAt[1],
    actor: { type: "ai_agent", id: "agent_opencode" },
    action: "agent.session.started",
    target: { type: "agent_session", id: "agt_sess_app_builder_01" },
    scope,
    purpose: "change_provenance",
    dataCategories: ["source_reference"],
    retention: "change_1y",
    metadata: {
      provider: "opencode",
      model: "local-fixture",
      promptHash: "sha256:prompt_track_error_toasts",
      contextHash: "sha256:context_repo_slice",
      policyHash: "sha256:opencode_policy_v1",
      configHash: "sha256:provider_config_v1",
      sandboxId: "sandbox_app_builder_01",
    },
  });
  await store.recordEvent({
    id: "evt_tool_call_apply_edits",
    occurredAt: occurredAt[2],
    actor: { type: "ai_agent", id: "agent_opencode" },
    action: "agent.tool.called",
    target: { type: "tool_call", id: "tool_apply_edits_01" },
    scope,
    purpose: "change_provenance",
    dataCategories: ["source_reference"],
    retention: "change_1y",
    metadata: {
      tool: "apply_edits",
      phase: "completed",
      approval: "auto_allowed",
      inputHash: "sha256:apply_edits_input",
      filesystemScope: ["apps/studio/**"],
      status: "succeeded",
      latencyMs: 1840,
    },
  });
  await store.recordEvent({
    id: "evt_change_proposal_created",
    occurredAt: occurredAt[3],
    actor: { type: "ai_agent", id: "agent_opencode" },
    action: "change.proposal.created",
    target: { type: "change_proposal", id: "proposal_safe_toasts_01" },
    scope,
    purpose: "change_provenance",
    dataCategories: ["source_reference"],
    retention: "change_1y",
    metadata: {
      baseVersion: 41,
      resultVersion: 42,
      proposalSignature: "sha256:proposal_safe_toasts_01",
      acceptedPathHashes: ["sha256:path_build_shared", "sha256:path_deployments_tab"],
      rejectedPathHashes: ["sha256:path_package_lock"],
      deletedPathHashes: [],
      reason: "ai_agent",
    },
  });
  await store.recordEvent({
    id: "evt_change_files_changed",
    occurredAt: occurredAt[4],
    actor: { type: "ai_agent", id: "agent_opencode" },
    action: "change.files.changed",
    target: { type: "source_tree", id: "source_tree_app_builder_dev" },
    scope,
    purpose: "change_provenance",
    dataCategories: ["source_reference"],
    retention: "change_1y",
    metadata: {
      baseVersion: 41,
      resultVersion: 42,
      rootHash: "sha256:root_after_safe_toasts",
      manifestDigest: "sha256:manifest_after_safe_toasts",
      files: [
        {
          pathHash: "sha256:path_build_shared",
          beforeHash: "sha256:before_build_shared",
          afterHash: "sha256:after_build_shared",
          hunkHashes: ["sha256:hunk_build_shared_01"],
          action: "upsert",
          sizeBytes: 1842,
        },
        {
          pathHash: "sha256:path_deployments_tab",
          beforeHash: "sha256:before_deployments_tab",
          afterHash: "sha256:after_deployments_tab",
          hunkHashes: ["sha256:hunk_deployments_tab_01"],
          action: "upsert",
          sizeBytes: 3921,
        },
      ],
    },
  });
  await store.recordEvent({
    id: "evt_review_approval_recorded",
    occurredAt: occurredAt[5],
    actor: { type: "user", id: "usr_reviewer" },
    action: "review.approval.recorded",
    target: { type: "pull_request", id: "pr_safe_toasts_01" },
    scope,
    purpose: "change_provenance",
    dataCategories: ["source_reference"],
    retention: "change_1y",
    metadata: {
      reviewFindingCount: 0,
      waiverCount: 0,
      approvalHash: "sha256:approval_safe_toasts",
    },
  });
  await store.recordEvent({
    id: "evt_ci_job_completed",
    occurredAt: occurredAt[6],
    actor: { type: "service", id: "svc_ci" },
    action: "ci.job.completed",
    target: { type: "ci_run", id: "ci_safe_toasts_01" },
    scope,
    purpose: "change_provenance",
    dataCategories: ["source_reference"],
    retention: "change_1y",
    metadata: {
      status: "succeeded",
      artifactHash: "sha256:artifact_safe_toasts",
      checks: ["typecheck", "unit", "diff-check"],
    },
  });
  await store.recordEvent({
    id: "evt_deploy_deployed",
    occurredAt: occurredAt[7],
    actor: { type: "service", id: "svc_deploy_worker" },
    action: "deploy.deployed",
    target: { type: "deployment", id: "dep_safe_toasts_01" },
    scope,
    purpose: "change_provenance",
    dataCategories: ["source_reference"],
    retention: "change_1y",
    metadata: {
      sourceHash: "sha256:source_safe_toasts",
      bundleHash: "sha256:bundle_safe_toasts",
      buildJobId: "build_job_safe_toasts_01",
      workerNameHash: "sha256:worker_name_safe_toasts",
    },
  });
  await store.recordEvent({
    id: "evt_runtime_observed_after_deploy",
    occurredAt: occurredAt[8],
    actor: { type: "user", id: "usr_reviewer" },
    action: "build.error.toast.viewed",
    target: { type: "runtime_event", id: "runtime_safe_toast_01" },
    scope,
    purpose: "quality_assurance",
    dataCategories: ["source_reference"],
    retention: "change_1y",
    metadata: {
      deploymentId: "dep_safe_toasts_01",
      routeHash: "sha256:route_app_settings_deployments",
      observedOutcome: "sanitized_error_copy",
    },
  });

  const edges: EvidenceEdgeInput[] = [
    {
      id: "edge_user_created_request",
      occurredAt: occurredAt[0],
      scope,
      from: { type: "actor", id: "usr_builder", actorType: "user" },
      relation: "created",
      to: { type: "resource", id: "req_track_error_toasts", resourceType: "change_request" },
      metadata: { source: "user_request" },
    },
    {
      id: "edge_session_caused_by_request",
      occurredAt: occurredAt[1],
      scope,
      from: { type: "agent_session", id: "agt_sess_app_builder_01" },
      relation: "caused_by",
      to: { type: "resource", id: "req_track_error_toasts", resourceType: "change_request" },
      metadata: { promptHash: "sha256:prompt_track_error_toasts" },
    },
    {
      id: "edge_session_created_tool_call",
      occurredAt: occurredAt[2],
      scope,
      from: { type: "agent_session", id: "agt_sess_app_builder_01" },
      relation: "created",
      to: { type: "tool_call", id: "tool_apply_edits_01" },
      metadata: { tool: "apply_edits", approval: "auto_allowed" },
    },
    {
      id: "edge_tool_modified_source_file",
      occurredAt: occurredAt[2],
      scope,
      from: { type: "tool_call", id: "tool_apply_edits_01" },
      relation: "modified",
      to: { type: "file", id: "file_build_shared", pathHash: "sha256:path_build_shared" },
      metadata: { beforeHash: "sha256:before_build_shared", afterHash: "sha256:after_build_shared" },
    },
    {
      id: "edge_tool_modified_deployment_file",
      occurredAt: occurredAt[2],
      scope,
      from: { type: "tool_call", id: "tool_apply_edits_01" },
      relation: "modified",
      to: { type: "file", id: "file_deployments_tab", pathHash: "sha256:path_deployments_tab" },
      metadata: { beforeHash: "sha256:before_deployments_tab", afterHash: "sha256:after_deployments_tab" },
    },
    {
      id: "edge_proposal_includes_rejected_file",
      occurredAt: occurredAt[3],
      scope,
      from: { type: "resource", id: "proposal_safe_toasts_01", resourceType: "change_proposal" },
      relation: "read",
      to: { type: "file", id: "file_package_lock", pathHash: "sha256:path_package_lock" },
      metadata: { decision: "rejected", reason: "classification:system" },
    },
    {
      id: "edge_proposal_created_hunk",
      occurredAt: occurredAt[3],
      scope,
      from: { type: "resource", id: "proposal_safe_toasts_01", resourceType: "change_proposal" },
      relation: "created",
      to: { type: "diff_hunk", id: "hunk_build_shared_01" },
      metadata: { hunkHash: "sha256:hunk_build_shared_01" },
    },
    {
      id: "edge_hunk_part_of_file",
      occurredAt: occurredAt[4],
      scope,
      from: { type: "diff_hunk", id: "hunk_build_shared_01" },
      relation: "part_of",
      to: { type: "file", id: "file_build_shared", pathHash: "sha256:path_build_shared" },
      metadata: { resultVersion: 42 },
    },
    {
      id: "edge_proposal_reviewed_by_user",
      occurredAt: occurredAt[5],
      scope,
      from: { type: "resource", id: "proposal_safe_toasts_01", resourceType: "change_proposal" },
      relation: "approved_by",
      to: { type: "actor", id: "usr_reviewer", actorType: "user" },
      metadata: { approvalHash: "sha256:approval_safe_toasts" },
    },
    {
      id: "edge_artifact_derived_from_source_file",
      occurredAt: occurredAt[6],
      scope,
      from: { type: "artifact", id: "artifact_safe_toasts_01" },
      relation: "derived_from",
      to: { type: "file", id: "file_build_shared", pathHash: "sha256:path_build_shared" },
      metadata: { sourceHash: "sha256:source_safe_toasts" },
    },
    {
      id: "edge_artifact_built_by_ci",
      occurredAt: occurredAt[6],
      scope,
      from: { type: "artifact", id: "artifact_safe_toasts_01" },
      relation: "built_by",
      to: { type: "ci_run", id: "ci_safe_toasts_01" },
      metadata: { status: "succeeded" },
    },
    {
      id: "edge_artifact_deployed_as",
      occurredAt: occurredAt[7],
      scope,
      from: { type: "artifact", id: "artifact_safe_toasts_01" },
      relation: "deployed_as",
      to: { type: "deployment", id: "dep_safe_toasts_01" },
      metadata: { bundleHash: "sha256:bundle_safe_toasts" },
    },
    {
      id: "edge_deployment_satisfies_policy",
      occurredAt: occurredAt[7],
      scope,
      from: { type: "deployment", id: "dep_safe_toasts_01" },
      relation: "satisfies_policy",
      to: { type: "policy", id: "policy_prod_deploy" },
      metadata: { requirements: ["human_approval", "ci_passed", "artifact_attestation"] },
    },
    {
      id: "edge_deployment_observed_runtime",
      occurredAt: occurredAt[8],
      scope,
      from: { type: "deployment", id: "dep_safe_toasts_01" },
      relation: "observed_in",
      to: { type: "runtime_event", id: "runtime_safe_toast_01" },
      metadata: { routeHash: "sha256:route_app_settings_deployments" },
    },
  ];

  for (const edge of edges) {
    await store.recordEdge(edge);
  }

  return {
    tenantId,
    graph: await store.getEvidenceGraph({ tenantId }),
    verification: await store.verify({ tenantId }),
    exportPreview: await store.previewExportBundle({ tenantId }),
  };
}

/**
 * Builds the same agent change-provenance graph as runChangeProvenanceScenario,
 * but through the public createProvenanceRecorder API instead of hand-assembled
 * events/edges. This exercises the recorder end-to-end and renders exactly what an
 * OpenCode-style agent session emits: the enforcing human is linked to the session
 * via a caused_by edge (no audit-event schema change), and provider/model use the
 * canonical agent:{name,version} + model:{provider,name} identity shape.
 */
export async function runRecorderProvenanceScenario(
  store: LocalEvidenceStore,
  options: { tenantId?: string } = {},
): Promise<ScenarioResult> {
  const tenantId = options.tenantId ?? "tenant_recorder_demo";
  const scope = { tenantId, workspaceId: "workspace_app_builder", environment: "dev" };
  const t = [
    "2026-06-16T09:14:00.000Z",
    "2026-06-16T09:14:02.000Z",
    "2026-06-16T09:14:04.000Z",
    "2026-06-16T09:14:06.000Z",
    "2026-06-16T09:14:08.000Z",
    "2026-06-16T09:14:10.000Z",
    "2026-06-16T09:14:12.000Z",
    "2026-06-16T09:14:14.000Z",
    "2026-06-16T09:14:16.000Z",
  ] as const;

  const recorder = createProvenanceRecorder({
    recordEvent: (input) => store.recordEvent(input),
    recordEdge: (input) => store.recordEdge(input),
  });

  const { session } = await recorder.startSession({
    scope,
    sessionId: "agt_sess_recorder_01",
    initiatedBy: { type: "user", id: "usr_builder" },
    agentActor: { type: "ai_agent", id: "agent_opencode" },
    agent: { name: "opencode", version: "1.17" },
    model: { provider: "anthropic", name: "claude-opus-4-8" },
    occurredAt: t[0],
    purpose: "change_provenance",
    retention: "change_1y",
    dataCategories: ["source_reference"],
    repository: { provider: "github", id: "getveritio/app-builder" },
    branch: "feat/error-toasts",
    policyHash: "sha256:opencode_policy_v1",
    configHash: "sha256:provider_config_v1",
    sandbox: { type: "container", id: "sandbox_app_builder_01" },
    promptHash: "sha256:prompt_track_error_toasts",
    requestId: "req_track_error_toasts",
  });

  await session.recordPrompt({
    occurredAt: t[1],
    promptHash: "sha256:prompt_track_error_toasts",
    contextHashes: ["sha256:context_repo_slice"],
  });
  await session.recordToolCall({
    occurredAt: t[2],
    toolCallId: "tool_apply_edits_01",
    tool: "apply_edits",
    status: "succeeded",
    approval: "auto_allowed",
    inputHash: "sha256:apply_edits_input",
    reads: [{ id: "file_readme", pathHash: "sha256:path_readme" }],
  });
  await session.recordChangeProposal({
    occurredAt: t[3],
    proposalId: "proposal_safe_toasts_01",
    baseVersion: 41,
    resultVersion: 42,
    proposalSignature: "sha256:proposal_safe_toasts_01",
    acceptedPathHashes: ["sha256:path_build_shared", "sha256:path_deployments_tab"],
    rejectedFiles: [{ id: "file_package_lock", pathHash: "sha256:path_package_lock" }],
    createdHunks: [
      {
        id: "hunk_build_shared_01",
        hash: "sha256:hunk_build_shared_01",
        fileId: "file_build_shared",
        pathHash: "sha256:path_build_shared",
      },
    ],
  });
  await session.recordFileChange({
    occurredAt: t[4],
    sourceTreeId: "source_tree_app_builder_dev",
    baseVersion: 41,
    resultVersion: 42,
    rootHash: "sha256:root_after_safe_toasts",
    manifestDigest: "sha256:manifest_after_safe_toasts",
    changedBy: { type: "tool_call", id: "tool_apply_edits_01" },
    causedByProposalId: "proposal_safe_toasts_01",
    files: [
      {
        id: "file_build_shared",
        pathHash: "sha256:path_build_shared",
        beforeHash: "sha256:before_build_shared",
        afterHash: "sha256:after_build_shared",
        hunkHashes: ["sha256:hunk_build_shared_01"],
        action: "upsert",
      },
      {
        id: "file_deployments_tab",
        pathHash: "sha256:path_deployments_tab",
        beforeHash: "sha256:before_deployments_tab",
        afterHash: "sha256:after_deployments_tab",
        action: "upsert",
      },
    ],
  });
  await session.recordReview({
    occurredAt: t[5],
    pullRequestId: "pr_safe_toasts_01",
    reviewer: { type: "user", id: "usr_reviewer" },
    proposalId: "proposal_safe_toasts_01",
    approvalHash: "sha256:approval_safe_toasts",
    decision: "approved",
    findingCount: 0,
    waiverCount: 0,
  });
  await session.recordCiRun({
    occurredAt: t[6],
    ciRunId: "ci_safe_toasts_01",
    service: { type: "service", id: "svc_ci" },
    status: "succeeded",
    checks: ["typecheck", "unit", "diff-check"],
    artifactId: "artifact_safe_toasts_01",
    artifactHash: "sha256:artifact_safe_toasts",
    derivedFromFiles: [{ id: "file_build_shared", pathHash: "sha256:path_build_shared" }],
  });
  await session.recordDeployment({
    occurredAt: t[7],
    deploymentId: "dep_safe_toasts_01",
    service: { type: "service", id: "svc_deploy_worker" },
    artifactId: "artifact_safe_toasts_01",
    bundleHash: "sha256:bundle_safe_toasts",
    sourceHash: "sha256:source_safe_toasts",
    policyId: "policy_prod_deploy",
    policyRequirements: ["human_approval", "ci_passed", "artifact_attestation"],
  });
  await session.recordRuntimeEvent({
    occurredAt: t[8],
    runtimeEventId: "runtime_safe_toast_01",
    actor: { type: "user", id: "usr_reviewer" },
    action: "audit.runtime.observed",
    deploymentId: "dep_safe_toasts_01",
    routeHash: "sha256:route_app_settings_deployments",
    observedOutcome: "sanitized_error_copy",
  });

  return {
    tenantId,
    graph: await store.getEvidenceGraph({ tenantId }),
    verification: await store.verify({ tenantId }),
    exportPreview: await store.previewExportBundle({ tenantId }),
  };
}

/**
 * Seeds the first exceptional governed-change demo with a project-entry update,
 * derived estimate revision, and rollback-as-new-revision. Each governed change
 * is grouped through an EvidenceCommit batch so export and Workbench surfaces
 * can show ordered commit membership without claiming host transaction binding.
 */
export async function runGovernedChangeScenario(
  store: LocalEvidenceStore,
  options: { tenantId?: string } = {},
): Promise<GovernedChangeScenarioResult> {
  const tenantId = options.tenantId ?? "tenant_governed_change_demo";
  const scope = { tenantId, workspaceId: "workspace_estimates", environment: "dev" };
  const streamId = `str_${tenantId}_governed_changes`;
  const producer: EvidenceRef = { authority: "acme.billing", kind: "principal", type: "service", id: "billing-api" };
  const user: EvidenceRef = { authority: "auth.acme.internal", kind: "principal", type: "user", id: "usr_123" };
  const agent: EvidenceRef = { authority: "acme.ai", kind: "principal", type: "ai_agent", id: "cost_agent_7" };
  const projectEntry = defineEntity<{
    id: string;
    quantity: number;
    monthlyPrice: number;
    customerEmail: string;
    temporaryCache: string;
  }>({
    authority: "acme.billing",
    type: "project_entry",
    schemaRef: "acme.billing/project_entry@3",
    fieldSetRef: "project-entry-governed-fields@2",
    identity: (row) => row.id,
    fields: {
      quantity: { capture: "full" },
      monthlyPrice: { capture: "full" },
      customerEmail: { capture: "keyed_digest" },
      temporaryCache: { capture: "omit" },
    },
  });

  const priceDraft = createGovernedChangeDraft({
    scope,
    entity: projectEntry,
    before: { id: "42", quantity: 10, monthlyPrice: 142800, customerEmail: "buyer@example.com", temporaryCache: "hot" },
    after: { id: "42", quantity: 11, monthlyPrice: 148220, customerEmail: "buyer@example.com", temporaryCache: "warm" },
    changedPaths: ["/quantity", "/monthlyPrice"],
    change: { id: "chg_project_entry_price_01", type: "project.entry.price_recalculation", initiatedBy: user },
    activity: { id: "act_project_entry_price_01", type: "computation.project_cost_estimate", performedBy: agent },
    producer,
    occurredAt: "2026-06-23T10:18:00.000Z",
    idempotencyKeyHash: "sha256:price-change",
    context: {
      changeId: "chg_project_entry_price_01",
      traceId: "trc_project_entry_price",
      collectionSource: "governed-change-scenario",
    },
    capturePolicyRef: { id: "cap_project_changes", version: "3" },
    digestKeys: { keyedDigest: { keyVersion: "tenant-key-7", secret: "scenario-hmac-secret" } },
  });
  await store.recordBatch({
    commitId: "cmt_project_entry_price_01",
    streamId,
    events: priceDraft.events,
    edges: priceDraft.edges,
    committedAt: "2026-06-23T10:18:01.000Z",
  });

  const rollbackDraft = createGovernedChangeDraft({
    scope,
    entity: projectEntry,
    before: {
      id: "42",
      quantity: 11,
      monthlyPrice: 148220,
      customerEmail: "buyer@example.com",
      temporaryCache: "warm",
    },
    after: {
      id: "42",
      quantity: 10,
      monthlyPrice: 142800,
      customerEmail: "buyer@example.com",
      temporaryCache: "restored",
    },
    changedPaths: ["/quantity", "/monthlyPrice"],
    change: { id: "chg_project_entry_revert_01", type: "project.entry.rollback", initiatedBy: user },
    activity: { id: "act_project_entry_revert_01", type: "project.entry.rollback", performedBy: user },
    producer,
    occurredAt: "2026-06-23T10:24:00.000Z",
    idempotencyKeyHash: "sha256:rollback-change",
    context: {
      changeId: "chg_project_entry_revert_01",
      traceId: "trc_project_entry_revert",
      collectionSource: "governed-change-scenario",
    },
    capturePolicyRef: { id: "cap_project_changes", version: "3" },
    digestKeys: { keyedDigest: { keyVersion: "tenant-key-7", secret: "scenario-hmac-secret" } },
  });
  await store.recordBatch({
    commitId: "cmt_project_entry_revert_01",
    streamId,
    events: rollbackDraft.events,
    edges: rollbackDraft.edges,
    committedAt: "2026-06-23T10:24:01.000Z",
  });

  const changes = await store.listChanges({ tenantId });
  const entityTimeline = await store.getEntityTimeline({ tenantId, entityType: "project_entry", entityId: "42" });
  const explain = await store.explainChange({ tenantId }, "chg_project_entry_price_01");
  const firstOutputRevision = explain.outputRevisionIds[0];
  if (!firstOutputRevision) {
    throw new TypeError("governed change scenario did not produce an output revision");
  }
  const diff = await store.diffRevision({ tenantId }, firstOutputRevision);

  return {
    tenantId,
    graph: await store.getEvidenceGraph({ tenantId }),
    verification: await store.verify({ tenantId }),
    exportPreview: await store.previewExportBundle({ tenantId }),
    changes,
    entityTimeline,
    explain,
    diff,
  };
}

/**
 * Creates a fetch-compatible Workbench app around an injected LocalEvidenceStore.
 * The app boundary keeps storage injection explicit for tests and CLI startup.
 */
export function createWorkbenchApp(options: WorkbenchAppOptions = {}): WorkbenchApp {
  const store = options.store ?? new LocalEvidenceStore();
  return {
    store,
    /**
     * Handles one Workbench request through the fetch-compatible app boundary.
     */
    async fetch(request) {
      return handleWorkbenchRequest(store, request, { allowWriteTools: options.allowWriteTools ?? false });
    },
  };
}

/**
 * Starts the Node HTTP Workbench server and returns its local URL plus a close
 * hook. The default host remains loopback-only for local development.
 */
export async function startWorkbenchServer(options: StartWorkbenchServerOptions = {}): Promise<StartedWorkbenchServer> {
  const host = options.host ?? "127.0.0.1";
  const requestedPort = options.port ?? 4983;
  const app = createWorkbenchApp(options);
  const server = createServer((request, response) => {
    void handleNodeRequest(app, request, response);
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(requestedPort, host, () => {
      server.off("error", reject);
      resolve();
    });
  });

  const address = server.address();
  const port = typeof address === "object" && address ? address.port : requestedPort;
  return {
    app,
    server,
    host,
    port,
    url: `http://${host}:${port}`,
    /**
     * Stops the local HTTP server and resolves after Node releases the listener.
     */
    close() {
      return new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}

/**
 * Handles the local MCP JSON-RPC endpoint. Read tools are always exposed; write
 * tools require explicit allowWriteTools opt-in to avoid accidental mutation.
 */
export async function handleMcpRequest(
  store: LocalEvidenceStore,
  request: McpRequest,
  options: McpHandlerOptions = {},
): Promise<Record<string, any>> {
  const id = request.id ?? null;
  if (request.method === "initialize") {
    return rpcResult(id, {
      protocolVersion: "2025-03-26",
      serverInfo: { name: "veritio-local", version: "0.0.0" },
      capabilities: { tools: {} },
    });
  }
  if (request.method === "tools/list") {
    const tools = [...READ_TOOLS, ...(options.allowWriteTools ? WRITE_TOOLS : [])].map((name) => {
      return { name, description: toolDescription(name), inputSchema: { type: "object" } };
    });
    return rpcResult(id, { tools });
  }
  if (request.method !== "tools/call") {
    return rpcError(id, -32601, "Unsupported MCP method");
  }

  const params = request.params ?? {};
  const name = String(params.name ?? "");
  const args = isObject(params.arguments) ? params.arguments : {};
  if ((WRITE_TOOLS as readonly string[]).includes(name) && !options.allowWriteTools) {
    return rpcError(id, -32001, "MCP write tools are disabled");
  }

  try {
    switch (name) {
      case "veritio.list_events":
        return rpcResult(id, {
          records: await store.listEvents({ tenantId: requireTenantArg(args) }, listOptions(args)),
        });
      case "veritio.get_event":
        return rpcResult(id, { record: await store.getEvent(requireString(args.id, "id")) });
      case "veritio.list_edges":
        return rpcResult(id, {
          records: await store.listEdges({ tenantId: requireTenantArg(args) }, listOptions(args)),
        });
      case "veritio.list_commits":
        return rpcResult(id, { records: await store.listCommits(commitListOptions(args)) });
      case "veritio.list_changes":
        return rpcResult(id, { records: await store.listChanges({ tenantId: requireTenantArg(args) }) });
      case "veritio.get_evidence_graph":
        return rpcResult(id, { graph: await store.getEvidenceGraph(graphQuery(args)) });
      case "veritio.verify_chain":
        return rpcResult(id, await store.verify({ tenantId: requireTenantArg(args) }));
      case "veritio.preview_export_bundle":
        return rpcResult(id, await store.previewExportBundle({ tenantId: requireTenantArg(args) }));
      case "veritio.run_integration_scenario":
        return rpcResult(id, await runIntegrationScenario(store, scenarioOptions(optionalString(args.tenantId))));
      case "veritio.run_change_provenance_scenario":
        return rpcResult(id, await runChangeProvenanceScenario(store, scenarioOptions(optionalString(args.tenantId))));
      case "veritio.run_recorder_provenance_scenario":
        return rpcResult(
          id,
          await runRecorderProvenanceScenario(store, scenarioOptions(optionalString(args.tenantId))),
        );
      case "veritio.record_event":
        return rpcResult(id, { record: await store.recordEvent(args as unknown as AuditEventInput) });
      case "veritio.record_edge":
        return rpcResult(id, { record: await store.recordEdge(args as unknown as EvidenceEdgeInput) });
      case "veritio.record_batch":
        return rpcResult(id, await store.recordBatch(args as unknown as LocalEvidenceBatchInput));
      case "veritio.reset_dev_store":
        await store.reset();
        return rpcResult(id, { ok: true });
      case "veritio.create_export_bundle":
        return rpcResult(id, await createExportBundleResult(store, args));
      default:
        return rpcError(id, -32602, `Unknown MCP tool: ${name}`);
    }
  } catch (error) {
    return rpcError(id, -32000, error instanceof Error ? error.message : String(error));
  }
}

/**
 * Selects vevb-1 or vevb-2 from explicit MCP input. Checkpoint-aware creation
 * accepts only host-injected anchors and receipts, then returns sanitized
 * per-chain verdicts alongside the serialized bundle; the legacy v1 response
 * remains exactly `{ bundle }`.
 */
async function createExportBundleResult(
  store: LocalEvidenceStore,
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const tenantId = requireTenantArg(args);
  const createdAt = requireIsoTimestamp(args.createdAt, "createdAt");
  const version = args.bundleVersion ?? "vevb-1";
  if (version === "vevb-1") {
    return { bundle: await store.createExportBundle({ tenantId }, { createdAt }) };
  }
  if (version !== "vevb-2") throw new TypeError("bundleVersion must be vevb-1 or vevb-2");
  const bundleText = await store.createExportBundle(
    { tenantId },
    {
      createdAt,
      bundleVersion: "vevb-2",
      auditOrigin: args.auditOrigin as AuditOriginClaim,
      checkpoints: requireArray(args.checkpoints, "checkpoints"),
      dispositions: args.dispositions === undefined ? [] : requireArray(args.dispositions, "dispositions"),
    },
  );
  const bundle = parseExportBundle(bundleText);
  if (bundle.bundleVersion !== "vevb-2") throw new TypeError("vevb-2 selection failed");
  const verification = await verifyExportBundle(bundle);
  return { bundleVersion: "vevb-2", verification, bundle: bundleText };
}

/**
 * Routes Workbench HTTP requests across UI, local API reads, JSONL previews, and
 * MCP transport while preserving tenant parameters at every evidence boundary.
 */
async function handleWorkbenchRequest(
  store: LocalEvidenceStore,
  request: Request,
  options: McpHandlerOptions,
): Promise<Response> {
  const url = new URL(request.url);
  try {
    if (request.method === "GET" && url.pathname === "/") {
      return htmlResponse(renderWorkbenchHtml());
    }
    if (request.method === "GET" && url.pathname === "/favicon.ico") {
      return new Response(null, { status: 204 });
    }
    if (url.pathname === "/v1/events") {
      if (request.method === "GET") {
        return jsonResponse({
          records: await store.listEvents({ tenantId: requireTenantParam(url) }, listOptionsFromUrl(url)),
        });
      }
      if (request.method === "POST") {
        return jsonResponse({ record: await store.recordEvent((await request.json()) as AuditEventInput) }, 201);
      }
    }
    if (url.pathname === "/v1/edges") {
      if (request.method === "GET") {
        return jsonResponse({
          records: await store.listEdges({ tenantId: requireTenantParam(url) }, listOptionsFromUrl(url)),
        });
      }
      if (request.method === "POST") {
        return jsonResponse({ record: await store.recordEdge((await request.json()) as EvidenceEdgeInput) }, 201);
      }
    }
    if (url.pathname === "/v1/commits") {
      if (request.method === "GET") {
        return jsonResponse({ records: await store.listCommits(commitListOptionsFromUrl(url)) });
      }
    }
    if (url.pathname === "/v1/changes") {
      if (request.method === "GET") {
        return jsonResponse({ records: await store.listChanges({ tenantId: requireTenantParam(url) }) });
      }
    }
    if (url.pathname === "/v1/batches") {
      if (request.method === "POST") {
        return jsonResponse(await store.recordBatch((await request.json()) as LocalEvidenceBatchInput), 201);
      }
    }
    if (request.method === "GET" && url.pathname === "/v1/graph") {
      return jsonResponse(await store.getEvidenceGraph(graphQueryFromUrl(url)));
    }
    if (request.method === "GET" && url.pathname === "/v1/verify") {
      return jsonResponse(await store.verify({ tenantId: requireTenantParam(url) }));
    }
    if (request.method === "POST" && url.pathname === "/v1/exports/preview") {
      const body = (await request.json()) as Record<string, unknown>;
      return jsonResponse(await store.previewExportBundle({ tenantId: requireTenantArg(body) }));
    }
    if (request.method === "POST" && url.pathname === "/v1/scenarios/integration") {
      const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
      return jsonResponse(await runIntegrationScenario(store, scenarioOptions(optionalString(body.tenantId))));
    }
    if (request.method === "POST" && url.pathname === "/v1/scenarios/change-provenance") {
      const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
      return jsonResponse(await runChangeProvenanceScenario(store, scenarioOptions(optionalString(body.tenantId))));
    }
    if (request.method === "POST" && url.pathname === "/v1/scenarios/recorder") {
      const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
      return jsonResponse(await runRecorderProvenanceScenario(store, scenarioOptions(optionalString(body.tenantId))));
    }
    if (request.method === "POST" && url.pathname === "/v1/scenarios/governed-change") {
      const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
      return jsonResponse(await runGovernedChangeScenario(store, scenarioOptions(optionalString(body.tenantId))));
    }
    if (request.method === "POST" && url.pathname === "/mcp") {
      const body = (await request.json()) as McpRequest;
      return jsonResponse(await handleMcpRequest(store, body, options));
    }
    return jsonResponse({ error: "not_found" }, 404);
  } catch (error) {
    return jsonResponse({ error: error instanceof Error ? error.message : String(error) }, 400);
  }
}

/**
 * Renders the minimal Workbench shell. Runtime functionality stays behind the
 * local JSON APIs so static HTML does not embed mutable evidence state.
 */
function renderWorkbenchHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Veritio Workbench</title>
  <style>
    * { box-sizing: border-box; }
    body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f6f7f9; color: #111827; letter-spacing: 0; }
    header { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 14px 18px; border-bottom: 1px solid #d7dde7; background: #ffffff; }
    main { display: grid; grid-template-columns: minmax(250px, 320px) minmax(0, 1fr); min-height: calc(100vh - 61px); }
    aside { border-right: 1px solid #d7dde7; padding: 14px; background: #ffffff; }
    section { padding: 14px; }
    h1 { margin: 0; font-size: 20px; line-height: 1.2; }
    h2 { font-size: 13px; margin: 0; color: #374151; }
    table { width: 100%; border-collapse: collapse; table-layout: fixed; font-size: 13px; background: #ffffff; border: 1px solid #d7dde7; }
    th, td { padding: 8px 10px; border-bottom: 1px solid #e4e8ef; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
    th { color: #4b5563; font-size: 12px; font-weight: 650; background: #f8fafc; }
    tbody tr:last-child td { border-bottom: 0; }
    pre { min-width: 0; white-space: pre-wrap; background: #111827; color: #f9fafb; padding: 10px; border-radius: 6px; overflow: auto; max-height: 300px; font-size: 12px; }
    button { width: 100%; border: 1px solid #9aa4b2; background: #ffffff; border-radius: 6px; padding: 8px 10px; cursor: pointer; text-align: left; font: inherit; }
    button:hover { background: #f2f6fb; }
    input { width: 100%; border: 1px solid #9aa4b2; border-radius: 6px; padding: 8px 10px; font: inherit; }
    .stack { display: grid; gap: 10px; }
    .panel { display: grid; gap: 10px; min-width: 0; }
    .content { display: grid; grid-template-columns: minmax(0, 1.15fr) minmax(300px, .85fr); gap: 14px; align-items: start; }
    .metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; }
    .metric { border: 1px solid #d7dde7; background: #ffffff; padding: 10px; border-radius: 6px; min-width: 0; }
    .metric strong { display: block; font-size: 20px; line-height: 1.1; }
    .metric span, .muted { color: #5b6472; font-size: 12px; }
    .status { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; font-size: 12px; }
    .pill { border-radius: 999px; padding: 4px 8px; border: 1px solid #c9d2df; background: #ffffff; color: #374151; }
    .pill.ok { border-color: #7eb391; color: #14532d; background: #edf8f0; }
    .pill.warn { border-color: #e0b65a; color: #713f12; background: #fff7df; }
    .split { display: grid; gap: 14px; min-width: 0; }
    .hash { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; word-break: break-all; }
    @media (max-width: 900px) {
      header { align-items: flex-start; flex-direction: column; }
      main, .content { grid-template-columns: 1fr; }
      aside { border-right: 0; border-bottom: 1px solid #d7dde7; }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
  </style>
</head>
<body>
  <header>
    <h1>Veritio Workbench</h1>
    <div class="status" id="status">
      <span class="pill">audit pending</span>
      <span class="pill">edges pending</span>
      <span class="pill">commits pending</span>
    </div>
  </header>
  <main>
    <aside class="stack">
      <h2>Tenant</h2>
      <input id="tenant" value="tenant_local_demo" autocomplete="off">
      <h2>Scenarios</h2>
      <button id="governed">Run governed change demo</button>
      <button id="scenario">Run integration scenario</button>
      <button id="change-provenance">Run agent provenance tree</button>
      <button id="recorder">Run recorder provenance</button>
      <button id="refresh">Refresh graph</button>
    </aside>
    <section class="panel">
      <div class="metrics">
        <div class="metric"><strong id="metric-events">0</strong><span>audit records</span></div>
        <div class="metric"><strong id="metric-edges">0</strong><span>edge records</span></div>
        <div class="metric"><strong id="metric-commits">0</strong><span>evidence commits</span></div>
        <div class="metric"><strong id="metric-changes">0</strong><span>changes</span></div>
      </div>
      <div class="content">
        <div class="split">
          <div class="stack">
            <h2>Changes</h2>
            <table>
              <thead><tr><th>Change</th><th>Status</th><th>Activity</th><th>Outputs</th></tr></thead>
              <tbody id="changes"><tr><td colspan="4" class="muted">No changes</td></tr></tbody>
            </table>
          </div>
          <div class="stack">
            <h2>Evidence Graph</h2>
            <table>
              <thead><tr><th>Nodes</th><th>Edges</th><th>Relations</th></tr></thead>
              <tbody id="graph"><tr><td colspan="3" class="muted">No graph loaded</td></tr></tbody>
            </table>
          </div>
        </div>
        <div class="split">
          <div class="stack">
            <h2>Evidence Commits</h2>
            <table>
              <thead><tr><th>Sequence</th><th>Commit</th><th>Members</th></tr></thead>
              <tbody id="commits"><tr><td colspan="3" class="muted">No commits</td></tr></tbody>
            </table>
          </div>
          <div class="stack">
            <h2>Export Files</h2>
            <table>
              <thead><tr><th>File</th><th>Digest</th></tr></thead>
              <tbody id="files"><tr><td colspan="2" class="muted">No export preview</td></tr></tbody>
            </table>
          </div>
          <div class="stack">
            <h2>Selected Response</h2>
            <pre id="output">{"status":"ready"}</pre>
          </div>
        </div>
      </div>
    </section>
  </main>
  <script>
    const tenantInput = document.getElementById("tenant");
    const output = document.getElementById("output");
    const status = document.getElementById("status");
    const changesBody = document.getElementById("changes");
    const commitsBody = document.getElementById("commits");
    const graphBody = document.getElementById("graph");
    const filesBody = document.getElementById("files");
    const metricEvents = document.getElementById("metric-events");
    const metricEdges = document.getElementById("metric-edges");
    const metricCommits = document.getElementById("metric-commits");
    const metricChanges = document.getElementById("metric-changes");

    function tenantId() {
      return tenantInput.value.trim() || "tenant_local_demo";
    }

    async function showGraph() {
      const snapshot = await loadSnapshot();
      output.textContent = JSON.stringify(snapshot, null, 2);
      renderSnapshot(snapshot);
    }

    async function loadSnapshot() {
      const tenant = encodeURIComponent(tenantId());
      const [graph, changes, commits, verification, bundle] = await Promise.all([
        fetch("/v1/graph?tenantId=" + tenant).then((response) => response.json()),
        fetch("/v1/changes?tenantId=" + tenant).then((response) => response.json()),
        fetch("/v1/commits").then((response) => response.json()),
        fetch("/v1/verify?tenantId=" + tenant).then((response) => response.json()),
        fetch("/v1/exports/preview", { method: "POST", body: JSON.stringify({ tenantId: tenantId() }) }).then((response) => response.json()),
      ]);
      return { graph, changes: changes.records || [], commits: commits.records || [], verification, bundle };
    }

    function renderSnapshot(snapshot) {
      metricEvents.textContent = String(snapshot.bundle.manifest.recordCounts.events);
      metricEdges.textContent = String(snapshot.bundle.manifest.recordCounts.edges);
      metricCommits.textContent = String(snapshot.bundle.manifest.recordCounts.commits);
      metricChanges.textContent = String(snapshot.changes.length);
      status.innerHTML = [
        pill("audit", snapshot.verification.audit.ok),
        pill("edges", snapshot.verification.edges.ok),
        pill("commits", snapshot.verification.commits.ok),
      ].join("");
      changesBody.innerHTML = snapshot.changes.length ? snapshot.changes.map(renderChangeRow).join("") : emptyRow(4, "No changes");
      commitsBody.innerHTML = snapshot.commits.length ? snapshot.commits.map(renderCommitRow).join("") : emptyRow(3, "No commits");
      graphBody.innerHTML = renderGraphRow(snapshot.graph);
      filesBody.innerHTML = snapshot.bundle.manifest.files.map(renderFileRow).join("");
    }

    function pill(label, ok) {
      return '<span class="pill ' + (ok ? "ok" : "warn") + '">' + escapeHtml(label) + " " + (ok ? "ok" : "check") + "</span>";
    }

    function renderChangeRow(change) {
      return "<tr><td>" + escapeHtml(change.title) + '<div class="muted">' + escapeHtml(change.id) + "</div></td><td>" + escapeHtml(change.status) + "</td><td>" + escapeHtml(change.activityIds.join(", ")) + "</td><td>" + escapeHtml(change.outputRevisionIds.length) + "</td></tr>";
    }

    function renderCommitRow(commit) {
      return "<tr><td>" + escapeHtml(String(commit.sequence)) + "</td><td>" + escapeHtml(commit.commitId) + '<div class="hash">' + escapeHtml(commit.hash.slice(0, 19)) + "...</div></td><td>" + escapeHtml(String(commit.recordCount)) + "</td></tr>";
    }

    function renderGraphRow(graph) {
      const relations = Array.from(new Set(graph.edges.map((edge) => edge.relation))).slice(0, 8).join(", ");
      return "<tr><td>" + escapeHtml(String(graph.nodes.length)) + "</td><td>" + escapeHtml(String(graph.edges.length)) + "</td><td>" + escapeHtml(relations || "none") + "</td></tr>";
    }

    function renderFileRow(file) {
      return '<tr><td>' + escapeHtml(file.name) + '</td><td class="hash">' + escapeHtml(file.sha256) + "</td></tr>";
    }

    function emptyRow(columns, label) {
      return '<tr><td colspan="' + columns + '" class="muted">' + escapeHtml(label) + "</td></tr>";
    }

    function escapeHtml(value) {
      return String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
    }

    async function runScenario(path) {
      const response = await fetch(path, { method: "POST", body: JSON.stringify({ tenantId: tenantId() }) });
      const result = await response.json();
      output.textContent = JSON.stringify(result, null, 2);
      renderSnapshot(await loadSnapshot());
    }
    document.getElementById("scenario").addEventListener("click", async () => {
      await runScenario("/v1/scenarios/integration");
    });
    document.getElementById("change-provenance").addEventListener("click", async () => {
      await runScenario("/v1/scenarios/change-provenance");
    });
    document.getElementById("recorder").addEventListener("click", async () => {
      await runScenario("/v1/scenarios/recorder");
    });
    document.getElementById("governed").addEventListener("click", async () => {
      await runScenario("/v1/scenarios/governed-change");
    });
    document.getElementById("refresh").addEventListener("click", showGraph);
    showGraph().catch((error) => {
      output.textContent = JSON.stringify({ error: String(error) }, null, 2);
    });
  </script>
</body>
</html>`;
}

/**
 * Converts Node IncomingMessage/ServerResponse objects into Fetch Request and
 * Response objects so the app can be tested through a single fetch boundary.
 */
async function handleNodeRequest(
  app: WorkbenchApp,
  incoming: IncomingMessage,
  outgoing: ServerResponse,
): Promise<void> {
  try {
    const body = await readIncomingBody(incoming);
    const headers = new Headers();
    for (const [key, value] of Object.entries(incoming.headers)) {
      if (Array.isArray(value)) {
        headers.set(key, value.join(", "));
      } else if (value !== undefined) {
        headers.set(key, value);
      }
    }
    const requestInit: RequestInit = {
      method: incoming.method ?? "GET",
      headers,
    };
    if (body.length > 0 && incoming.method !== "GET" && incoming.method !== "HEAD") {
      requestInit.body = new Uint8Array(body);
    }
    const request = new Request(`http://${incoming.headers.host ?? "127.0.0.1"}${incoming.url ?? "/"}`, requestInit);
    const response = await app.fetch(request);
    outgoing.statusCode = response.status;
    response.headers.forEach((value, key) => outgoing.setHeader(key, value));
    outgoing.end(Buffer.from(await response.arrayBuffer()));
  } catch (error) {
    outgoing.statusCode = 500;
    outgoing.setHeader("content-type", "application/json; charset=utf-8");
    outgoing.end(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
  }
}

/**
 * Reads an incoming Node request body into a Buffer for the Fetch Request bridge.
 */
function readIncomingBody(request: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

/**
 * Detects already-normalized audit events before recording local scenario input.
 */
function isAuditEvent(value: AuditEventInput | AuditEvent): value is AuditEvent {
  return (value as AuditEvent).schemaVersion === "2026-06-10";
}

/**
 * Detects already-normalized evidence edges before recording local scenario input.
 */
function isEvidenceEdge(value: EvidenceEdgeInput | EvidenceEdge): value is EvidenceEdge {
  return (value as EvidenceEdge).schemaVersion === "2026-06-13";
}

/**
 * Narrows untrusted JSON or URL-derived values to plain objects.
 */
function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Requires tenant scope on API calls that operate on stored evidence.
 */
function requireTenantId(scope: EvidenceScope | undefined, field: string): string {
  return requireString(scope?.tenantId, field);
}

/**
 * Reads a tenant id from URL query parameters for Workbench HTTP APIs.
 */
function requireTenantParam(url: URL): string {
  return requireString(url.searchParams.get("tenantId"), "tenantId");
}

/**
 * Reads a tenant id from MCP tool arguments.
 */
function requireTenantArg(args: Record<string, unknown>): string {
  return requireString(args.tenantId, "tenantId");
}

/**
 * Derives an export bundle's `[from, to]` window from the ISO timestamps of the
 * selected records (audit `occurredAt`, edge `occurredAt`, commit `committedAt`).
 * All timestamps are canonical UTC ISO-8601, so a lexical min/max is a correct
 * chronological bound. An empty selection falls back to `createdAt` for both
 * ends, keeping the range valid without inventing a wider window.
 */
function exportBundleRange(
  events: AuditRecord[],
  edges: EvidenceEdgeRecord[],
  commits: EvidenceCommit[],
  createdAt: string,
): { from: string; to: string } {
  const timestamps = [
    ...events.map((record) => record.event.occurredAt),
    ...edges.map((record) => record.edge.occurredAt),
    ...commits.map((commit) => commit.committedAt),
  ]
    .filter((value): value is string => typeof value === "string")
    .sort();
  return {
    from: timestamps[0] ?? createdAt,
    to: timestamps[timestamps.length - 1] ?? createdAt,
  };
}

/**
 * Requires a non-empty string from untrusted request or tool input.
 */
function requireString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`${field} is required`);
  }
  return value;
}

/** Requires a host-injected protocol record list without coercion or defaults. */
function requireArray(value: unknown, field: string): unknown[] {
  if (!Array.isArray(value)) throw new TypeError(`${field} must be an array`);
  return value;
}

const ISO_8601_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?(Z|[+-]\d{2}:\d{2})$/;

/**
 * Requires an ISO-8601 timestamp so `createdAt` cannot poison a bundle's
 * canonical manifest. Accepts `Z` or a numeric UTC offset and fails closed on
 * any other string with the tool's sanitized invalid-argument message.
 */
function requireIsoTimestamp(value: unknown, field: string): string {
  const text = requireString(value, field);
  if (!ISO_8601_TIMESTAMP.test(text) || !Number.isFinite(Date.parse(text))) {
    throw new TypeError(`${field} must be an ISO-8601 timestamp`);
  }
  return text;
}

/**
 * Reads optional string input while rejecting non-string values.
 */
function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

/**
 * Validates local list pagination controls before they are used to slice records.
 */
function validateListOptions(options: LocalEvidenceStoreListOptions): void {
  if (options.afterSequence !== undefined && (!Number.isInteger(options.afterSequence) || options.afterSequence < 0)) {
    throw new TypeError("afterSequence must be a non-negative integer");
  }
  if (options.limit !== undefined && (!Number.isInteger(options.limit) || options.limit < 0)) {
    throw new TypeError("limit must be a non-negative integer");
  }
}

/**
 * Converts MCP JSON arguments into list options.
 */
function listOptions(value: Record<string, unknown>): LocalEvidenceStoreListOptions {
  const options: LocalEvidenceStoreListOptions = {};
  if (typeof value.afterSequence === "number") {
    options.afterSequence = value.afterSequence;
  }
  if (typeof value.limit === "number") {
    options.limit = value.limit;
  }
  return options;
}

/**
 * Converts Workbench URL parameters into list options.
 */
function listOptionsFromUrl(url: URL): LocalEvidenceStoreListOptions {
  const options: LocalEvidenceStoreListOptions = {};
  const afterSequence = url.searchParams.get("afterSequence");
  const limit = url.searchParams.get("limit");
  if (afterSequence !== null) {
    options.afterSequence = Number(afterSequence);
  }
  if (limit !== null) {
    options.limit = Number(limit);
  }
  return options;
}

/**
 * Converts MCP JSON arguments into EvidenceCommit list options.
 */
function commitListOptions(value: Record<string, unknown>): LocalEvidenceCommitListOptions {
  const options: LocalEvidenceCommitListOptions = { ...listOptions(value) };
  const streamId = optionalString(value.streamId);
  if (streamId) {
    options.streamId = streamId;
  }
  return options;
}

/**
 * Converts Workbench URL parameters into EvidenceCommit list options.
 */
function commitListOptionsFromUrl(url: URL): LocalEvidenceCommitListOptions {
  const options: LocalEvidenceCommitListOptions = { ...listOptionsFromUrl(url) };
  const streamId = url.searchParams.get("streamId");
  if (streamId) {
    options.streamId = streamId;
  }
  return options;
}

/**
 * Converts MCP JSON arguments into an evidence graph query.
 */
function graphQuery(value: Record<string, unknown>): EvidenceGraphQuery {
  const query: EvidenceGraphQuery = { tenantId: requireTenantArg(value) };
  const rootId = optionalString(value.rootId);
  const limit = typeof value.limit === "number" ? value.limit : undefined;
  if (rootId) {
    query.rootId = rootId;
  }
  if (limit !== undefined) {
    query.limit = limit;
  }
  return query;
}

/**
 * Converts Workbench URL parameters into an evidence graph query.
 */
function graphQueryFromUrl(url: URL): EvidenceGraphQuery {
  const query: EvidenceGraphQuery = { tenantId: requireTenantParam(url) };
  const rootId = url.searchParams.get("rootId");
  const limit = url.searchParams.get("limit");
  if (rootId) {
    query.rootId = rootId;
  }
  if (limit !== null) {
    query.limit = Number(limit);
  }
  return query;
}

/**
 * Builds the optional scenario seed configuration while omitting undefined
 * tenant ids so SDK default behavior remains visible.
 */
function scenarioOptions(tenantId: string | undefined): { tenantId?: string } {
  return tenantId ? { tenantId } : {};
}

/**
 * Applies an optional result limit after records have already been validated.
 */
function limited<T>(records: readonly T[], limit: number | undefined): T[] {
  return limit === undefined ? [...records] : records.slice(0, limit);
}

/**
 * Adds or preserves an evidence graph node keyed by stable entity identity.
 */
function addGraphNode(nodes: Map<string, EvidenceGraphNode>, entity: EvidenceEntity): void {
  if (!nodes.has(entity.id)) {
    nodes.set(entity.id, { id: entity.id, type: entity.type });
  }
}

/**
 * Converts a stored edge record into the graph edge shape returned by Workbench
 * APIs.
 */
function edgeRecordToGraphEdge(record: EvidenceEdgeRecord): EvidenceGraphEdge {
  return {
    id: record.edge.id,
    from: record.edge.from.id,
    to: record.edge.to.id,
    relation: record.edge.relation,
    source: "edge_record",
    recordHash: record.hash,
  };
}

/**
 * Projects one change declaration event plus related edges into the product
 * Change row shape used by Workbench and examples.
 */
function changeViewFromRecord(record: AuditRecord, edgeRecords: EvidenceEdgeRecord[]): ChangeView {
  const relatedEdges = edgeRecords.filter((edgeRecord) => edgeRecord.edge.from.id === record.event.target.id);
  const metadata = record.event.metadata as JsonObject;
  const view: ChangeView = {
    id: record.event.target.id,
    title: stringFromJson(metadata.changeType) ?? record.event.action,
    status: "declared",
    occurredAt: record.event.occurredAt,
    activityIds: relatedEdges
      .filter((edgeRecord) => edgeRecord.edge.relation === "has_activity")
      .map((edgeRecord) => edgeRecord.edge.to.id),
    outputRevisionIds: relatedEdges
      .filter((edgeRecord) => edgeRecord.edge.relation === "has_output")
      .map((edgeRecord) => edgeRecord.edge.to.id),
    supportingRecordIds: [record.event.id, ...relatedEdges.map((edgeRecord) => edgeRecord.edge.id)],
    assurance: ["current-protocol relation links present"],
  };
  const initiatedBy = evidenceRefFromJson(metadata.initiatedBy);
  if (initiatedBy) {
    view.initiatedBy = initiatedBy;
  }
  return view;
}

/**
 * Converts a revision compatibility event into one entity timeline row.
 */
function revisionFromRecord(record: AuditRecord): EntityTimeline["revisions"][number] {
  const revision = revisionPayloadFromRecord(record);
  const row: EntityTimeline["revisions"][number] = {
    id: revision.ref.id,
    occurredAt: record.event.occurredAt,
    changedPaths: Array.isArray(revision.changedPaths) ? revision.changedPaths.map(String) : [],
    stateCommitment: revision.stateCommitment as JsonObject,
    supportingRecordId: record.event.id,
  };
  const generatedBy = evidenceRefFromJson(revision.generatedBy);
  if (generatedBy) {
    row.generatedBy = generatedBy;
  }
  return row;
}

/**
 * Returns a timeline row only for records that actually contain revision
 * compatibility metadata.
 */
function revisionFromRecordOrNull(record: AuditRecord): EntityTimeline["revisions"][number] | null {
  try {
    return record.event.action === "entity.revision.created" ? revisionFromRecord(record) : null;
  } catch {
    return null;
  }
}

/**
 * Reads the current v1 revision compatibility encoding from event metadata.
 */
function revisionPayloadFromRecord(record: AuditRecord): Record<string, any> {
  const metadata = record.event.metadata as Record<string, any>;
  const revision = metadata.veritio?.revision;
  if (!revision || typeof revision !== "object") {
    throw new TypeError("revision metadata is missing");
  }
  return revision as Record<string, any>;
}

/**
 * Narrows JSON metadata back to an authority-qualified evidence ref when present.
 */
function evidenceRefFromJson(value: unknown): EvidenceRef | undefined {
  if (!isObject(value)) {
    return undefined;
  }
  const authority = optionalString(value.authority);
  const kind = optionalString(value.kind);
  const type = optionalString(value.type);
  const id = optionalString(value.id);
  if (!authority || !kind || !type || !id) {
    return undefined;
  }
  return { authority, kind: kind as EvidenceRef["kind"], type, id };
}

/**
 * Reads optional string values from JSON metadata without coercing objects.
 */
function stringFromJson(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/**
 * Sorts graph nodes deterministically for stable API responses.
 */
function compareNodes(left: EvidenceGraphNode, right: EvidenceGraphNode): number {
  return left.id.localeCompare(right.id);
}

/**
 * Builds the physical-record EvidenceCommit member manifest used by local
 * stores. Audit and edge hashes stay in their v1 envelope format and are
 * wrapped as algorithm-qualified commit member digests.
 */
function buildEvidenceCommitMembers(
  auditRecords: readonly AuditRecord[],
  edgeRecords: readonly EvidenceEdgeRecord[],
): EvidenceCommitInput["members"] {
  return [
    ...auditRecords.map((record, index) => ({
      index,
      recordType: "audit.record" as const,
      recordId: record.event.id,
      recordHash: `sha256:${record.hash}`,
    })),
    ...edgeRecords.map((record, index) => ({
      index: auditRecords.length + index,
      recordType: "evidence.edge.record" as const,
      recordId: record.edge.id,
      recordHash: `sha256:${record.hash}`,
    })),
  ];
}

/**
 * Serializes export preview records as newline-delimited canonical JSON.
 */
function toJsonl(records: readonly unknown[]): string {
  return records.map((record) => canonicalJson(record)).join("\n");
}

/**
 * Creates a JSON Response with the Workbench API content type.
 */
function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

/**
 * Creates an HTML Response for the Workbench shell.
 */
function htmlResponse(value: string): Response {
  return new Response(value, {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

/**
 * Builds a successful JSON-RPC envelope.
 */
function rpcResult(id: string | number | null, result: unknown): Record<string, any> {
  return { jsonrpc: "2.0", id, result };
}

/**
 * Builds an error JSON-RPC envelope with a stable code and message.
 */
function rpcError(id: string | number | null, code: number, message: string): Record<string, any> {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

/**
 * Provides tool descriptions for MCP clients without changing the tool schemas.
 */
function toolDescription(name: string): string {
  switch (name) {
    case "veritio.record_event":
      return "Record a local Veritio audit event when write tools are enabled.";
    case "veritio.record_edge":
      return "Record a local Veritio evidence graph edge when write tools are enabled.";
    case "veritio.record_batch":
      return "Record local audit events and graph edges with an EvidenceCommit when write tools are enabled.";
    case "veritio.reset_dev_store":
      return "Clear the local development evidence store.";
    case "veritio.create_export_bundle":
      return "Emit a portable, verifiable vevb-1 evidence export bundle when write tools are enabled.";
    default:
      return `Read local evidence through ${name}.`;
  }
}

/**
 * Computes SHA-256 identifiers for graph nodes and export bundle manifests.
 */
function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/**
 * Deep-clones local store values before returning them to callers.
 */
function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
