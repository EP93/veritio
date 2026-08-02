import { buildFullGovernanceScenario } from "./scenario";

/**
 * Posts the full non-agent/non-code governance scenario to a deployed Veritio
 * Cloud project. Secrets stay in environment variables and are never logged.
 */
async function main() {
  const baseUrl = readEnv("VERITIO_CLOUD_BASE_URL", "http://localhost:3010");
  const projectId = readEnv("VERITIO_CLOUD_PROJECT_ID");
  const ingestToken = readEnv("VERITIO_CLOUD_INGEST_TOKEN");
  const readToken = process.env.VERITIO_CLOUD_READ_TOKEN;
  const scenario = buildFullGovernanceScenario({
    tenantId: projectId,
    environment: "test",
    actorId: process.env.VERITIO_CLOUD_ACTOR_ID ?? "sdk_poc_operator",
  });

  const response = await fetch(`${baseUrl}/api/ingest/events`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${ingestToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ events: scenario.events, edges: scenario.edges }),
  });
  const body = await readJson(response);
  if (!response.ok) {
    throw new Error(`Cloud ingest failed with ${response.status}: ${JSON.stringify(body)}`);
  }

  const result: Record<string, unknown> = {
    baseUrl,
    projectId,
    runId: scenario.runId,
    canonicalPlanHash: scenario.canonicalPlanHash,
    posted: { events: scenario.events.length, edges: scenario.edges.length },
    ingest: body,
  };

  if (readToken) {
    result.readBack = await readBack(baseUrl, projectId, scenario.runId, readToken);
  }

  console.log(JSON.stringify(result, null, 2));
}

/**
 * Reads the same run through Cloud's machine read API when a read-scoped key is
 * supplied. This keeps the script useful for CI without browser cookies.
 */
async function readBack(baseUrl: string, projectId: string, runId: string, readToken: string) {
  const headers = { authorization: `Bearer ${readToken}` };
  const [eventsResponse, edgesResponse, graphResponse] = await Promise.all([
    fetch(`${baseUrl}/api/evidence/events?projectId=${encodeURIComponent(projectId)}&limit=200`, { headers }),
    fetch(`${baseUrl}/api/evidence/edges?projectId=${encodeURIComponent(projectId)}&limit=200`, { headers }),
    fetch(`${baseUrl}/api/evidence/graph?projectId=${encodeURIComponent(projectId)}`, { headers }),
  ]);
  const [eventsBody, edgesBody, graphBody] = await Promise.all([
    readJson(eventsResponse),
    readJson(edgesResponse),
    readJson(graphResponse),
  ]);
  if (!eventsResponse.ok || !edgesResponse.ok || !graphResponse.ok) {
    throw new Error(
      `Cloud read-back failed: ${JSON.stringify({
        events: eventsResponse.status,
        edges: edgesResponse.status,
        graph: graphResponse.status,
      })}`,
    );
  }

  const events = Array.isArray((eventsBody as { events?: unknown[] }).events)
    ? (eventsBody as { events: unknown[] }).events.filter((record) => JSON.stringify(record).includes(runId))
    : [];
  const edges = Array.isArray((edgesBody as { edges?: unknown[] }).edges)
    ? (edgesBody as { edges: unknown[] }).edges.filter((record) => JSON.stringify(record).includes(runId))
    : [];
  const graph = (graphBody as { graph?: { nodes?: unknown[]; edges?: unknown[] } }).graph;

  return {
    events: events.length,
    edges: edges.length,
    graph: {
      nodes: graph?.nodes?.length ?? null,
      edges: graph?.edges?.length ?? null,
    },
  };
}

/**
 * Reads JSON response bodies while preserving text when a deployed edge returns
 * a non-JSON error.
 */
async function readJson(response: Response): Promise<unknown> {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return { text };
  }
}

/**
 * Reads required environment variables at the host boundary.
 */
function readEnv(name: string, fallback?: string): string {
  const value = process.env[name] ?? fallback;
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

await main();
