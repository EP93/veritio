# Veritio

[English](README.md) | **Deutsch** | [한국어](README.ko.md) | [简体中文](README.zh-CN.md)

[getveritio.com](https://getveritio.com/de/) · [Doku](https://getveritio.com/docs/) · [Veritio Cloud](https://getveritio.com/de/cloud/)

[![Verify](https://github.com/getveritio/veritio/actions/workflows/verify.yml/badge.svg)](https://github.com/getveritio/veritio/actions/workflows/verify.yml)
[![npm](https://img.shields.io/npm/v/%40veritio%2Fcore?label=%40veritio%2Fcore)](https://www.npmjs.com/package/@veritio/core)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

> Dieses Dokument ist eine Übersetzung des englischen [README](README.md). Bei
> Abweichungen ist die englische Fassung maßgeblich.

Veritio ist ein protokollbasierter Open-Source-**Evidence-Layer**:
manipulationsevidente Audit-Trails, KI-Agenten-Provenienz, Einwilligungs- und
DSAR-Workflow-Nachweise, Aufbewahrungsereignisse und Compliance-Exporte, die
jeder offline verifizieren kann.

Veritio unterstützt die Erhebung und Verifikation von Compliance-Nachweisen; es
ist keine Rechtsberatung und macht eine Anwendung nicht automatisch konform mit
DSGVO, EAA, SOC 2, HIPAA, DORA, NIS2 oder irgendeinem anderen Rahmenwerk.

## Warum Veritio

- **Manipulationsevident per Konstruktion.** Append-only-Records mit
  kanonischem JSON, SHA-256-Hash-Ketten und mandantenbezogener Idempotenz. Die
  Verifikation erkennt Veränderung, Löschung und Umordnung.
- **Offline verifizierbar.** Ein signiertes Evidence-Bundle (`vevb-1`)
  exportieren und überall prüfen — ohne Netzwerk, ohne Anbieter, ohne Konto.
- **Ein Protokoll, kein Lock-in.** Sprachneutrale Schemas in [`spec/`](spec/),
  mit TypeScript-, Python- und Go-SDKs, die byte-identische Hashes und Scores
  erzeugen, fixiert durch sprachübergreifende Konformitäts-Fixtures.
- **KI-Agenten-Provenienz.** Claude-Code-Sitzungen als hash-verkettete,
  redigierte Evidenz erfassen — Prompts, Tool-Aufrufe und Dateiänderungen als
  Hashes und stabile IDs, niemals Rohinhalte.
- **Deterministisches Risiko-Scoring.** Strukturierte Risikosignale ergeben in
  allen drei SDKs identische Bytes; keine Modellaufrufe, keine Heuristiken zur
  Abfragezeit.
- **Privacy by default.** Deterministische Metadaten-Redaktion, stabile IDs
  statt personenbezogener Daten und Fail-closed-Integrität bei fehlenden
  Pflichtfeldern.
- **Dünne Ränder.** Framework-Adapter übersetzen nur Kontext; Storage wird vom
  Host injiziert — eure Datenbank-Clients, eure Zugangsdaten, niemals unsere.

## Schnellstart

```sh
npm install @veritio/core
```

```ts
import { MemoryAuditStore, createAuditEvent } from "@veritio/core";

const store = new MemoryAuditStore();

const record = await store.append(
  createAuditEvent({
    id: "evt_01",
    occurredAt: "2026-06-10T00:00:00.000Z",
    actor: { type: "user", id: "usr_123" },
    action: "org.member.invited",
    target: { type: "organization", id: "org_123" },
    scope: { tenantId: "org_123", environment: "production" },
    purpose: "access_management",
    lawfulBasis: "contract",
    retention: "security_1y",
    metadata: { inviteId: "inv_123", role: "viewer" },
  }),
);
// record.hash verkettet sich mit dem vorherigen Record dieses Mandanten.
```

Für dauerhafte Speicherung injiziert der Host eigene Datenbank-Clients über
[`@veritio/storage`](storage/README.md) (Postgres, Neon, MySQL, MariaDB,
MongoDB, dazu ein lokaler File-Store und ein Redis-Tip-Cache). Die Python- und
Go-SDKs bieten dieselbe Event-, Hashing- und Redaktionssemantik — siehe
[`sdks/python`](sdks/python/) und [`sdks/go`](sdks/go/).

**Später beweisen.** Ein portables Export-Bundle bauen und offline
verifizieren — mit Einzelergebnissen für `structure` / `integrity` / `chains` /
`signature` und einem finalen `VALID` / `INVALID`:

```sh
veritio verify-bundle bundle.json --public-key key.hex --require-signature
```

Das Bundle-Format ist normativ in
[`spec/export-bundle.md`](spec/export-bundle.md) beschrieben; die
`veritio`-CLI läuft derzeit aus diesem Repository und ist noch nicht auf npm.

## KI-Agenten-Aktivität erfassen

[`@veritio/claude-code`](adapters/claude-code/README.md) zeichnet
Claude-Code-Sitzungen als hash-verkettete Provenienzspur auf — out-of-band über
Hooks, sodass die Evidenz nicht davon abhängt, dass der Agent sich selbst
meldet:

- Prompts, Tool-Eingaben und Dateiinhalte werden **nur als Hashes und stabile
  IDs** erfasst — Rohinhalte gelangen nie in die Spur.
- Jedes Ereignis trägt die `sessionId` der Sitzung und eine dauerhafte
  `activityEpisodeId`, sodass eine ganze Agentensitzung zu einer prüfbaren
  Episode zusammengefasst wird.
- Bash-Befehle und Dateiänderungen werden in strukturierte
  `metadata.riskSignals` klassifiziert und vom SDK-Risikomodul deterministisch
  bewertet (Policy `veritio.reference.v1`) — dieselben Bytes in TypeScript,
  Python und Go. Siehe [docs/risk-scoring.md](docs/risk-scoring.md).
- Ein rein lesender MCP-Server erlaubt es Menschen oder anderen Agenten,
  Sitzungen aufzulisten, den Provenienzgraphen zu inspizieren und ein
  verifizierbares Bundle zu exportieren.

Coding-Agenten das SDK selbst beibringen — über [skills.sh](https://www.skills.sh):

```sh
npx skills add getveritio/veritio
```

## Governed Actions

Wenn eine Server-Action oder API-Route eine governete Entität verändert, leitet
ein einziger Helfer Change-/Activity-IDs, mandantenbezogene Idempotenz-Hashes,
geänderte Pfade, Revisionsnachweise und Outbox-fertige Event- und Edge-Inputs
ab — verfügbar als `createGovernedActionDraft` (TS),
`create_governed_action_draft` (Python) und `CreateGovernedActionDraft` (Go):

```ts
import { createGovernedActionDraft, defineEntity } from "@veritio/core";

const ProjectEntry = defineEntity({
  authority: "app.example",
  type: "project_entry",
  schemaRef: "app.example/project-entry@1",
  fieldSetRef: "project-entry-governed-fields@1",
  identity: (row: { id: string }) => row.id,
  fields: {
    status: { capture: "full" },
    customerEmail: { capture: "keyed_digest" },
    privateNotes: { capture: "omit" },
  },
});
```

Governed Actions gehören an die serverseitige Mutationsgrenze der
Geschäftslogik, nicht in Browser-Formular-State. Vollständige Rezepte —
TypeScript, FastAPI, Gin, Framework-Adapter, Hosted Ingest und transaktionale
Outbox — stehen in [`docs/integrations.md`](docs/integrations.md).

## Lokale Workbench

Die lokale Workbench samt MCP-Endpoint läuft ohne jedes Konto:

```sh
veritio dev --mcp --scenario
```

Sie bedient Event-/Edge-Ingest, Evidenzgraph-Abfragen, Kettenverifikation,
Export-Vorschau, eine Browser-UI und einen MCP-JSON-RPC-Endpoint unter `/mcp`
auf `http://127.0.0.1:4983`. Schreibende Tools bleiben verborgen, solange nicht
mit `--allow-write-tools` gestartet wird.

## Ökosystem

| Paket | Status | Rolle |
| --- | --- | --- |
| [`@veritio/core`](sdks/typescript/) | npm | TypeScript-SDK: Events, Edges, Hashing, Redaktion, Templates, Provenienz-Recorder, Risiko-Scoring, Assertions. |
| [`@veritio/storage`](storage/) | npm | Host-injizierte Postgres/Neon/MySQL/MariaDB/MongoDB-Stores, Redis-Tip-Cache, File-Store, Konformitätstests. |
| [`@veritio/claude-code`](adapters/claude-code/) | npm | Claude-Code-Capture-Hooks + rein lesendes MCP-Query/-Export. |
| [`@veritio/better-auth`](adapters/better-auth/) | npm | Serverseitiger Better-Auth-Lifecycle-Adapter. |
| [`@veritio/next`](adapters/next/), [`@veritio/tanstack-start`](adapters/tanstack-start/), [`@veritio/sveltekit`](adapters/sveltekit/) | npm | Serverseitige Framework-Adapter. |
| [`@veritio/react`](adapters/react/), [`@veritio/vue`](adapters/vue/), [`@veritio/svelte`](adapters/svelte/) | npm | Browser-sichere UI-Intent-Helfer; kein clientseitiges Recording. |
| [`sdks/python`](sdks/python/) | im Repo | Python-SDK (`pip install -e sdks/python`; noch nicht auf PyPI). |
| [`sdks/go`](sdks/go/) | Go-Modul | `go get github.com/getveritio/veritio/sdks/go`. |
| `veritio`-CLI, `@veritio/server`, `@veritio/gateway`, `@veritio/codex`, express/hono/trpc-Shells | im Repo | Lokale Workbench/MCP-CLI, selbstgehostetes Servermodul, experimentelles KI-Gateway und noch unveröffentlichte Adapter-Oberflächen. |

## Veritio Cloud

[Veritio Cloud](https://getveritio.com/de/cloud/) ist die gehostete Option:
verwalteter Ingest, Dashboards, Risiko-Timelines und regionsbewusste Exporte
auf Basis desselben Protokolls. Alles in diesem Repository funktioniert
vollständig self-hosted ohne Konto — Hosted Delivery ist immer optional.

## Mehr erfahren

- [`spec/`](spec/) — sprachneutrale Schemas, Hash-Regeln und
  Konformitäts-Fixtures; die Quelle der Wahrheit für das Protokoll.
- [`docs/architecture.md`](docs/architecture.md) — Schichten,
  Integritätsmodell, Redaktion, Risiko und die Hosted-Grenze.
- [`docs/integrations.md`](docs/integrations.md) — Integrationsrezepte.
- [`docs/ai-integration.md`](docs/ai-integration.md) — KI-Agenten-Capture und
  MCP-Leitfaden.
- [`examples/`](examples/) — lauffähige Beispiele für Better Auth, FastAPI,
  Gin, Storage und Hosted Ingest.
- Mitmachen: `bun install && bun run verify` führt das vollständige
  sprachübergreifende Gate aus; siehe
  [`docs/release-checklist.md`](docs/release-checklist.md).

## Lizenz

Apache-2.0.
