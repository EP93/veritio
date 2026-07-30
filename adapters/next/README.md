# `@veritio/next`

Part of [Veritio](https://getveritio.com), the open-source evidence layer — see the [docs](https://getveritio.com/docs/) and [Veritio Cloud](https://getveritio.com/cloud/).

Thin Next.js adapter for recording route-handler and server-action evidence
through a host-configured Veritio recorder.

This package does not import Next.js runtime APIs, reads no environment state,
and owns no protocol semantics. Host applications resolve tenant/actor context
and inject a configured recorder from server-side code.

## Install

```sh
npm install @veritio/next @veritio/core
```

## Usage

`resolveContext` runs on every record call and must return the tenant scope
and acting principal. The adapter **fails closed** with a `TypeError` when
`tenantId` or `actor` is missing, so an unauthenticated request can never
produce a scopeless event:

```ts
import { createAuditRecorder, MemoryAuditStore } from "@veritio/core";
import { createNextVeritioAdapter } from "@veritio/next";

const recorder = createAuditRecorder({ store: new MemoryAuditStore() });

export const veritio = createNextVeritioAdapter({
  recorder,
  environment: "production",
  resolveContext: async (input) => {
    const session = await readSession(input.request); // host-owned auth
    return {
      tenantId: session.orgId,
      actor: { type: "user", id: session.userId },
      requestId: session.requestId,
    };
  },
});
```

Record inside a route handler, or wrap a server action so evidence is written
only after the action succeeds:

```ts
// app/api/entries/route.ts
export async function POST(request: Request) {
  const entry = await createEntry(request);
  await veritio.recordRouteHandler({
    request,
    action: "entry.created",
    target: { type: "entry", id: entry.id },
    metadata: { source: "api" },
  });
  return Response.json(entry);
}

// app/actions.ts — evidence records only when the handler resolves.
export async function renameEntry(id: string, title: string) {
  return veritio.withServerAction(
    { action: "entry.renamed", target: { type: "entry", id } },
    () => updateEntryTitle(id, title),
  );
}
```

Per-call `idempotencyKey` and `append` options pass through to the store;
`purpose`, `lawfulBasis`, `dataCategories`, and `retention` stay
host-controlled.

For governed create/update/delete flows, prefer `@veritio/core`
`createGovernedActionDraft` inside the server action or route handler that owns
the database mutation. This adapter can provide request context for simple audit
events, but it does not own governed-change storage or protocol semantics. See
`../../docs/integrations.md`.

## Boundary

- The recorder (and any storage credentials behind it) stays server-side; never
  construct this adapter in browser-visible code. For client components, use
  `@veritio/react` intent attributes and record on the server.
- Prefer stable IDs in metadata — no emails, IP addresses, or freeform
  personal data.
- See `examples/nextjs-better-auth` for a full Next.js app recording governed
  CRUD and auth lifecycle evidence with a server-owned recorder.

Veritio supports audit trail evidence workflows; it is not legal advice and
does not guarantee compliance with any regulation or framework.
