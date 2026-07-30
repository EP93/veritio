# `@veritio/tanstack-start`

Part of [Veritio](https://getveritio.com), the open-source evidence layer — see the [docs](https://getveritio.com/docs/) and [Veritio Cloud](https://getveritio.com/cloud/).

Thin TanStack Start adapter for recording route-handler and server-function
evidence through a host-configured Veritio recorder.

This package does not import TanStack Start runtime APIs, reads no environment
state, and owns no protocol semantics. Host applications resolve tenant/actor
context and inject a configured recorder from server-side code.

## Install

```sh
npm install @veritio/tanstack-start @veritio/core
```

## Usage

`resolveContext` runs on every record call and must return the tenant scope
and acting principal. The adapter **fails closed** with a `TypeError` when
`tenantId` or `actor` is missing, so an unauthenticated request can never
produce a scopeless event:

```ts
import { createAuditRecorder, MemoryAuditStore } from "@veritio/core";
import { createTanStackStartVeritioAdapter } from "@veritio/tanstack-start";

const recorder = createAuditRecorder({ store: new MemoryAuditStore() });

export const veritio = createTanStackStartVeritioAdapter({
  recorder,
  environment: "production",
  resolveContext: async (input) => {
    const session = await readSession(input.request); // host-owned auth
    return {
      tenantId: session.orgId,
      actor: { type: "user", id: session.userId },
    };
  },
});
```

Record inside a server route, or wrap a server function so evidence is written
only after it succeeds:

```ts
await veritio.recordRouteHandler({
  request,
  action: "entry.created",
  target: { type: "entry", id: entry.id },
});

// Evidence records only when the wrapped function resolves.
const result = await veritio.withServerFunction(
  { action: "entry.renamed", target: { type: "entry", id: entryId } },
  () => updateEntryTitle(entryId, title),
);
```

Per-call `idempotencyKey` and `append` options pass through to the store;
`purpose`, `lawfulBasis`, `dataCategories`, and `retention` stay
host-controlled.

For governed create/update/delete flows, prefer `@veritio/core`
`createGovernedActionDraft` inside the server function or route that owns the
database mutation. This adapter can provide request context for simple audit
events, but it does not own governed-change storage or protocol semantics. See
`../../docs/integrations.md`.

## Boundary

- The recorder (and any storage credentials behind it) stays server-side; never
  construct this adapter in browser-visible code. For client components, use
  `@veritio/react` intent attributes and record on the server.
- Prefer stable IDs in metadata — no emails, IP addresses, or freeform
  personal data.
- See `examples/tanstack-start-better-auth` for a full TanStack Start app
  recording governed CRUD and auth lifecycle evidence with a server-owned
  recorder.

Veritio supports audit trail evidence workflows; it is not legal advice and
does not guarantee compliance with any regulation or framework.
