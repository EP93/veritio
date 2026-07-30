# `@veritio/sveltekit`

Part of [Veritio](https://getveritio.com), the open-source evidence layer — see the [docs](https://getveritio.com/docs/) and [Veritio Cloud](https://getveritio.com/cloud/).

Thin SvelteKit adapter for recording form-action and endpoint evidence through
a host-configured Veritio recorder.

This package does not import SvelteKit runtime APIs, reads no environment
state, and owns no protocol semantics. Host applications resolve tenant/actor
context (typically from `event.locals`) and inject a configured recorder from
server-side code.

## Install

```sh
npm install @veritio/sveltekit @veritio/core
```

## Usage

`resolveContext` runs on every record call and must return the tenant scope
and acting principal. The adapter **fails closed** with a `TypeError` when
`tenantId` or `actor` is missing, so an unauthenticated request can never
produce a scopeless event:

```ts
import { createAuditRecorder, MemoryAuditStore } from "@veritio/core";
import { createSvelteKitVeritioAdapter } from "@veritio/sveltekit";

const recorder = createAuditRecorder({ store: new MemoryAuditStore() });

export const veritio = createSvelteKitVeritioAdapter({
  recorder,
  environment: "production",
  resolveContext: (input) => {
    const locals = input.locals as { tenantId: string; userId: string };
    return {
      tenantId: locals.tenantId,
      actor: { type: "user", id: locals.userId },
    };
  },
});
```

Record inside an endpoint, or wrap a form action so evidence is written only
after it succeeds:

```ts
// +server.ts endpoint
await veritio.recordEndpoint({
  locals,
  action: "entry.created",
  target: { type: "entry", id: entry.id },
});

// +page.server.ts action — evidence records only when the handler resolves.
const result = await veritio.withAction(
  { locals, action: "entry.renamed", target: { type: "entry", id: entryId } },
  () => updateEntryTitle(entryId, title),
);
```

Per-call `idempotencyKey` and `append` options pass through to the store;
`purpose`, `lawfulBasis`, `dataCategories`, and `retention` stay
host-controlled.

For governed create/update/delete flows, prefer `@veritio/core`
`createGovernedActionDraft` inside the action or endpoint that owns the database
mutation. This adapter can provide request context for simple audit events, but
it does not own governed-change storage or protocol semantics. See
`../../docs/integrations.md`.

## Boundary

- The recorder (and any storage credentials behind it) stays server-side; never
  construct this adapter in browser-visible code. For client components, use
  `@veritio/svelte` intent attributes and record on the server.
- Prefer stable IDs in metadata — no emails, IP addresses, or freeform
  personal data.
- See `examples/sveltekit-better-auth` for a full SvelteKit app recording
  governed CRUD and auth lifecycle evidence with a server-owned recorder.

Veritio supports audit trail evidence workflows; it is not legal advice and
does not guarantee compliance with any regulation or framework.
