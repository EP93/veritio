# `@veritio/better-auth`

Part of [Veritio](https://getveritio.com), the open-source evidence layer — see the [docs](https://getveritio.com/docs/) and [Veritio Cloud](https://getveritio.com/cloud/).

Better Auth adapter for emitting Veritio events for auth lifecycle activity.

The adapter is a thin mapper. Host applications own Better Auth configuration,
tenant resolution, and Veritio storage setup.

Initial event targets:

- user creation
- session creation and revocation
- organization creation
- organization invitation creation and acceptance
- organization/member changes when used by the host app

This adapter must receive a configured Veritio recorder from the host application. It must not read secrets or storage credentials directly.

Use this adapter for auth lifecycle audit events. For governed CRUD actions
that happen after sign-in, call `createGovernedActionDraft` from the host
application's server-side mutation boundary; Better Auth does not own governed
entity storage or protocol semantics. See `../../docs/integrations.md`.

## Install

```sh
npm install @veritio/better-auth @veritio/core
```

## Usage

```ts
import { createAuditRecorder, MemoryAuditStore } from "@veritio/core";
import { createBetterAuthVeritioAdapter } from "@veritio/better-auth";

const store = new MemoryAuditStore();
const recorder = createAuditRecorder({ store });

export const veritioAuth = createBetterAuthVeritioAdapter({
  recorder,
  environment: "production",
});
```

Wire the returned methods from server-side Better Auth hooks. For example,
Better Auth `databaseHooks.user.create.after` can call `recordUserCreated`:

```ts
databaseHooks: {
  user: {
    create: {
      after: async (user) => {
        await veritioAuth.recordUserCreated({
          user: { id: user.id },
          tenantId: resolveTenantId(user),
        });
      },
    },
  },
}
```

Session hooks can pass an allowlisted auth-security context object when the host
intentionally records sign-in/logout context:

```ts
databaseHooks: {
  session: {
    create: {
      after: async (session, context) => {
        await veritioAuth.recordSessionCreated({
          user: { id: session.userId },
          session: { id: session.id },
          tenantId: await resolveTenantId(session.userId),
          requestId: context?.headers.get("x-request-id") ?? undefined,
          securityContext: {
            ipAddressHash: await hashIpAddress(session.ipAddress),
            userAgentHash: await hashUserAgent(session.userAgent),
            location: await resolveCountryRegion(context),
          },
        });
      },
    },
    delete: {
      after: async (session, context) => {
        await veritioAuth.recordSessionRevoked({
          user: { id: session.userId },
          session: { id: session.id },
          tenantId: await resolveTenantId(session.userId),
          requestId: context?.headers.get("x-request-id") ?? undefined,
        });
      },
    },
  },
}
```

For Better Auth organization plugin hooks, map only stable IDs and allowlisted
fields:

```ts
organizationHooks: {
  afterCreateOrganization: async ({ organization, user }) => {
    await veritioAuth.recordOrganizationCreated({
      actor: { id: user.id },
      organization: { id: organization.id },
    });
  },
  afterCreateInvitation: async ({ invitation, inviter, organization }) => {
    await veritioAuth.recordInvitationCreated({
      invitation: { id: invitation.id, role: invitation.role },
      inviter: { id: inviter.id },
      organization: { id: organization.id },
    });
  },
}
```

Do not pass raw emails, passwords, bearer tokens, reset tokens, authorization
headers, cookies, raw IP addresses, precise locations, or raw user agents into
adapter metadata. Prefer `securityContext.ipAddressHash`, `networkHash`,
`userAgentHash`, and country/region location when the host has intentionally
chosen to capture authentication security context.

## Defaults and determinism

Every recorded event carries `purpose: "access_management"`,
`lawfulBasis: "contract"`, and `retention: "security_1y"`, and derives a
deterministic idempotency key (for example
`better-auth:session-created:<tenantId>:<sessionId>`) so a replayed hook cannot
duplicate evidence. Stable IDs are required and validated before they become
tenant scope, actor, target, or idempotency-key material.

## Pure event mappers

When the host records through something other than an `AuditStore` (an outbox,
a queue, a hosted ingest call), use the pure mappers instead of the recorder
methods. They return a portable `AuditEventInput` with the same
metadata-minimization rules and no side effects:

```ts
import { buildBetterAuthSessionCreatedAuditEventInput } from "@veritio/better-auth";

const eventInput = buildBetterAuthSessionCreatedAuditEventInput(
  { user: { id: "usr_123" }, session: { id: "sess_123" }, tenantId: "org_123" },
  "production",
);
```

`buildBetterAuthUserCreatedAuditEventInput`,
`buildBetterAuthOrganizationCreatedAuditEventInput`, and
`buildBetterAuthSessionRevokedAuditEventInput` follow the same shape.

## Full examples

Five runnable reference apps wire this adapter end to end (Better Auth
lifecycle hooks + governed CRUD + evidence graph): `examples/nextjs-better-auth`,
`examples/react-better-auth`, `examples/vue-better-auth`,
`examples/sveltekit-better-auth`, and `examples/tanstack-start-better-auth`.

Veritio supports audit trail evidence workflows; it is not legal advice and
does not guarantee compliance with any regulation or framework.
