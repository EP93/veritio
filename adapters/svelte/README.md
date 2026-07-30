# `@veritio/svelte`

Part of [Veritio](https://getveritio.com), the open-source evidence layer — see the [docs](https://getveritio.com/docs/) and [Veritio Cloud](https://getveritio.com/cloud/).

Browser-safe Svelte helpers for annotating UI elements with inert Veritio
evidence-intent attributes (`data-veritio-action`, `data-veritio-target-type`,
`data-veritio-target-id`, `data-veritio-purpose`).

This package does not import Svelte runtime APIs, has **no dependency on
`@veritio/core`**, and does not record audit events. It only declares what a
UI element *intends*; a server-side adapter (for example `@veritio/sveltekit`
or `@veritio/better-auth`) must translate trusted request context into
recorded events through an injected recorder.

## Install

```sh
npm install @veritio/svelte
```

## Usage

```ts
import { createSvelteVeritioAttributes } from "@veritio/svelte";

const attrs = createSvelteVeritioAttributes({
  action: "ui.dsar.requested",
  target: { type: "form", id: "dsar-request" },
});
```

```svelte
<form {...attrs}>
  <button type="submit">Request export</button>
</form>
```

The returned object is frozen and contains only the `data-veritio-*` strings.
`createVeritioAttributes` is exported as a shorter alias.

For governed create/update/delete flows, submit form/API intent to a server
boundary and call `createGovernedActionDraft` from `@veritio/core` there.
Svelte attributes are only browser-visible hints; they do not carry tenant
scope, storage, idempotency, or protocol semantics. See
`../../docs/integrations.md`.

## Server-only keys are rejected

Because these attributes render into the DOM, the builder **fails closed**
with a `TypeError` if the input carries any server-only key — `recorder`,
`store`, `scope`, `tenantId`, `actor`, `metadata`, `secret`, `token`,
`password`, `authorization`, API keys, connection strings, and similar.
Tenant scope and actor identity are resolved server-side at record time,
never embedded in the page.

Veritio supports audit trail evidence workflows; it is not legal advice and
does not guarantee compliance with any regulation or framework.
