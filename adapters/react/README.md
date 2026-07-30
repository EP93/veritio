# `@veritio/react`

Part of [Veritio](https://getveritio.com), the open-source evidence layer — see the [docs](https://getveritio.com/docs/) and [Veritio Cloud](https://getveritio.com/cloud/).

Browser-safe React helpers for annotating UI elements with inert Veritio
evidence-intent attributes (`data-veritio-action`, `data-veritio-target-type`,
`data-veritio-target-id`, `data-veritio-purpose`).

This package does not import React runtime APIs, has **no dependency on
`@veritio/core`**, and does not record audit events. It only declares what a
UI element *intends*; a server-side framework or auth adapter (for example
`@veritio/next` or `@veritio/better-auth`) must translate trusted request
context into recorded events through an injected recorder.

## Install

```sh
npm install @veritio/react
```

## Usage

```tsx
import { createReactVeritioAttributes } from "@veritio/react";

const attrs = createReactVeritioAttributes({
  action: "ui.export.clicked",
  target: { type: "button", id: "export" },
  purpose: "data_subject_workflow",
});

export function ExportButton() {
  return <button {...attrs}>Export</button>;
}
```

The returned object is frozen and contains only the `data-veritio-*` strings.
`createVeritioAttributes` is exported as a shorter alias.

For governed create/update/delete flows, submit form/API intent to a server
boundary and call `createGovernedActionDraft` from `@veritio/core` there. React
attributes are only browser-visible hints; they do not carry tenant scope,
storage, idempotency, or protocol semantics. See `../../docs/integrations.md`.

## Server-only keys are rejected

Because these attributes render into the DOM, the builder **fails closed**
with a `TypeError` if the input carries any server-only key — `recorder`,
`store`, `scope`, `tenantId`, `actor`, `metadata`, `secret`, `token`,
`password`, `authorization`, API keys, connection strings, and similar.
Tenant scope and actor identity are resolved server-side at record time,
never embedded in the page.

Veritio supports audit trail evidence workflows; it is not legal advice and
does not guarantee compliance with any regulation or framework.
