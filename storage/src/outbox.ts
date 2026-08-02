/**
 * Public transactional-outbox façade. Driver, serialization, and dispatch
 * concerns live in focused modules so lease and integrity invariants remain
 * independently reviewable.
 */

export * from "./outbox-dispatcher.js";
export * from "./outbox-file.js";
export * from "./outbox-sql.js";
export * from "./outbox-types.js";
