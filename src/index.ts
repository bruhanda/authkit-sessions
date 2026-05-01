/**
 * `@authkit/sessions` — universal, edge-runtime-native session manager.
 *
 * The core entry point keeps the bundle minimal: only the manager
 * factory, the error class, and the public type surface. Every opt-in
 * feature lives at its own subpath (`@authkit/sessions/csrf`,
 * `/fingerprint`, `/concurrency`, `/audit`) so a build that never
 * imports a feature ships zero feature code.
 */

export { createSessionManager } from './core/manager.js';
export { SessionError } from './errors/base.js';

export type {
  AuditEvent,
  AuditHook,
  CookieOptions,
  ConcurrencyPolicy,
  CsrfConfig,
  DestroyReason,
  Device,
  EvictionStrategy,
  ExpirationPolicy,
  FingerprintConfig,
  Result,
  SessionAttachment,
  SessionConfig,
  SessionData,
  SessionFeature,
  SessionManager,
  SessionMetadata,
  SessionRecord,
  SessionStore,
} from './types/index.js';
