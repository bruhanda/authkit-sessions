import type { Device } from './device.js';
import type { EvictionStrategy } from './policy.js';
import type { SessionErrorCode } from '../errors/codes.js';

/**
 * Why a session was destroyed. Carried inside `session.destroyed` audit
 * events so dashboards can distinguish voluntary logouts from forced
 * revocations.
 */
export type DestroyReason =
  | 'logout'
  | 'expired'
  | 'rotated'
  | 'evicted'
  | 'fingerprint-mismatch'
  | 'manual';

/**
 * Discriminated union of every event the manager emits. Listening for
 * specific `type` values gives type-safe access to per-event fields with
 * no manual casts.
 */
export type AuditEvent =
  | { type: 'session.created'; sessionId: string; userId?: string; device?: Device; at: number }
  | { type: 'session.read'; sessionId: string; at: number }
  | { type: 'session.read.failed'; reason: SessionErrorCode; at: number }
  | { type: 'session.updated'; sessionId: string; at: number }
  | { type: 'session.rotated'; oldId: string; newId: string; at: number }
  | { type: 'session.destroyed'; sessionId: string; reason: DestroyReason; at: number }
  | { type: 'session.evicted'; sessionId: string; userId: string; strategy: EvictionStrategy; at: number }
  | { type: 'csrf.failed'; reason: 'missing' | 'mismatch' | 'origin' | 'no-session'; at: number };

/**
 * Audit hook. Errors thrown inside the hook are caught and swallowed — audit
 * MUST NOT break request flow. Use `composeAuditHook(...hooks)` to fan out
 * to multiple destinations (console, OTel, Sentry).
 */
export type AuditHook = (event: AuditEvent) => void | Promise<void>;
