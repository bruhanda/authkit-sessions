import type { AuditEvent, AuditHook } from '../types/audit.js';
import type { Device } from '../types/device.js';
import type { SessionFeature } from '../types/feature.js';
import type { EvictionStrategy } from '../types/policy.js';
import type { SessionData, SessionMetadata, SessionRecord } from '../types/session.js';
import type { SessionStore } from '../types/store.js';

/**
 * Internal-only feature implementation shapes. The public `SessionFeature`
 * type carries only `__feature` discriminator; the manager inspects the
 * concrete impl on the same object.
 *
 * Factories (`csrf()`, `fingerprint()`, etc.) construct values typed as
 * the corresponding impl interface and return them as the public
 * `SessionFeature`. The manager narrows back via the discriminator and
 * a single, well-commented type assertion.
 *
 * @internal — never exported from the package root.
 */

/** Audit feature — exposes the `AuditHook` directly. */
export interface AuditFeatureImpl extends SessionFeature {
  readonly __feature: 'audit';
  readonly hook: AuditHook;
}

/** CSRF feature — encapsulates the double-submit cookie configuration. */
export interface CsrfFeatureImpl extends SessionFeature {
  readonly __feature: 'csrf';
  readonly cookieName: string;
  readonly headerName: string;
  readonly protectedMethods: ReadonlySet<'POST' | 'PUT' | 'PATCH' | 'DELETE'>;
  readonly enforceOrigin: boolean;
}

/** Fingerprint feature — captures and verifies device hashes. */
export interface FingerprintFeatureImpl extends SessionFeature {
  readonly __feature: 'fingerprint';
  readonly include: ReadonlyArray<'user-agent' | 'accept-language' | 'ip' | 'sec-ch-ua'>;
  readonly ipExtractor: ((req: Request) => string | undefined) | undefined;
  readonly onMismatch: 'rotate' | 'destroy' | 'ignore';
}

/** Concurrency feature — enforces per-user session limits. */
export interface ConcurrencyFeatureImpl extends SessionFeature {
  readonly __feature: 'concurrency';
  readonly max: number;
  readonly strategy: EvictionStrategy;
}

/** Discriminated union of every feature implementation. */
export type FeatureImpl =
  | AuditFeatureImpl
  | CsrfFeatureImpl
  | FingerprintFeatureImpl
  | ConcurrencyFeatureImpl;

/**
 * Bundle of resolved features for a manager instance. Built once during
 * `createSessionManager` and shared across requests.
 */
export interface ResolvedFeatures {
  readonly audit?: AuditFeatureImpl;
  readonly csrf?: CsrfFeatureImpl;
  readonly fingerprint?: FingerprintFeatureImpl;
  readonly concurrency?: ConcurrencyFeatureImpl;
}

/**
 * Reduce a public `SessionFeature` (or `false`) to its internal impl by
 * inspecting the discriminator. Returns `undefined` when the input is
 * `undefined` or `false`. The narrowing is safe because every feature
 * factory in this package constructs values of the matching impl shape;
 * external code cannot legally produce a `SessionFeature` without going
 * through one of those factories.
 *
 * @internal
 */
export function resolveFeature<K extends FeatureImpl['__feature']>(
  kind: K,
  value: SessionFeature | false | undefined,
): Extract<FeatureImpl, { __feature: K }> | undefined {
  if (value === undefined || value === false) return undefined;
  if (value.__feature !== kind) return undefined;
  // Safe narrowing: the discriminator was minted by an in-package factory
  // that constructed the matching impl shape.
  return value as Extract<FeatureImpl, { __feature: K }>;
}

/**
 * Hook context passed to internal feature operations. Includes the
 * resolved audit hook so features can emit events without needing the
 * full manager surface.
 *
 * @internal
 */
export interface FeatureContext<T extends SessionData = SessionData> {
  readonly now: () => number;
  readonly emit: (event: AuditEvent) => void;
  readonly store: SessionStore<T>;
  readonly meta: SessionMetadata | null;
  readonly record: SessionRecord<T> | null;
  readonly device: Device | undefined;
}
