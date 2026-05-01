/**
 * Opaque feature handle. The user constructs one by calling `csrf({...})` /
 * `fingerprint({...})` / `concurrency({...})` / `audit({...})` imported
 * from the matching subpath. The internal shape (lifecycle hooks) is
 * intentionally private; the manager invokes hooks during request
 * processing.
 */
export interface SessionFeature {
  readonly __feature: 'csrf' | 'fingerprint' | 'concurrency' | 'audit';
}
