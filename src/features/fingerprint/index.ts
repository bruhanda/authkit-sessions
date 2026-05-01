import type { FingerprintFeatureImpl } from '../../core/feature.js';
import type { FingerprintConfig } from '../../types/device.js';
import type { SessionFeature } from '../../types/feature.js';

const DEFAULT_INCLUDE: readonly ('user-agent' | 'accept-language' | 'sec-ch-ua')[] = [
  'user-agent',
  'accept-language',
  'sec-ch-ua',
];

/**
 * Construct a fingerprint feature handle. The session manager hashes the
 * configured request components on `create` and stores the digest in
 * `meta.device.hash`; on every subsequent read the hash is recomputed
 * and compared.
 *
 * Default components (`user-agent`, `accept-language`, `sec-ch-ua`) give
 * roughly 12-16 bits of entropy — enough to distinguish browser/platform
 * combinations without churning on mobile carrier IP roams. Adding
 * `'ip'` raises entropy substantially; pair it with `onMismatch:
 * 'rotate'` to avoid kicking legitimate users.
 *
 * Stored values are HMAC digests, never raw fingerprint inputs — listing
 * a user's active devices via `listByUser` cannot leak their IP or UA.
 *
 * @param config  Optional fingerprint tuning.
 * @returns A `SessionFeature` ready to assign to `SessionConfig.fingerprint`.
 *
 * @example
 *   import { fingerprint } from '@authkit/sessions/fingerprint';
 *   const sessions = createSessionManager({
 *     secrets: [SECRET],
 *     store,
 *     fingerprint: fingerprint({ include: ['user-agent', 'ip'] }),
 *   });
 */
export function fingerprint(config: FingerprintConfig = {}): SessionFeature {
  const impl: FingerprintFeatureImpl = {
    __feature: 'fingerprint',
    include: [...(config.include ?? DEFAULT_INCLUDE)],
    ipExtractor: config.ip,
    onMismatch: config.onMismatch ?? 'rotate',
  };
  return impl;
}
