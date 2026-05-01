import { sign } from '../crypto/hmac.js';
import {
  coerceSecret,
  deriveFingerprintKey,
  deriveSigKey,
  validateSecret,
} from '../crypto/kdf.js';
import { timingSafeEqualString } from '../crypto/timing.js';
import { SessionError } from '../errors/base.js';
import type { AuditEvent } from '../types/audit.js';
import type { SessionConfig } from '../types/config.js';
import type { Device } from '../types/device.js';
import type { SessionAttachment, SessionManager } from '../types/manager.js';
import type { SessionData, SessionRecord } from '../types/session.js';
import { base64urlEncode } from '../utils/base64url.js';
import { deepFreeze } from '../utils/freeze.js';
import { invariant } from '../utils/invariant.js';
import { DEFAULT_COOKIE_OPTIONS, prefixedName, serializeCookie } from './cookie.js';
import {
  cookieMaxAge,
  evaluate,
  extendExpiry,
  resolveExpiration,
} from './expiration.js';
import {
  type ResolvedFeatures,
  resolveFeature,
} from './feature.js';
import { appendSetCookie, extractCookie } from './headers.js';
import { generateCsrfToken, generateSessionId } from './id.js';
import {
  mintMetadata,
  persistWithRetry,
  signSessionId,
  verifySessionId,
} from './lifecycle.js';
import { nowSeconds } from './time.js';

const DEFAULT_COOKIE_NAME = 'sid';

/**
 * Construct a session manager bound to a single config. The returned
 * handle is frozen and safe to share across requests in the same runtime
 * instance.
 *
 * @typeParam T  Shape of the session payload. Defaults to
 *               `Record<string, unknown>` but is intended to be supplied
 *               by the caller so handlers receive a fully typed
 *               `record.data` (no manual casts).
 *
 * @param config  Resolved configuration. `secrets` and `store` are
 *                required; everything else has a documented default.
 * @returns A frozen `SessionManager<T>`.
 * @throws {SessionError} `SECRET_TOO_SHORT` when any secret carries
 *                        <256 bits of entropy; `CONFIG_INVALID` for
 *                        any other validation failure.
 *
 * @example
 *   import { createSessionManager } from '@authkit/sessions';
 *   import { createRedisStore } from '@authkit/sessions/adapters/redis';
 *   import { csrf } from '@authkit/sessions/csrf';
 *
 *   const sessions = createSessionManager<{ userId: string }>({
 *     secrets: [process.env.SESSION_SECRET!],
 *     store: createRedisStore(redis),
 *     getUserId: (data) => data.userId,
 *     csrf: csrf({ enforceOrigin: true }),
 *   });
 */
export function createSessionManager<T extends SessionData = SessionData>(
  config: SessionConfig<T>,
): SessionManager<T> {
  invariant(config.secrets !== undefined, 'CONFIG_INVALID', 'secrets is required');
  invariant(config.store !== undefined, 'CONFIG_INVALID', 'store is required');

  const secretsArray: readonly (string | Uint8Array)[] =
    typeof config.secrets === 'string' || config.secrets instanceof Uint8Array
      ? [config.secrets]
      : config.secrets;
  const secretBytes = secretsArray.map((s) => {
    const bytes = coerceSecret(s);
    validateSecret(bytes);
    return bytes;
  });
  const [activeSecret, ...otherSecrets] = secretBytes;
  invariant(
    activeSecret !== undefined,
    'CONFIG_INVALID',
    'at least one secret is required',
  );

  const sigKeys: readonly Uint8Array[] = [
    deriveSigKey(activeSecret),
    ...otherSecrets.map((s) => deriveSigKey(s)),
  ];
  const activeSigKey = sigKeys[0] ?? deriveSigKey(activeSecret);
  const fingerprintKey = deriveFingerprintKey(activeSecret);

  const expiration = resolveExpiration(config.expiration);
  const cookieOptions = { ...DEFAULT_COOKIE_OPTIONS, ...(config.cookie ?? {}) };
  const cookieName = config.cookieName ?? DEFAULT_COOKIE_NAME;
  const effectiveCookieName = prefixedName(cookieName, cookieOptions);
  const clock = config.clock ?? nowSeconds;
  const store = config.store;
  const getUserId = config.getUserId;

  const auditFeature = resolveFeature('audit', config.audit);
  const csrfFeature = resolveFeature('csrf', config.csrf);
  const fingerprintFeature = resolveFeature('fingerprint', config.fingerprint);
  const concurrencyFeature = resolveFeature('concurrency', config.concurrency);

  const features: ResolvedFeatures = {
    ...(auditFeature ? { audit: auditFeature } : {}),
    ...(csrfFeature ? { csrf: csrfFeature } : {}),
    ...(fingerprintFeature ? { fingerprint: fingerprintFeature } : {}),
    ...(concurrencyFeature ? { concurrency: concurrencyFeature } : {}),
  };

  const emit = (event: AuditEvent): void => {
    const hook = features.audit?.hook;
    if (!hook) return;
    try {
      const out = hook(event);
      if (out instanceof Promise) {
        out.catch(() => {
          // Audit must not break request flow.
        });
      }
    } catch {
      // Audit must not break request flow.
    }
  };

  const computeDevice = (req: Request, prior?: Device): Device | undefined => {
    if (!fingerprintFeature) return undefined;
    const enc = new TextEncoder();
    const parts: string[] = [];
    let userAgent: string | undefined;
    let platform: string | undefined;
    let ipHash: string | undefined;
    for (const component of fingerprintFeature.include) {
      if (component === 'user-agent') {
        const ua = req.headers.get('user-agent') ?? '';
        userAgent = ua || undefined;
        parts.push(`ua:${ua}`);
      } else if (component === 'accept-language') {
        parts.push(`al:${req.headers.get('accept-language') ?? ''}`);
      } else if (component === 'sec-ch-ua') {
        const ch = req.headers.get('sec-ch-ua') ?? '';
        platform = req.headers.get('sec-ch-ua-platform') ?? undefined;
        parts.push(`ch:${ch}`);
      } else if (component === 'ip') {
        const raw = fingerprintFeature.ipExtractor?.(req) ?? defaultIpExtractor(req);
        if (raw !== undefined) {
          ipHash = base64urlEncode(sign(fingerprintKey, enc.encode(raw))).slice(0, 22);
          parts.push(`ip:${ipHash}`);
        }
      }
    }
    const hash = base64urlEncode(sign(fingerprintKey, enc.encode(parts.join('|')))).slice(0, 22);
    const now = clock();
    return {
      hash,
      ...(userAgent !== undefined ? { userAgent } : {}),
      ...(platform !== undefined ? { platform } : {}),
      ...(ipHash !== undefined ? { ip: ipHash } : {}),
      firstSeenAt: prior?.firstSeenAt ?? now,
      lastSeenAt: now,
    };
  };

  const codec = store.__codec;

  const buildCookieValue = (record: SessionRecord<T>): string =>
    codec ? codec.encode(record) : signSessionId(record.meta.id, activeSigKey);

  const buildAttachment = (
    record: SessionRecord<T>,
    cookieValue: string,
    maxAge: number,
  ): SessionAttachment<T> => {
    const headerLine = serializeCookie(cookieName, cookieValue, maxAge, cookieOptions);
    const headers = new Headers();
    appendSetCookie(headers, headerLine);
    if (csrfFeature) {
      const csrfHeader = serializeCookie(
        csrfFeature.cookieName,
        record.meta.csrf,
        maxAge,
        { ...cookieOptions, httpOnly: false },
      );
      appendSetCookie(headers, csrfHeader);
    }
    return {
      record,
      cookie: headerLine,
      headers,
      attachTo: makeAttachTo(headers),
    };
  };

  const readActive = async (req: Request): Promise<SessionRecord<T> | null> => {
    const cookieValue = extractCookie(req, effectiveCookieName);
    if (!cookieValue) return null;

    let record: SessionRecord<T> | null;
    if (codec) {
      record = codec.decode(cookieValue);
      if (!record) {
        emit({ type: 'session.read.failed', reason: 'INVALID_COOKIE', at: clock() });
        return null;
      }
    } else {
      const id = verifySessionId(cookieValue, sigKeys);
      if (!id) {
        emit({ type: 'session.read.failed', reason: 'INVALID_SIGNATURE', at: clock() });
        return null;
      }
      try {
        record = await store.read(id);
      } catch (err) {
        if (SessionError.is(err)) throw err;
        throw new SessionError('STORE_UNAVAILABLE', 'store.read failed', err);
      }
      if (!record) return null;
    }

    const now = clock();
    const outcome = evaluate(record.meta, now, expiration);
    if (outcome.state === 'expired') {
      emit({ type: 'session.read.failed', reason: 'EXPIRED', at: now });
      await store.delete(record.meta.id).catch(() => undefined);
      return null;
    }

    if (fingerprintFeature && record.meta.device) {
      const current = computeDevice(req, record.meta.device);
      if (current && current.hash !== record.meta.device.hash) {
        if (fingerprintFeature.onMismatch === 'destroy') {
          await store.delete(record.meta.id).catch(() => undefined);
          emit({
            type: 'session.destroyed',
            sessionId: record.meta.id,
            reason: 'fingerprint-mismatch',
            at: now,
          });
          emit({ type: 'session.read.failed', reason: 'FINGERPRINT_MISMATCH', at: now });
          return null;
        }
        // 'rotate' / 'ignore' — keep the session alive on read; rotate
        // happens on the next mutation.
      }
    }

    if (outcome.touch) {
      const updated: SessionRecord<T> = {
        meta: {
          ...record.meta,
          lastSeenAt: now,
          expiresAt: extendExpiry(record.meta, now, expiration),
        },
        data: record.data,
      };
      await store.update(updated).catch(() => undefined);
      record = updated;
    }

    emit({ type: 'session.read', sessionId: record.meta.id, at: now });
    return record;
  };

  const enforceConcurrency = async (
    record: SessionRecord<T>,
    userId: string,
  ): Promise<void> => {
    if (!concurrencyFeature) return;
    const existing = await store.listByUser(userId);
    if (existing.length < concurrencyFeature.max) return;

    if (concurrencyFeature.strategy === 'deny-new') {
      throw new SessionError(
        'CONCURRENCY_DENIED',
        `concurrent session limit reached (max=${concurrencyFeature.max})`,
      );
    }

    const overflow = existing.length - concurrencyFeature.max + 1;
    const sorted = [...existing];
    if (concurrencyFeature.strategy === 'lru') {
      sorted.sort((a, b) => a.lastSeenAt - b.lastSeenAt);
    } else {
      sorted.sort((a, b) => a.createdAt - b.createdAt);
    }
    for (let i = 0; i < overflow; i++) {
      const victim = sorted[i];
      if (!victim || victim.id === record.meta.id) continue;
      await store.delete(victim.id).catch(() => undefined);
      emit({
        type: 'session.evicted',
        sessionId: victim.id,
        userId,
        strategy: concurrencyFeature.strategy,
        at: clock(),
      });
    }
  };

  const manager: SessionManager<T> = {
    async get(req) {
      return readActive(req);
    },

    async create(req, data, opts) {
      const now = clock();
      const userId = getUserId?.(data);
      const baseDevice = computeDevice(req);
      const device =
        baseDevice && opts?.device ? { ...baseDevice, ...opts.device } : baseDevice;
      const meta = mintMetadata(
        now,
        expiration.absoluteSeconds,
        expiration.slidingSeconds,
        userId,
        device,
      );
      const record: SessionRecord<T> = { meta, data };
      if (userId !== undefined) await enforceConcurrency(record, userId);
      const persisted = await persistWithRetry(store, record, () => ({
        meta: mintMetadata(
          now,
          expiration.absoluteSeconds,
          expiration.slidingSeconds,
          userId,
          device,
        ),
        data,
      }));
      emit({
        type: 'session.created',
        sessionId: persisted.meta.id,
        ...(userId !== undefined ? { userId } : {}),
        ...(device !== undefined ? { device } : {}),
        at: now,
      });
      return buildAttachment(
        persisted,
        buildCookieValue(persisted),
        cookieMaxAge(persisted.meta, now),
      );
    },

    async update(req, mutator) {
      const record = await readActive(req);
      if (!record) throw new SessionError('NOT_FOUND', 'no active session to update');
      const nextData = await mutator(record.data);
      const now = clock();
      const userId = getUserId?.(nextData);
      const updated: SessionRecord<T> = {
        meta: {
          ...record.meta,
          ...(userId !== undefined ? { userId } : {}),
          lastSeenAt: now,
          expiresAt: extendExpiry(record.meta, now, expiration),
        },
        data: nextData,
      };
      const ok = await store.update(updated);
      if (!ok) throw new SessionError('CONFLICT', 'store rejected update');
      emit({ type: 'session.updated', sessionId: updated.meta.id, at: now });
      return buildAttachment(
        updated,
        buildCookieValue(updated),
        cookieMaxAge(updated.meta, now),
      );
    },

    async rotate(req) {
      const record = await readActive(req);
      if (!record) throw new SessionError('NOT_FOUND', 'no active session to rotate');
      const now = clock();
      const newId = generateSessionId();
      const newCsrf = generateCsrfToken();
      const rotated: SessionRecord<T> = {
        meta: {
          ...record.meta,
          id: newId,
          csrf: newCsrf,
          lastSeenAt: now,
          expiresAt: extendExpiry(record.meta, now, expiration),
        },
        data: record.data,
      };
      await store.create(rotated);
      await store.delete(record.meta.id).catch(() => undefined);
      emit({ type: 'session.rotated', oldId: record.meta.id, newId, at: now });
      return buildAttachment(
        rotated,
        buildCookieValue(rotated),
        cookieMaxAge(rotated.meta, now),
      );
    },

    async signOut(req) {
      const cookieValue = extractCookie(req, effectiveCookieName);
      let id: string | null = null;
      if (cookieValue) {
        if (codec) {
          id = codec.decode(cookieValue)?.meta.id ?? null;
        } else {
          id = verifySessionId(cookieValue, sigKeys);
        }
      }
      if (id) {
        await store.delete(id).catch(() => undefined);
        emit({ type: 'session.destroyed', sessionId: id, reason: 'logout', at: clock() });
      }
      const headers = new Headers();
      const expiringCookie = serializeCookie(cookieName, '', 0, cookieOptions);
      appendSetCookie(headers, expiringCookie);
      if (csrfFeature) {
        appendSetCookie(
          headers,
          serializeCookie(csrfFeature.cookieName, '', 0, {
            ...cookieOptions,
            httpOnly: false,
          }),
        );
      }
      return {
        record: null,
        cookie: expiringCookie,
        headers,
        attachTo: makeAttachTo(headers),
      };
    },

    async revokeBySessionId(id) {
      const ok = await store.delete(id);
      if (ok) {
        emit({ type: 'session.destroyed', sessionId: id, reason: 'manual', at: clock() });
      }
      return ok;
    },

    async revokeByUser(userId) {
      return store.deleteByUser(userId);
    },

    async listByUser(userId) {
      return store.listByUser(userId);
    },

    async verifyCsrf(req, token) {
      const record = await readActive(req);
      const now = clock();
      if (!record) {
        emit({ type: 'csrf.failed', reason: 'no-session', at: now });
        return false;
      }
      if (!token) {
        emit({ type: 'csrf.failed', reason: 'missing', at: now });
        return false;
      }
      if (!timingSafeEqualString(record.meta.csrf, token)) {
        emit({ type: 'csrf.failed', reason: 'mismatch', at: now });
        return false;
      }
      return true;
    },

    async getCsrfToken(req) {
      const record = await readActive(req);
      return record?.meta.csrf ?? null;
    },
  };

  return deepFreeze(manager);
}

/**
 * Build the `attachTo` helper that copies `Set-Cookie` entries from one
 * `Headers` into another without clobbering existing entries.
 *
 * @internal
 */
function makeAttachTo(source: Headers): (target: Headers) => Headers {
  return (target) => {
    for (const [k, v] of source.entries()) {
      if (k.toLowerCase() === 'set-cookie') target.append('Set-Cookie', v);
    }
    return target;
  };
}

/**
 * Default IP extractor — picks the first hop in `X-Forwarded-For`,
 * falling back to `CF-Connecting-IP` (Cloudflare) and `True-Client-IP`
 * (Akamai). Returns `undefined` when no proxy header is present.
 *
 * @param req  Standard `Request`.
 * @returns IP string, or `undefined` when no proxy header is present.
 *
 * @example
 *   const ip = defaultIpExtractor(req);
 */
export function defaultIpExtractor(req: Request): string | undefined {
  const xff = req.headers.get('x-forwarded-for');
  if (xff) {
    const first = xff.split(',')[0]?.trim();
    if (first) return first;
  }
  return (
    req.headers.get('cf-connecting-ip') ??
    req.headers.get('true-client-ip') ??
    undefined
  );
}
