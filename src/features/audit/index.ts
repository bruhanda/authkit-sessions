import type { AuditFeatureImpl } from '../../core/feature.js';
import type { AuditEvent, AuditHook } from '../../types/audit.js';
import type { SessionFeature } from '../../types/feature.js';

/**
 * Construct an audit feature handle. The session manager invokes the
 * supplied hook for every lifecycle event (`session.created`,
 * `session.read`, `session.read.failed`, `session.updated`,
 * `session.rotated`, `session.destroyed`, `session.evicted`,
 * `csrf.failed`).
 *
 * Errors thrown inside the hook are caught and swallowed — audit MUST
 * NOT break request flow. Use `composeAuditHook(...hooks)` to fan out to
 * multiple destinations (console, OTel, Sentry).
 *
 * @param hook  Audit hook function.
 * @returns A `SessionFeature` ready to assign to `SessionConfig.audit`.
 *
 * @example
 *   import { audit } from '@authkit/sessions/audit';
 *   const sessions = createSessionManager({
 *     secrets: [SECRET],
 *     store,
 *     audit: audit((event) => log.info(event)),
 *   });
 */
export function audit(hook: AuditHook): SessionFeature {
  const impl: AuditFeatureImpl = { __feature: 'audit', hook };
  return impl;
}

/**
 * Combine N audit hooks into one. Each hook receives every event;
 * exceptions are isolated so one failing destination does not stop the
 * others.
 *
 * @param hooks  Hooks to fan out to. Order is preserved.
 * @returns A single hook that delegates to every input.
 *
 * @example
 *   import { audit, composeAuditHook } from '@authkit/sessions/audit';
 *   const hook = composeAuditHook(
 *     (e) => console.log(e),
 *     (e) => sentry.captureMessage(e.type),
 *   );
 *   const sessions = createSessionManager({ secrets: [SECRET], store, audit: audit(hook) });
 */
export function composeAuditHook(...hooks: readonly AuditHook[]): AuditHook {
  return (event: AuditEvent) => {
    for (const hook of hooks) {
      try {
        const out = hook(event);
        if (out instanceof Promise) {
          out.catch(() => {
            // Per-hook isolation.
          });
        }
      } catch {
        // Per-hook isolation.
      }
    }
  };
}

/**
 * Default JSON formatter. Stringifies the event with a trailing newline,
 * suitable for piping into a structured-log destination.
 *
 * @param event  Audit event.
 * @returns JSON line.
 *
 * @example
 *   const hook: AuditHook = (e) => process.stdout.write(formatAuditEventJson(e));
 */
export function formatAuditEventJson(event: AuditEvent): string {
  return `${JSON.stringify(event)}\n`;
}
