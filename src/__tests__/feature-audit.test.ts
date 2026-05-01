import { describe, expect, it, vi } from 'vitest';
import { audit, composeAuditHook, formatAuditEventJson } from '../features/audit/index.js';
import type { AuditEvent } from '../types/audit.js';

const sampleEvent: AuditEvent = { type: 'session.read', sessionId: 'a'.repeat(43), at: 1 };

describe('audit factory', () => {
  it('should wrap a hook into a feature handle', () => {
    const hook = vi.fn();
    const f = audit(hook) as { __feature: string; hook: typeof hook };
    expect(f.__feature).toBe('audit');
    expect(f.hook).toBe(hook);
  });
});

describe('composeAuditHook', () => {
  it('should fan out to every supplied hook', () => {
    const a = vi.fn();
    const b = vi.fn();
    const composed = composeAuditHook(a, b);
    composed(sampleEvent);
    expect(a).toHaveBeenCalledWith(sampleEvent);
    expect(b).toHaveBeenCalledWith(sampleEvent);
  });

  it('should isolate exceptions between hooks', () => {
    const broken = vi.fn(() => {
      throw new Error('boom');
    });
    const ok = vi.fn();
    const composed = composeAuditHook(broken, ok);
    expect(() => composed(sampleEvent)).not.toThrow();
    expect(broken).toHaveBeenCalled();
    expect(ok).toHaveBeenCalled();
  });

  it('should swallow rejected promises from async hooks', async () => {
    const broken = vi.fn(async () => {
      throw new Error('async boom');
    });
    const composed = composeAuditHook(broken);
    expect(() => composed(sampleEvent)).not.toThrow();
    await new Promise((r) => setTimeout(r, 5));
    expect(broken).toHaveBeenCalled();
  });

  it('should run hooks in supplied order', () => {
    const calls: string[] = [];
    const composed = composeAuditHook(
      () => calls.push('a'),
      () => calls.push('b'),
    );
    composed(sampleEvent);
    expect(calls).toEqual(['a', 'b']);
  });

  it('should still return a hook even when given no inputs', () => {
    const h = composeAuditHook();
    expect(() => h(sampleEvent)).not.toThrow();
  });
});

describe('formatAuditEventJson', () => {
  it('should render a JSON line with a trailing newline', () => {
    const out = formatAuditEventJson(sampleEvent);
    expect(out.endsWith('\n')).toBe(true);
    expect(out.trim()).toBe(JSON.stringify(sampleEvent));
  });
});
