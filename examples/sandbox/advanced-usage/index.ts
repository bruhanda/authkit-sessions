/**
 * advanced-usage.ts — production-shaped scenario.
 *
 * Demonstrates every opt-in feature working together:
 *   - typed payload + getUserId
 *   - device fingerprinting (HMAC-hashed components)
 *   - concurrent session limits with LRU eviction (Netflix-style)
 *   - audit hook fed by composeAuditHook
 *   - CSRF (double-submit cookie + Origin enforcement)
 *   - rotate after privilege change
 *   - revokeBySessionId / listByUser ("active devices" UI)
 *
 *   npm install
 *   npm start
 */
import { createSessionManager, SessionError } from '@authkit/sessions';
import { createMemoryStore } from '@authkit/sessions/adapters/memory';
import { audit, composeAuditHook, formatAuditEventJson } from '@authkit/sessions/audit';
import { concurrency } from '@authkit/sessions/concurrency';
import { csrf } from '@authkit/sessions/csrf';
import { fingerprint } from '@authkit/sessions/fingerprint';

type AppSession = {
  userId: string;
  role: 'user' | 'admin';
  preferences: { theme: 'light' | 'dark' };
};

const SECRET = 'b'.repeat(32);

// Audit hook — fans out to two destinations: a JSON line writer (stdout)
// and an in-memory tally so the demo can assert on what fired.
const tally = new Map<string, number>();
const sessions = createSessionManager<AppSession>({
  secrets: [SECRET],
  store: createMemoryStore<AppSession>(),
  getUserId: (data) => data.userId,
  cookie: { secure: false },
  csrf: csrf({ enforceOrigin: true }),
  fingerprint: fingerprint({
    include: ['user-agent', 'accept-language'],
    onMismatch: 'rotate',
  }),
  concurrency: concurrency({ max: 3, strategy: 'lru' }),
  audit: audit(
    composeAuditHook(
      (e) => process.stdout.write(`[audit] ${formatAuditEventJson(e)}`),
      (e) => tally.set(e.type, (tally.get(e.type) ?? 0) + 1),
    ),
  ),
});

function carry(...attachments: { cookie: string }[]): string {
  const parts: string[] = [];
  for (const a of attachments) {
    const eq = a.cookie.indexOf('=');
    const semi = a.cookie.indexOf(';');
    const name = a.cookie.slice(0, eq);
    const value = a.cookie.slice(eq + 1, semi === -1 ? undefined : semi);
    parts.push(`${name}=${value}`);
  }
  return parts.join('; ');
}

function deviceRequest(label: string, init: { method?: string; cookie?: string } = {}): Request {
  const headers: Record<string, string> = {
    'user-agent': `MyApp/1.0 ${label}`,
    'accept-language': 'en-US',
    origin: 'https://app.example.com',
    host: 'app.example.com',
  };
  if (init.cookie) headers.cookie = init.cookie;
  return new Request('https://app.example.com/api/x', { method: init.method, headers });
}

async function main() {
  console.log('--- 1. Concurrency (max=3, lru): create 4 sessions, oldest is evicted ---');
  const a = await sessions.create(deviceRequest('phone'), { userId: 'u1', role: 'user', preferences: { theme: 'light' } });
  const b = await sessions.create(deviceRequest('laptop'), { userId: 'u1', role: 'user', preferences: { theme: 'light' } });
  const c = await sessions.create(deviceRequest('tablet'), { userId: 'u1', role: 'user', preferences: { theme: 'light' } });

  // Touch `b` so `a` becomes the LRU victim.
  await sessions.get(deviceRequest('laptop', { cookie: carry(b) }));

  const d = await sessions.create(deviceRequest('desktop'), { userId: 'u1', role: 'user', preferences: { theme: 'light' } });

  const active = await sessions.listByUser('u1');
  console.log(`   active sessions for u1: ${active.length} (expected 3)`);
  console.log(`   evicted '${a.record.meta.id.slice(0, 8)}…' (LRU)? ${active.every((m) => m.id !== a.record.meta.id)}`);

  console.log('\n--- 2. Rotate after privilege change (e.g. role bump) ---');
  const promoted = await sessions.update(
    deviceRequest('laptop', { cookie: carry(b) }),
    (data) => ({ ...data, role: 'admin' as const }),
  );
  console.log(`   role:        ${promoted.record.data.role}`);
  // Real-world: call rotate() right after a privilege change to swap the id
  // (defence-in-depth against fixation).
  const rotated = await sessions.rotate(
    deviceRequest('laptop', { cookie: carry(promoted) }),
  );
  console.log(`   id rotated:  ${rotated.record.meta.id !== promoted.record.meta.id}`);
  console.log(`   csrf rotated:${rotated.record.meta.csrf !== promoted.record.meta.csrf}`);

  console.log('\n--- 3. CSRF — double-submit cookie ---');
  const token = await sessions.getCsrfToken(
    deviceRequest('laptop', { cookie: carry(rotated) }),
  );
  console.log(`   token (server-side):  ${token?.slice(0, 16)}…`);
  const okPost = await sessions.verifyCsrf(
    deviceRequest('laptop', { method: 'POST', cookie: carry(rotated) }),
    token ?? '',
  );
  const badPost = await sessions.verifyCsrf(
    deviceRequest('laptop', { method: 'POST', cookie: carry(rotated) }),
    'forged-token',
  );
  console.log(`   verify(token):        ${okPost}`);
  console.log(`   verify('forged…'):    ${badPost}`);

  console.log('\n--- 4. Device fingerprint mismatch — rotate, do not destroy ---');
  // Same cookie, different UA. With onMismatch='rotate' the session
  // survives but is flagged for rotation on the next mutation.
  const wrongDevice = new Request('https://app.example.com/api/x', {
    headers: {
      cookie: carry(rotated),
      'user-agent': 'AttackerBrowser/9.9',
      'accept-language': 'fr-FR',
    },
  });
  const survived = await sessions.get(wrongDevice);
  console.log(`   read with wrong UA:   ${survived ? 'session preserved' : 'session destroyed'}`);

  console.log('\n--- 5. listByUser ("active devices" UI) ---');
  const list = await sessions.listByUser('u1');
  for (const meta of list) {
    console.log(
      `   id=${meta.id.slice(0, 8)}… ua=${meta.device?.userAgent ?? '?'} lastSeen=${new Date(meta.lastSeenAt * 1000).toISOString()}`,
    );
  }

  console.log('\n--- 6. revokeByUser (log out everywhere) ---');
  const removed = await sessions.revokeByUser('u1');
  console.log(`   revoked: ${removed} sessions`);

  console.log('\n--- 7. Concurrency in deny-new mode ---');
  const denyMgr = createSessionManager<{ userId: string }>({
    secrets: [SECRET],
    store: createMemoryStore(),
    getUserId: (d) => d.userId,
    cookie: { secure: false },
    concurrency: concurrency({ max: 1, strategy: 'deny-new' }),
  });
  await denyMgr.create(new Request('https://x.test/'), { userId: 'u2' });
  try {
    await denyMgr.create(new Request('https://x.test/'), { userId: 'u2' });
  } catch (err) {
    if (SessionError.is(err) && err.code === 'CONCURRENCY_DENIED') {
      console.log(`   second create rejected: ${err.code}`);
    } else throw err;
  }

  console.log('\n--- audit tally ---');
  for (const [k, v] of [...tally.entries()].sort()) {
    console.log(`   ${k.padEnd(28)} ${v}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
