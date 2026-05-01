/**
 * basic-usage.ts — minimal core functionality.
 *
 * Walks through the four paths every consumer needs: create, read,
 * update, sign out. Uses the in-memory store so it runs anywhere with
 * zero infrastructure.
 *
 *   npx tsx examples/basic-usage.ts
 */
import { createSessionManager, SessionError } from '@authkit/sessions';
import { createMemoryStore } from '@authkit/sessions/adapters/memory';

type AppSession = {
  userId: string;
  role: 'user' | 'admin';
  visits: number;
};

const SECRET = 'a'.repeat(32); // 32 bytes — minimum entropy for a real deployment.

const sessions = createSessionManager<AppSession>({
  secrets: [SECRET],
  store: createMemoryStore<AppSession>(),
  getUserId: (data) => data.userId,
  cookie: {
    secure: false, // set to true in production behind HTTPS
  },
});

/**
 * Tiny helper to chain requests in a script: pull the session cookie out
 * of an attachment and put it on the next inbound `Request`. Browsers do
 * this for free; for a CLI demo we wire it ourselves.
 */
function carryCookies(setCookie: string): Headers {
  const inbound = new Headers();
  const eq = setCookie.indexOf('=');
  const semi = setCookie.indexOf(';');
  const name = setCookie.slice(0, eq);
  const value = setCookie.slice(eq + 1, semi === -1 ? undefined : semi);
  inbound.set('cookie', `${name}=${value}`);
  return inbound;
}

async function main() {
  // 1. Create a session for a freshly logged-in user.
  const loginReq = new Request('https://example.com/login', { method: 'POST' });
  const created = await sessions.create(loginReq, {
    userId: 'user_42',
    role: 'user',
    visits: 1,
  });

  console.log('1. Created');
  console.log('   id:        ', created.record.meta.id.slice(0, 12), '…');
  console.log('   csrf:      ', created.record.meta.csrf.slice(0, 12), '…');
  console.log('   set-cookie:', created.cookie.split(';')[0]);

  // 2. Read the session on a follow-up request — the typed payload flows
  //    through end-to-end with no casts.
  const meReq = new Request('https://example.com/me', {
    headers: carryCookies(created.cookie),
  });
  const me = await sessions.get(meReq);
  if (!me) throw new Error('expected an active session');

  console.log('\n2. Read');
  console.log('   userId:', me.data.userId);
  console.log('   role:  ', me.data.role); // 'user' | 'admin' — no cast
  console.log('   visits:', me.data.visits);

  // 3. Update — the mutator receives the typed payload and returns the next.
  const updateReq = new Request('https://example.com/visit', {
    method: 'POST',
    headers: carryCookies(created.cookie),
  });
  const updated = await sessions.update(updateReq, (data) => ({
    ...data,
    visits: data.visits + 1,
  }));
  console.log('\n3. Updated');
  console.log('   visits now:', updated.record.data.visits);

  // 4. Update under the wrong cookie — read paths never throw, they just
  //    return null. Mutating paths throw `SessionError('NOT_FOUND')`.
  try {
    const bogus = new Request('https://example.com/x', {
      headers: { cookie: 'sid=not.a.real.signed.id' },
    });
    await sessions.update(bogus, (d) => d);
  } catch (err) {
    if (SessionError.is(err)) {
      console.log('\n4. Mutating without a session throws');
      console.log('   code:   ', err.code);
      console.log('   message:', err.publicMessage);
    } else {
      throw err;
    }
  }

  // 5. Sign out — emits an expiring Set-Cookie so the browser drops it.
  const logoutReq = new Request('https://example.com/logout', {
    method: 'POST',
    headers: carryCookies(updated.cookie),
  });
  await sessions.signOut(logoutReq);

  const after = await sessions.get(
    new Request('https://example.com/me', { headers: carryCookies(updated.cookie) }),
  );
  console.log('\n5. Signed out');
  console.log('   session after logout:', after);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
