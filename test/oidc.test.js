import { test, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { boot, resetDb, apiPath, bearer, signupAndAccept, uniqNs } from './helpers.mjs';
import { roundTripProvider, startFakeIdp } from './fake-idp.mjs';

let app;
let idp;

before(async () => {
  idp = await startFakeIdp();
  ({ app } = await boot({
    auth: { oidc: { issuer: idp.issuer, clientId: 'twexthub-test' } },
    rateLimits: { signupsPerIpPerWindow: 10_000 },
  }));
});
beforeEach(async () => {
  await resetDb();
  idp.setClaims({});
});
after(async () => {
  await idp.close();
  await (await boot()).sql.end();
});

// Drive the browser through one full JSON sign-in and return the callback
// response, which is the session for an API client.
async function signIn(claims) {
  idp.setClaims(claims);
  const authorize = await request(app).get(apiPath('/auth/oidc/authorize')).expect(200);
  const { code, state } = await roundTripProvider(authorize.body.authorizationUrl);
  return request(app).get(apiPath('/auth/oidc/callback')).query({ code, state });
}

test('the descriptor advertises the provider and password sign-in', async () => {
  const r = await request(app).get(apiPath('/auth')).expect(200);
  assert.equal(r.body.passwordAuth, true);
  assert.equal(r.body.oidc.issuer, idp.issuer);
  assert.equal(r.body.oidc.required, false);
});

test('a first sign-in creates an admin account and a second reuses it', async () => {
  const first = await signIn({ sub: 'sub-alice', preferred_username: 'alice', name: 'Alice' });
  assert.equal(first.status, 201, JSON.stringify(first.body));
  assert.equal(first.body.user.namespace, 'alice');
  assert.equal(first.body.user.role, 'admin');
  assert.equal(typeof first.body.token, 'string');
  assert.equal(typeof first.body.session.id, 'string');

  const second = await signIn({ sub: 'sub-alice', preferred_username: 'alice', name: 'Alice' });
  assert.equal(second.status, 201);
  assert.equal(second.body.user.namespace, first.body.user.namespace);
  assert.equal(second.body.user.createdAt, first.body.user.createdAt);
});

test('a browser sign-in returns a one-time code that trades for a session', async () => {
  idp.setClaims({ sub: 'sub-bob', preferred_username: 'bob' });
  const authorize = await request(app)
    .get(apiPath('/auth/oidc/authorize'))
    .query({ returnTo: '/welcome' })
    .set('Accept', 'text/html')
    .redirects(0)
    .expect(302);
  const { code, state } = await roundTripProvider(authorize.headers.location);

  const callback = await request(app)
    .get(apiPath('/auth/oidc/callback'))
    .query({ code, state })
    .set('Accept', 'text/html')
    .redirects(0)
    .expect(302);
  const target = new URL(callback.headers.location);
  assert.equal(target.pathname, '/welcome');
  const oidcCode = target.searchParams.get('oidc_code');
  assert.ok(oidcCode);

  const exchange = await request(app)
    .post(apiPath('/auth/oidc/exchange'))
    .send({ code: oidcCode })
    .expect(201);
  assert.equal(exchange.body.user.namespace, 'bob');
  assert.equal(typeof exchange.body.token, 'string');

  // The code is one-time: redeeming it again finds nothing.
  await request(app).post(apiPath('/auth/oidc/exchange')).send({ code: oidcCode }).expect(400);
});

test('an email shared by two subjects does not merge the accounts', async () => {
  const one = await signIn({ sub: 'sub-one', email: 'shared@example.test' });
  const two = await signIn({ sub: 'sub-two', email: 'shared@example.test' });
  assert.notEqual(one.body.user.namespace, two.body.user.namespace);
});

test('a claimed name that cannot be a namespace falls back to a digest', async () => {
  const r = await signIn({ sub: 'sub-weird', preferred_username: '!!!' });
  assert.match(r.body.user.namespace, /^user-[0-9a-f]{12}$/);
});

test('a taken namespace gains a suffix', async () => {
  const first = await signIn({ sub: 'sub-claim-a', preferred_username: 'clash' });
  const second = await signIn({ sub: 'sub-claim-b', preferred_username: 'clash' });
  assert.equal(first.body.user.namespace, 'clash');
  assert.equal(second.body.user.namespace, 'clash-2');
});

test('replaying a state is refused', async () => {
  idp.setClaims({ sub: 'sub-replay' });
  const authorize = await request(app).get(apiPath('/auth/oidc/authorize')).expect(200);
  const { code, state } = await roundTripProvider(authorize.body.authorizationUrl);
  await request(app).get(apiPath('/auth/oidc/callback')).query({ code, state }).expect(201);
  await request(app).get(apiPath('/auth/oidc/callback')).query({ code, state }).expect(400);
});

test('an unknown state is refused', async () => {
  await request(app)
    .get(apiPath('/auth/oidc/callback'))
    .query({ code: 'whatever', state: 'never-issued' })
    .expect(400);
});

test('a returnTo that is not an allowed origin is refused', async () => {
  for (const returnTo of ['https://evil.example/steal', '//evil.example', 'ftp://evil.example']) {
    await request(app).get(apiPath('/auth/oidc/authorize')).query({ returnTo }).expect(422);
  }
});

test('linking an identity lets the account sign in through it', async () => {
  const { user, token } = await signupAndAccept(app, uniqNs());

  idp.setClaims({ sub: 'sub-link', email: 'link@example.test' });
  const link = await request(app)
    .post(apiPath('/auth/oidc/link'))
    .set(bearer(token))
    .send({ returnTo: '/settings' })
    .expect(200);
  const { code, state } = await roundTripProvider(link.body.authorizationUrl);
  const callback = await request(app)
    .get(apiPath('/auth/oidc/callback'))
    .query({ code, state })
    .expect(200);
  assert.equal(callback.body.linked, true);

  const list = await request(app).get(apiPath('/auth/oidc/identities')).set(bearer(token));
  assert.equal(list.status, 200);
  assert.equal(list.body.data.length, 1);
  assert.equal(list.body.data[0].issuer, idp.issuer);
  assert.equal(list.body.data[0].subject, 'sub-link');

  const signedIn = await signIn({ sub: 'sub-link' });
  assert.equal(signedIn.body.user.namespace, user.namespace);
});

test('linking the same identity twice is idempotent for the same account', async () => {
  const { token } = await signupAndAccept(app, uniqNs());
  idp.setClaims({ sub: 'sub-twice' });
  for (let i = 0; i < 2; i += 1) {
    const link = await request(app).post(apiPath('/auth/oidc/link')).set(bearer(token)).send({});
    const { code, state } = await roundTripProvider(link.body.authorizationUrl);
    await request(app).get(apiPath('/auth/oidc/callback')).query({ code, state }).expect(200);
  }
  const list = await request(app)
    .get(apiPath('/auth/oidc/identities'))
    .set(bearer(token))
    .expect(200);
  assert.equal(list.body.data.length, 1);
});

test('an identity already linked to another account cannot be claimed again', async () => {
  const owner = await signIn({ sub: 'sub-owner', preferred_username: 'owner' });
  assert.ok(owner.body.token);

  const { token } = await signupAndAccept(app, uniqNs());
  const link = await request(app).post(apiPath('/auth/oidc/link')).set(bearer(token)).send({});
  const { code, state } = await roundTripProvider(link.body.authorizationUrl);
  const callback = await request(app).get(apiPath('/auth/oidc/callback')).query({ code, state });
  assert.equal(callback.status, 409);
});

test('an account with a password may unlink its only identity', async () => {
  const { token } = await signupAndAccept(app, uniqNs());
  idp.setClaims({ sub: 'sub-unlink' });
  const link = await request(app).post(apiPath('/auth/oidc/link')).set(bearer(token)).send({});
  const { code, state } = await roundTripProvider(link.body.authorizationUrl);
  await request(app).get(apiPath('/auth/oidc/callback')).query({ code, state }).expect(200);

  const list = await request(app)
    .get(apiPath('/auth/oidc/identities'))
    .set(bearer(token))
    .expect(200);
  await request(app)
    .delete(apiPath(`/auth/oidc/identities/${list.body.data[0].id}`))
    .set(bearer(token))
    .expect(204);
  const after = await request(app)
    .get(apiPath('/auth/oidc/identities'))
    .set(bearer(token))
    .expect(200);
  assert.equal(after.body.data.length, 0);
});

test('a passwordless account cannot unlink its only way in', async () => {
  const signedIn = await signIn({ sub: 'sub-solo', preferred_username: 'solo' });
  const token = signedIn.body.token;
  const list = await request(app)
    .get(apiPath('/auth/oidc/identities'))
    .set(bearer(token))
    .expect(200);
  assert.equal(list.body.data.length, 1);
  await request(app)
    .delete(apiPath(`/auth/oidc/identities/${list.body.data[0].id}`))
    .set(bearer(token))
    .expect(409);
});
