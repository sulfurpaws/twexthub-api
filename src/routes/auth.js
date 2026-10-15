import { createHash, randomBytes } from 'node:crypto';
import { Router } from 'express';
import { hashToken, requireSession } from '../auth.js';
import { makeOidcClient, newSecret, oidcEnabled, OidcError } from '../oidc.js';
import { conflict, fieldErrors, HttpError, notFound } from '../errors.js';
import { isValidNamespace, normalizeApiRoot } from '../util.js';
import { sessionToObject, userToObject } from '../serialize.js';
import { createSession, requireObjectBody } from './shared.js';
import { audit } from '../audit.js';

// How long a sign-in may sit between the authorize redirect and the callback,
// and how long the browser then has to redeem its one-time code for the
// session. The first is generous because it includes typing a password at the
// provider; the second only has to cover a redirect and one request.
const FLOW_TTL_MS = 10 * 60_000;
const EXCHANGE_TTL_MS = 5 * 60_000;

export function makeAuthRouter({ sql, config, rateLimiter }) {
  const root = normalizeApiRoot(config.apiRoot);
  const mount = (path) => `${root ? `/${root}` : ''}${path}`;
  const router = Router();
  const oidc = config.auth.oidc;
  const enabled = oidcEnabled(config);
  const client = enabled ? makeOidcClient(config) : null;
  const sessionTtlMs = config.auth.sessionTtlDays * 86_400_000;

  // The flow is bound to the browser that started it by a secret in a cookie:
  // the callback has to present the same secret, so a callback minted in one
  // browser cannot be replayed into another. `Secure` only when the instance
  // is actually served over TLS, for the same reason the instance allows plain
  // HTTP at all.
  const flowCookie = 'twexthub_oidc_flow';
  const flowCookieOptions = {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.publicBaseUrl.startsWith('https:'),
    path: mount('/auth'),
    maxAge: FLOW_TTL_MS,
  };
  const setFlowCookie = (res, secret) => res.cookie(flowCookie, secret, flowCookieOptions);
  const clearFlowCookie = (res) => res.clearCookie(flowCookie, flowCookieOptions);

  // What a sign-in page needs to render: whether password sign-in is offered,
  // and where the button for the provider should lead. Public, because it is
  // read before anybody has signed in.
  router.get('/', (req, res) => {
    res.json({
      passwordAuth: !oidc.required,
      oidc: enabled ? { issuer: oidc.issuer, required: Boolean(oidc.required) } : null,
    });
  });

  // The browser leaves here for the provider, and the provider sends it back
  // to the callback. The flow row is what makes the return trip trustworthy:
  // it holds the state the callback has to see again, the PKCE verifier the
  // code can only be redeemed with, and the nonce the ID token must contain.
  router.get('/oidc/authorize', async (req, res) => {
    if (!enabled) throw notFound();
    const returnTo = returnToPath(req.query.returnTo, config);
    const state = newSecret();
    const verifier = newSecret();
    const nonce = newSecret();
    const binding = newSecret();
    const authorizationUrl = await client.authorizationUrl({ state, nonce, verifier });

    await sql`DELETE FROM oidc_flows WHERE expires_at < now()`;
    await sql`
      INSERT INTO oidc_flows (kind, state_hash, flow_secret_hash, code_verifier, nonce, return_to, expires_at)
      VALUES ('signin', ${hashToken(state)}, ${hashToken(binding)}, ${verifier}, ${nonce}, ${returnTo}, ${new Date(Date.now() + FLOW_TTL_MS)})
    `;
    setFlowCookie(res, binding);

    if (wantsHtml(req)) return res.redirect(authorizationUrl);
    res.json({ authorizationUrl });
  });

  router.get('/oidc/callback', async (req, res) => {
    if (!enabled) throw notFound();
    const { state, code, error: providerError } = req.query;
    if (typeof state !== 'string' || state === '') {
      return failFlow(
        req,
        res,
        null,
        400,
        'state_invalid',
        'The callback is missing its state parameter.',
      );
    }

    // Claiming the row and consuming its state are the same write: the guard
    // on exchange_code_hash means only the first callback through matches, so
    // a replayed state finds nothing. The cookie binding is checked in the
    // same statement, so a callback carrying another browser's state does not
    // complete a sign-in for this one.
    const exchangeCode = newSecret();
    const binding = readCookie(req, flowCookie);
    const [flow] = await sql`
      UPDATE oidc_flows
      SET exchange_code_hash = ${hashToken(exchangeCode)}
      WHERE state_hash = ${hashToken(state)}
        AND flow_secret_hash = ${hashToken(binding ?? '')}
        AND exchange_code_hash IS NULL AND expires_at > now()
      RETURNING *
    `;
    if (!flow) {
      return failFlow(
        req,
        res,
        null,
        400,
        'state_invalid',
        'The sign-in attempt is unknown or has expired.',
      );
    }
    clearFlowCookie(res);

    if (typeof providerError === 'string' && providerError !== '') {
      return failFlow(
        req,
        res,
        flow,
        502,
        'provider_error',
        `The provider refused the sign-in (${providerError.slice(0, 64)}).`,
      );
    }
    if (typeof code !== 'string' || code === '') {
      return failFlow(
        req,
        res,
        flow,
        400,
        'provider_error',
        'The callback is missing its code parameter.',
      );
    }

    let claims;
    try {
      claims = await client.redeemCode({ code, verifier: flow.code_verifier, nonce: flow.nonce });
    } catch (error) {
      if (error instanceof OidcError) {
        return failFlow(req, res, flow, error.status, error.slug, error.detail);
      }
      throw error;
    }
    const issuer = claims.iss;
    const subject = claims.sub;

    if (flow.kind === 'link') {
      return finishLink(req, res, flow, { issuer, subject, claims });
    }
    return finishSignin(req, res, flow, exchangeCode, { issuer, subject, claims });
  });

  // The token is handed to the client exactly once, in exchange for the code
  // it was redirected with, so an Authorization header reaches the browser
  // script without the session token ever appearing in a URL.
  router.post('/oidc/exchange', async (req, res) => {
    if (!enabled) throw notFound();
    requireObjectBody(req);
    const { code } = req.body;
    if (typeof code !== 'string' || code === '') {
      throw fieldErrors([{ field: 'code', message: 'A code is required.' }]);
    }
    const [flow] = await sql`
      DELETE FROM oidc_flows
      WHERE exchange_code_hash = ${hashToken(code)} AND user_id IS NOT NULL AND expires_at > now()
      RETURNING *
    `;
    if (!flow) throw new HttpError(400, { detail: 'That code is invalid or has expired.' });
    const [user] = await sql`SELECT * FROM users WHERE id = ${flow.user_id}`;
    if (!user) throw new HttpError(400, { detail: 'That code is invalid or has expired.' });

    const created = await createSession(sql, user.id, sessionTtlMs);
    res
      .location(mount(`/sessions/${created.session.id}`))
      .status(201)
      .json({
        session: sessionToObject(created.session),
        user: userToObject(user, config),
        token: created.token,
      });
  });

  // Linking is confirmed from a session rather than from a token, because it
  // is a lasting change to how the account can be signed into: a session is
  // the account acting as itself, while an automation token is a credential
  // that should not be able to bind a new identity to the account.
  router.post('/oidc/link', requireSession, async (req, res) => {
    if (!enabled) throw notFound();
    requireObjectBody(req);
    const returnTo = returnToPath(req.body.returnTo, config);
    const state = newSecret();
    const verifier = newSecret();
    const nonce = newSecret();
    const binding = newSecret();
    const authorizationUrl = await client.authorizationUrl({ state, nonce, verifier });

    await sql`DELETE FROM oidc_flows WHERE expires_at < now()`;
    await sql`
      INSERT INTO oidc_flows (kind, state_hash, flow_secret_hash, code_verifier, nonce, user_id, return_to, expires_at)
      VALUES ('link', ${hashToken(state)}, ${hashToken(binding)}, ${verifier}, ${nonce}, ${req.auth.user.id}, ${returnTo}, ${new Date(Date.now() + FLOW_TTL_MS)})
    `;
    setFlowCookie(res, binding);
    res.json({ authorizationUrl });
  });

  router.get('/oidc/identities', requireSession, async (req, res) => {
    const rows = await sql`
      SELECT id, issuer, subject, email, created_at FROM user_identities
      WHERE user_id = ${req.auth.user.id}
      ORDER BY id
    `;
    res.json({ data: rows.map(identityToObject) });
  });

  // An identity is not gated on the provider still being configured: an
  // operator who turns the provider off leaves accounts that linked it needing
  // a way to remove the link.
  router.delete('/oidc/identities/:id', requireSession, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id <= 0) throw notFound();
    await sql.begin(async (tx) => {
      const [identity] = await tx`
        SELECT * FROM user_identities WHERE id = ${id} AND user_id = ${req.auth.user.id} FOR UPDATE
      `;
      if (!identity) throw notFound('No such linked identity.');
      const [user] = await tx`SELECT * FROM users WHERE id = ${req.auth.user.id} FOR UPDATE`;
      const [{ count }] = await tx`
        SELECT count(*)::int AS count FROM user_identities WHERE user_id = ${req.auth.user.id}
      `;
      // Unlinking the last way in would strand the account: a password that
      // still works is a way in, but one the instance no longer accepts is not.
      const canUsePassword = Boolean(user.password_hash) && !oidc.required;
      if (!canUsePassword && count <= 1) {
        throw conflict(
          user.password_hash
            ? 'Password sign-in is turned off on this instance, so this link is the only way in.'
            : 'This link is the only way into the account. Ask an admin for a password before removing it.',
        );
      }
      await tx`DELETE FROM user_identities WHERE id = ${id}`;
      await audit(
        tx,
        user,
        'identity.unlink',
        { namespace: user.namespace },
        { issuer: identity.issuer },
      );
    });
    res.status(204).end();
  });

  async function finishLink(req, res, flow, { issuer, subject, claims }) {
    const [user] = await sql`SELECT * FROM users WHERE id = ${flow.user_id}`;
    if (!user) {
      return failFlow(
        req,
        res,
        flow,
        400,
        'link_failed',
        'The account this link was started for no longer exists.',
      );
    }
    const identity = await attachIdentity(sql, user.id, issuer, subject, claimEmail(claims));
    if (!identity || Number(identity.user_id) !== Number(user.id)) {
      return failFlow(
        req,
        res,
        flow,
        409,
        'identity_taken',
        'That identity is already linked to another account.',
      );
    }
    if (identity.created) {
      await audit(sql, user, 'identity.link', { namespace: user.namespace }, { issuer });
    }
    await sql`DELETE FROM oidc_flows WHERE id = ${flow.id}`;
    if (wantsHtml(req)) {
      const target = redirectTarget(flow.return_to, config);
      target.searchParams.set('oidc_linked', '1');
      return res.redirect(target.toString());
    }
    res.json({ linked: true, issuer, subject });
  }

  async function finishSignin(req, res, flow, exchangeCode, { issuer, subject, claims }) {
    const [existing] = await sql`
      SELECT * FROM user_identities WHERE issuer = ${issuer} AND subject = ${subject}
    `;
    let user;
    if (existing) {
      [user] = await sql`SELECT * FROM users WHERE id = ${existing.user_id}`;
    } else {
      user = await createAccountFromClaims(sql, rateLimiter, req, {
        issuer,
        subject,
        claims,
      });
    }
    if (!user) {
      return failFlow(req, res, flow, 500, 'signup_failed', 'The account could not be created.');
    }

    // A browser cannot read an Authorization header from a redirect, so it is
    // sent back with a one-time code instead and trades that for the session.
    if (wantsHtml(req)) {
      await sql`
        UPDATE oidc_flows
        SET user_id = ${user.id}, expires_at = ${new Date(Date.now() + EXCHANGE_TTL_MS)}
        WHERE id = ${flow.id}
      `;
      const target = redirectTarget(flow.return_to, config);
      target.searchParams.set('oidc_code', exchangeCode);
      return res.redirect(target.toString());
    }

    const created = await createSession(sql, user.id, sessionTtlMs);
    await sql`DELETE FROM oidc_flows WHERE id = ${flow.id}`;
    res
      .location(mount(`/sessions/${created.session.id}`))
      .status(201)
      .json({
        session: sessionToObject(created.session),
        user: userToObject(user, config),
        token: created.token,
      });
  }

  // A failure in the middle of a sign-in reaches a browser as a redirect back
  // with a slug the sign-in page can turn into wording, and an API client as
  // the problem response its own Accept header asked for.
  function failFlow(req, res, flow, status, slug, detail) {
    if (wantsHtml(req)) {
      const target = redirectTarget(flow?.return_to, config);
      target.searchParams.set('oidc_error', slug);
      return res.redirect(target.toString());
    }
    throw new HttpError(status, { detail });
  }

  return router;
}

// An account is created for an identity the provider vouches for and the hub
// has never seen. Roles stay local -- the first account is an admin exactly as
// it is for password sign-up -- and the namespace comes from the provider's
// preferred name when it can, with a digest-based fallback that cannot collide
// with anybody.
async function createAccountFromClaims(sql, rateLimiter, req, { issuer, subject, claims }) {
  await rateLimiter.signupCheck(`signup:${req.ip}`);
  const base = namespaceFromClaims(claims, issuer, subject);
  const displayName = displayNameFromClaims(claims, base);

  return sql.begin(async (tx) => {
    await tx`SELECT pg_advisory_xact_lock(hashtext('signup-bootstrap'))`;
    // Another callback for the same identity may have created the account
    // while this one waited for the lock.
    const [existing] = await tx`
      SELECT u.* FROM user_identities i JOIN users u ON u.id = i.user_id
      WHERE i.issuer = ${issuer} AND i.subject = ${subject}
    `;
    if (existing) return existing;

    const [{ count }] = await tx`SELECT count(*)::int AS count FROM users`;
    const role = count === 0 ? 'admin' : 'normal';
    const namespace = await freeNamespace(tx, base);
    const [user] = await tx`
      INSERT INTO users (namespace, display_name, role)
      VALUES (${namespace}, ${displayName}, ${role})
      RETURNING *
    `;
    await tx`
      INSERT INTO user_identities (user_id, issuer, subject, email)
      VALUES (${user.id}, ${issuer}, ${subject}, ${claimEmail(claims)})
    `;
    return user;
  });
}

// Inserts the link unless the identity already exists, in which case the row
// is returned with `created: false` and the caller decides what an existing
// link belonging to somebody else means.
async function attachIdentity(sql, userId, issuer, subject, email) {
  const [inserted] = await sql`
    INSERT INTO user_identities (user_id, issuer, subject, email)
    VALUES (${userId}, ${issuer}, ${subject}, ${email})
    ON CONFLICT (issuer, subject) DO NOTHING
    RETURNING *
  `;
  if (inserted) return { ...inserted, created: true };
  const [existing] = await sql`
    SELECT * FROM user_identities WHERE issuer = ${issuer} AND subject = ${subject}
  `;
  return existing;
}

async function freeNamespace(tx, base) {
  if (base) {
    const [taken] = await tx`SELECT 1 FROM users WHERE namespace = ${base}`;
    if (!taken) return base;
    for (let suffix = 2; suffix <= 50; suffix += 1) {
      const candidate = `${base.slice(0, 36)}-${suffix}`;
      const [hit] = await tx`SELECT 1 FROM users WHERE namespace = ${candidate}`;
      if (!hit) return candidate;
    }
  }
  for (;;) {
    const candidate = `user-${randomBytes(6).toString('hex')}`;
    const [hit] = await tx`SELECT 1 FROM users WHERE namespace = ${candidate}`;
    if (!hit) return candidate;
  }
}

function namespaceFromClaims(claims, issuer, subject) {
  const claimed = [claims.preferred_username, claims.nickname, claims.username].find(
    (value) => typeof value === 'string' && value.trim() !== '',
  );
  const normalized = claimed
    ?.toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 40)
    .replace(/-$/, '');
  if (normalized && isValidNamespace(normalized)) return normalized;
  const digest = createHash('sha256')
    .update(`${issuer}\u0000${subject}`)
    .digest('hex')
    .slice(0, 12);
  return `user-${digest}`;
}

function displayNameFromClaims(claims, fallback) {
  const claimed = [claims.name, claims.preferred_username, claims.nickname].find(
    (value) => typeof value === 'string' && value.trim() !== '',
  );
  return claimed ? claimed.trim().slice(0, 80) : fallback;
}

function claimEmail(claims) {
  if (typeof claims.email !== 'string') return null;
  const email = claims.email.trim();
  return email !== '' && email.length <= 254 ? email : null;
}

function identityToObject(row) {
  return {
    id: String(row.id),
    issuer: row.issuer,
    subject: row.subject,
    email: row.email ?? null,
    createdAt: row.created_at.toISOString(),
  };
}

// A browser navigation is a request for a page; anything else (an SPA calling
// with fetch, a CLI) wants JSON and gets the same information as one.
function wantsHtml(req) {
  return String(req.headers.accept ?? '').includes('text/html');
}

// Read one cookie without pulling in a parser for the whole jar. The values
// this reads are base64url secrets this instance set, so malformed input is
// simply "no cookie".
function readCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      return null;
    }
  }
  return null;
}

// Where the browser is sent once the provider hands it back. A path is
// resolved against publicBaseUrl and has to stay on that origin; an absolute
// URL has to name an origin the instance already trusts. Either way the stored
// value is the resolved URL, because otherwise an authorize link with an
// attacker's returnTo would hand that attacker a freshly minted sign-in code.
function returnToPath(value, config) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string' || value.length > 1024) {
    throw fieldErrors([{ field: 'returnTo', message: 'Must be a path or an allowed origin.' }]);
  }
  // Control characters are stripped by the URL parser rather than encoded, so
  // "/<tab>/evil.example" would first pass the leading-slash check here and
  // then resolve to "//evil.example" off-origin. Backslashes are refused for
  // the same reason on the browsers that treat them as slashes.
  if (hasControlChars(value) || value.includes('\\')) {
    throw fieldErrors([{ field: 'returnTo', message: 'Must be a path on this instance.' }]);
  }
  const base = URL.parse(config.publicBaseUrl);
  if (value.startsWith('/')) {
    const target = resolveAgainst(value, config.publicBaseUrl);
    if (!base || !target || target.origin !== base.origin) {
      throw fieldErrors([{ field: 'returnTo', message: 'Must be a path on this instance.' }]);
    }
    return `${target.pathname}${target.search}${target.hash}`;
  }
  const parsed = URL.parse(value);
  if (!parsed || (parsed.protocol !== 'https:' && parsed.protocol !== 'http:')) {
    throw fieldErrors([{ field: 'returnTo', message: 'Must be a path or an allowed origin.' }]);
  }
  if (!allowedReturnOrigins(config).has(parsed.origin)) {
    throw fieldErrors([
      {
        field: 'returnTo',
        message:
          "Must be a path on this instance, or an origin in the instance's cors.allowedOrigins.",
      },
    ]);
  }
  return parsed.toString();
}

function resolveAgainst(value, base) {
  try {
    return new URL(value, base);
  } catch {
    return null;
  }
}

function hasControlChars(value) {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function allowedReturnOrigins(config) {
  const origins = new Set();
  const base = URL.parse(config.publicBaseUrl);
  if (base) origins.add(base.origin);
  for (const origin of Array.isArray(config.cors.allowedOrigins)
    ? config.cors.allowedOrigins
    : []) {
    const parsed = URL.parse(origin);
    if (parsed) origins.add(parsed.origin);
  }
  return origins;
}

function redirectTarget(returnTo, config) {
  try {
    return new URL(returnTo ?? '', config.publicBaseUrl);
  } catch {
    return new URL(config.publicBaseUrl);
  }
}
