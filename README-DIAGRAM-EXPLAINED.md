# Real_Time_Auth — Diagram 1 Explained End-to-End
### Authentication Flow: From Login to `req.user` (CAP Node.js)

This app implements **every box in your image**, with security comments in code.
Start here, then open files in order 1 → 7.

```
User/UI5/Postman
       |
cds.requires.auth.kind?  <-- package.json > cds.requires.auth (4 profiles)
  /  |   \      \
xsuaa ias Custom  mocked
  \  |   /      |
 IdentityProvider  Local Mock Users (alice,bob)
       |                |
 Returns JWT Token      | (no JWT, Basic Auth)
       |                |
Authorization: Bearer JWT  (srv/server.js logs it, never logs the secret)
       |
CAP Middleware xssec validates (automatic: signature, exp, aud, iss)
       |
     Valid? --No--> 401 Unauthorized
       |
      Yes
       |
req.user Created: id, roles, attr (srv/bookstore-service.js uses it)
       |
Go to Authorization (@restrict in srv/bookstore-service.cds)
```

---

## PHASE 1 — Entry: `User / UI5 / Postman` (your laptop)

| Client | What it sends | When |
|---|---|---|
| Postman (mocked) | `Authorization: Basic YWxpY2U6YWxpY2U=` (=`alice:alice`) | Local learning, `kind=mocked` |
| Postman (prod) | `Authorization: Bearer <JWT from IAS/XSUAA>` | BTP, `kind=ias/xsuaa/jwt` |
| UI5 app | Same Bearer header + `X-CSRF-Token` for POST/PUT/DELETE | Browser via approuter |

**Security:** always HTTPS in prod (else JWT is sniffed). Approuter + `srv/server.js`
helmet/CORS/rate-limit wrap every call. Try without header → expect `401`.

Test now:
```http
GET http://localhost:4004/bookstore/WhoAmI
# no header -> 401. This is diagram arrow "Valid? --No--> 401".
```

## PHASE 2 — Decision: `cds.requires.auth.kind?` (the diamond)

File: `package.json > cds.requires.auth` + profiles `[mocked] [xsuaa] [ias] [jwt]`.

| `kind` | Diagram arrow | Needs BTP? | Validator |
|---|---|---|---|
| `mocked` | `mocked → Local Mock Users` | No | CAP builds `req.user` from `users:{alice,bob,erin}` |
| `xsuaa` | `xsuaa → XSUAA Service` | Yes (XSUAA binding + `xs-security.json`) | `@sap/xssec` checks XSUAA signature |
| `ias` | `ias → SAP IAS New Standard` | Yes (IAS broker) | `@sap/xssec` checks IAS signature |
| `jwt` | `Custom OIDC → Identity Provider` | Any OIDC IdP | `xssec` checks `jwks_uri + aud + iss` |

Switch with:
```
npm run dev            # mocked (default, learning)
npm run start:xsuaa    # cds serve --profile xsuaa
npm run start:ias      # cds serve --profile ias
npm run start:jwt      # cds serve --profile jwt
```
Same code, same `req.user` shape afterwards — that is the point of the diagram:
all real IdPs **converge** at `Returns JWT Token`.

## PHASE 3a — `XSUAA Service` (left arrow, legacy standard)

1. Admin creates XSUAA instance: `cf create-service xsuaa application xsuaa -c xs-security.json`
2. User logs in at `https://<subdomain>.authentication.<region>.hana.ondemand.com`
3. XSUAA returns JWT with `scope: ["real-time-auth-demo.Viewer", ...]`
4. CAP strips prefix → `req.user.is('Viewer') === true`

Learn in: `xs-security.json` (scopes → role-templates → role-collections).
Assign `Bookstore-Viewer` to bob, `Bookstore-Admin` to alice in BTP cockpit.

## PHASE 3b — `SAP IAS, New Standard` (middle arrow, use for NEW projects)

Same JWT flow, different issuer (`*.accounts.ondemand.com`) + IAS cockpit for
users/groups/conditional-auth/MFA. CAP config is one word change:
`kind: "ias"`. Role mapping identical. Prefer IAS for all greenfield apps —
XSUAA is maintenance mode.

## PHASE 3c — `Custom OIDC` (generic arrow, Entra ID / Auth0 / Keycloak)

Config in `package.json > [jwt] > jwt: { jwks_uri, aud, iss }`.
- `jwks_uri` = where public keys live (rotated by IdP, cached by xssec).
- `aud` = "this token is FOR my app" (stops replay to another app).
- `iss` = "this token is FROM my IdP" (stops forged-issuer attack).

Generate a learning token: `npm run token` → see `auth/generate-token.js`
comments for `header.payload.signature`, `sub/scope/exp/aud/iss`.

## PHASE 3d — `mocked → Local Mock Users alice, bob` (right arrow)

No Identity Provider, no JWT. CAP reads `Authorization: Basic base64(user:pass)`
and looks up `package.json > users`. Passwords here are **plain text for learning
only** — real IdPs store salted hashes (bcrypt) + MFA. Never deploy `mocked`.

| User | Password | Roles | attr |
|---|---|---|---|
| alice | alice | admin, Viewer | sales / DE |
| bob | bob | Viewer | marketing / IN |
| erin | erin | Support | support / US |

Postman → Headers → `Authorization: Basic YWxpY2U6YWxpY2U=` for alice.

## PHASE 4 — `Identity Provider → Returns JWT Token`

Real IdPs return (simplified):
```json
{ "access_token": "eyJhbG... (JWT)", "token_type": "Bearer", "expires_in": 3600 }
```
JWT = `base64(header).base64(payload).signature`. Decode at jwt.io — **payload is
NOT encrypted**, so never put passwords/PII inside. Signature proves authenticity.

## PHASE 5 — `Authorization: Bearer JWT` (client → CAP)

Every OData call carries:
```http
GET /bookstore/BookList HTTP/1.1
Host: myapp.cfapps.eu10.hana.ondemand.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```
`server.js` audit hook logs method+IP+status but **never the token**.
Missing/expired token → `401 + WWW-Authenticate: Bearer` header.

## PHASE 6 — `CAP Middleware xssec validates` (automatic, no code needed)

For each request xssec checks, in order — first failure → `401`:
1. **Present?** header exists and starts with `Bearer ` (else 401).
2. **Signature?** RSA-verify with key from `jwks_uri` (else 401 — forged token).
3. **Expired?** `exp > now`, `nbf <= now` (else 401 — replay of old token).
4. **Audience?** `aud` contains our xsappname (else 401 — token for another app).
5. **Issuer?** `iss` matches binding (else 401 — wrong IdP).
6. **Tenant?** `zid` matches subscribed subaccount (else 401 — cross-tenant access).

You can watch it: wrong `aud` token → 401 even with valid signature.

## PHASE 7 — `Valid? No → 401 / Yes → req.user { id, roles, attr }`

```js
// srv/bookstore-service.js
this.on('READ', WhoAmI, (req) => {
  req.user.id            // JWT sub        | 'alice'
  req.user.roles         // JWT scope      | { admin:{}, Viewer:{} }
  req.user.attr          // JWT attributes | { department:'sales', country:'DE' }
  req.user.tenant        // JWT zid        | subaccount zone
  req.user.is('admin')   // correct check (handles xsuaa prefix)
});
```

| Outcome | HTTP | Meaning | Fix |
|---|---|---|---|
| Bad/missing JWT, anon | `401 Unauthorized` | Authentication failed | Login again, fresh token |
| Valid JWT, wrong role | `403 Forbidden` | Authenticated, not allowed | Ask admin for role-collection |
| Valid JWT + role | `200 OK` | → `Go to Authorization` | See `srv/bookstore-service.cds` `@restrict` |

## PHASE 8 — `Go to Authorization` (next diagram, preview included)

- `@requires:'authenticated-user'` on service → any login passes, anon → 401.
- `@restrict GRANT/TO` on entities → role gate, wrong role → 403.
- `req.query.where(department=...)` in JS → attribute/row gate using `req.user.attr`.
- `req.data.owner = req.user.id` → ownership stamp (anti-spoofing).

Try the matrix (all `GET /bookstore/...`):

| Who | `WhoAmI` | `BookList READ` | `BookList CREATE` | `pingAdminOnly` |
|---|---|---|---|---|
| none | 401 | 401 | 401 | 401 |
| bob (Viewer) | 200 | 200 | 403 | 403 |
| erin (Support) | 200 | 403* | 403 | 403 |
| alice (admin) | 200 | 200 | 200 | 200 |

\* erin lacks `Viewer/admin` on BookList by design — teaches 403.

## Run it (3 commands)

```bash
npm install
npm run dev          # http://localhost:4004
# open tests/requests.http in VS Code (REST Client) or import into Postman
npm run token alice  # see what a JWT looks like
```

## Files to read in order

1. `package.json` — the diamond `cds.requires.auth.kind` + 4 profiles
2. `db/schema.cds` — data behind authorization
3. `srv/bookstore-service.cds` — `@requires` / `@restrict` (Go to Authorization)
4. `srv/bookstore-service.js` — `req.user` usage, 401/403, validation
5. `srv/server.js` — helmet / CORS / rate-limit around xssec
6. `auth/generate-token.js` — JWT anatomy for learning
7. `xs-security.json` — XSUAA scopes → CAP roles
8. `tests/requests.http` — copy-paste Postman flows

## Prod checklist (don't skip before `cf push`)

- [ ] `kind` is `ias` (new) or `xsuaa` (existing), never `mocked`
- [ ] `ALLOWED_ORIGINS` set to exact UI5/FLP URL (no `*`)
- [ ] CSP enabled in `server.js`, rate limits tuned, HANA bound, `npm audit` clean
- [ ] Short token lifetime, role-collections assigned, audit logs shipped
