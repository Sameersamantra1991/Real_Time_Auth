// ============================================================================
// FILE: srv/bookstore-service.js
// DIAGRAM BOXES COVERED:
//   "CAP Middleware xssec validates" -> "Valid? No->401 / Yes->req.user" -> handlers below
// After validation, CAP creates `req.user` and calls YOUR handlers.
// This file shows HOW to USE req.user safely + where 401 vs 403 come from.
// ----------------------------------------------------------------------------
// req.user SHAPE (same for mocked AND real JWT, only SOURCE differs):
//   req.user.id       : String  <- JWT 'sub' claim  | mock username ("alice")
//   req.user.roles    : Object  <- JWT scopes/groups | mock roles array
//   req.user.attr     : Object  <- JWT custom attrs | mock attr map
//   req.user.tenant   : String  <- JWT 'zid' / 'zone' (multitenancy)
//   req.user.is(role) : fn      <- BEST WAY to check a role (handles xsuaa prefix)
//   req.user.isAuthenticatedAnon? -> use req.user._anon flag / is('authenticated-user')
// ============================================================================
const cds = require('@sap/cds');

module.exports = cds.service.impl(async function () {
  const { BookList, IncidentList, WhoAmI } = this.entities;

  // --------------------------------------------------------------------------
  // 0) GLOBAL REQUEST LOG = teaches "Authorization: Bearer JWT" box.
  // Runs BEFORE every handler. Logs WHICH identity CAP extracted.
  // SECURITY: audit logging is mandatory in secure apps (detect token theft).
  // --------------------------------------------------------------------------
  this.before('*', (req) => {
    const u = req.user;
    // u._anon === true means NO valid credential -> CAP will soon return 401
    // because service has @requires:'authenticated-user'.
    console.log(
      `[AUDIT] ${req.method} ${req.path} | id=${u.id} anon=${!!u._anon} |` +
      ` roles=${JSON.stringify(u.roles)} | tenant=${u.tenant || '-'}`
    );
  });

  // --------------------------------------------------------------------------
  // 1) WhoAmI = VISUALIZE diagram box "req.user Created id, roles, attr".
  // Try in Postman:
  //   a) alice (admin): Authorization: Basic YWxpY2U6YWxpY2U=  (alice:alice)
  //   b) bob   (viewer): Authorization: Basic Ym9iOmJvYg==    (bob:bob)
  //   c) none  (anon):   no header -> 401 Unauthorized
  // PROD (xsuaa/ias/jwt): Authorization: Bearer <JWT from IdP> -> same output,
  // but values come from JWT claims, NOT from package.json mock map.
  // --------------------------------------------------------------------------
  this.on('READ', WhoAmI, (req) => {
    const u = req.user;
    // req.reject(401) is what CAP does AUTOMATICALLY for @requires failures.
    // Shown here explicitly for learning: never trust u.id without this check
    // in CUSTOM middleware (CAP already checked it via @requires above).
    if (u._anon || u.id === 'anonymous') {
      // DIAGRAM ARROW: Valid? --No--> 401 Unauthorized
      return req.reject(401, 'Missing or invalid credentials. Send Basic (mock) or Bearer JWT (prod).');
    }
    return [{
      id: u.id,                                   // WHO: JWT sub / mock username
      roles: Object.keys(u.roles || {}).join(','), // WHAT ROLES: JWT scopes / mock roles
      tenant: u.tenant || 'provider',              // WHICH SUBACCOUNT (xsuaa zid)
      attrDump: JSON.stringify(u.attr || {})       // EXTRA CLAIMS: department, country...
    }];
  });

  // --------------------------------------------------------------------------
  // 2) ROLE CHECK inside code = second layer behind @restrict (defense in depth).
  // @restrict in .cds already blocks non-admin WRITE with 403.
  // This handler adds a CLEAR error message + teaches req.user.is('admin').
  // --------------------------------------------------------------------------
  this.before(['CREATE', 'UPDATE', 'DELETE'], BookList, (req) => {
    // req.user.is('admin') understands BOTH:
    //   mocked: roles array contains 'admin'
    //   xsuaa : JWT scope 'myapp.admin' (prefix stripped automatically)
    if (req.method !== 'READ' && !req.user.is('admin')) {
      // Authenticated (401 passed) but not allowed -> 403 Forbidden.
      // NEVER return 404 to hide existence (info leak); 403 is correct here.
      return req.reject(403, `User '${req.user.id}' lacks role 'admin' for ${req.method} on Books.`);
    }
    // --- INPUT VALIDATION (secure app MUST validate, never trust client) ---
    // @assert in CDS validates types; THESE checks stop business-logic abuse:
    if (req.method === 'CREATE' || req.method === 'UPDATE') {
      const { title, price } = req.data;
      // Prevent stored-XSS via book titles rendered later in UI5:
      if (title && /<script|javascript:|onerror\s*=/i.test(title)) {
        return req.reject(400, 'Title contains forbidden HTML/JS. Plain text only.');
      }
      // Prevent negative-price / overflow abuse:
      if (price !== undefined && (Number(price) < 0 || Number(price) > 999999)) {
        return req.reject(400, 'Price must be between 0 and 999999.');
      }
      // Mass-assignment guard: client must NOT set internal fields (none here,
      // but pattern shown for learning). Strip unexpected props if needed.
    }
  });

  // --------------------------------------------------------------------------
  // 3) ATTRIBUTE-BASED FILTER = teaches "attr" in "id, roles, attr".
  // IncidentList rows are filtered by req.user.attr.department.
  // alice (sales) sees only sales tickets; bob has NO Support role so @restrict
  // already gave him 403 before this code runs. Erin (support) sees support rows.
  // REAL JWT: attr comes from IdP attribute mapping (IAS -> xs-security.json
  // attribute-references). Same code works unchanged. That is the POWER of CAP:
  // handlers read req.user.attr, independent of WHICH IdP issued the JWT.
  // --------------------------------------------------------------------------
  this.before('READ', IncidentList, (req) => {
    const u = req.user;
    // Admin bypasses attribute filter (sees all) - common break-glass pattern.
    if (u.is('admin')) return;
    const dept = u.attr?.department;
    if (!dept) {
      // Authenticated but no department claim -> deny, don't leak all rows.
      return req.reject(403, `User '${u.id}' has no department attribute.`);
    }
    // Inject WHERE clause: attacker cannot override via $filter because CAP
    // ANDs this with user query. This is ROW-LEVEL security (secure pattern).
    req.query.where(`department = '${dept}'`);
  });

  // Stamp ownership on CREATE: owner = req.user.id (JWT sub). Prevents spoofing
  // where attacker sends { owner: 'alice' } to impersonate someone else.
  this.before('CREATE', IncidentList, (req) => {
    req.data.owner = req.user.id; // SERVER-ASSIGNED, ignore client-sent owner
    req.data.department = req.data.department || req.user.attr?.department || 'general';
  });

  // --------------------------------------------------------------------------
  // 4) ACTION with explicit role check = teaches 401 vs 403 difference.
  //   no header / bad JWT  -> CAP middleware rejects BEFORE here -> 401
  //   valid login, wrong role (bob calls pingAdminOnly) -> 403 here
  // --------------------------------------------------------------------------
  this.on('pingAdminOnly', (req) => {
    if (!req.user.is('admin')) {
      return req.reject(403, 'Only admin may call pingAdminOnly.');
    }
    return `Hello ${req.user.id}, you proved role-based authorization works.`;
  });
});
