// ============================================================================
// FILE: srv/bookstore-service.cds
// MAPS TO DIAGRAM BOXES:
//   "req.user Created id, roles, attr" -> "Go to Authorization"
// This file IS the Authorization phase. Authentication already finished above.
// ----------------------------------------------------------------------------
// CONCEPT 1: @requires  = "you must be LOGGED IN" (any authenticated user).
// CONCEPT 2: @restrict  = "you must have THIS ROLE / CONDITION" (fine-grained).
// CONCEPT 3: `where` condition inside @restrict = ATTRIBUTE-BASED control,
//            reads req.user.attr.*  (e.g. country, department from JWT or mock users).
// ----------------------------------------------------------------------------
// SECURITY NOTE: @restrict is enforced in the CAP RUNTIME (database layer),
// not just in UI. Attacker calling OData directly with Postman is still blocked.
// Always prefer @restrict over hiding buttons in UI5 (defense in depth).
// ============================================================================
using { demo.auth as db } from '../db/schema';

@requires : 'authenticated-user'
// Every entity below inherits: unauthenticated request -> 401 Unauthorized.
// Authenticated but wrong role               -> 403 Forbidden.
service BookstoreService @(path : '/bookstore') {

  // ---- Custom helper: WHO AM I? -------------------------------------------
  // Exposes the diagram box "req.user Created id, roles, attr" so you can SEE it.
  // GET /bookstore/whoAmI  with  Authorization: Basic YWxpY2U6YWxpY2U=
  // Returns: { id:"alice", roles:["admin","Viewer"], attr:{...}, tenant, ... }
  // In production (xsuaa/ias/jwt) the SAME endpoint returns JWT-derived values:
  //   id    <- JWT 'sub' / 'user_name' claim
  //   roles <- JWT 'scope' / 'groups' claim mapped via xs-security.json role-templates
  //   attr  <- JWT custom attributes (e.g. country, department)
  entity WhoAmI {
    key id       : String;
        roles    : String;
        tenant   : String;
        attrDump : String;
  };

  // ---- ROLE-BASED example ---------------------------------------------------
  // grant: Viewer may READ. admin may CREATE/READ/UPDATE/DELETE (*).
  // to   : role name must EXACTLY match JWT scope/role OR mock user role.
  //        PROD TIP: xsuaa role = "$XSAPPNAME.<scope>" e.g. "myapp.Viewer".
  //        CAP strips the app prefix, so @restrict uses short name "Viewer".
  @restrict : [
    { grant : 'READ',   to : 'Viewer' },
    { grant : '*',      to : 'admin'  }
  ]
  entity BookList as projection on db.Books;

  // ---- ATTRIBUTE + OWNERSHIP example ----------------------------------------
  // All logged-in Support/admin users can READ, but row-level filtering happens
  // in JS (see bookstore-service.js): users only SEE their own department rows.
  // This is the "attr" arrow from req.user -> database query.
  @restrict : [
    { grant : 'READ',   to : ['Support', 'admin'] },
    { grant : 'CREATE', to : ['Support', 'admin'] },
    { grant : 'UPDATE', to : 'admin' }
  ]
  entity IncidentList as projection on db.Incidents;

  // ---- ACTION protected by role (teaches 403) --------------------------------
  // Even if authenticated, calling this without admin role -> 403 Forbidden.
  // Unauthenticated (no/invalid JWT)                        -> 401 Unauthorized.
  action pingAdminOnly() returns String;
}
