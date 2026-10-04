// ============================================================================
// FILE: db/schema.cds
// DIAGRAM CONTEXT: This is the DATA that sits BEHIND "Go to Authorization".
//   Authentication (Diagram 1) answers: WHO are you?  -> req.user
//   Authorization (next diagram) answers: WHAT may you do? -> @restrict below
// LEARN: @restrict here is ENFORCED by CAP automatically AFTER req.user exists.
//        If req.user has no matching role -> 403 Forbidden (not 401!).
//        401 = not authenticated (bad/missing JWT). 403 = authenticated but not allowed.
// ============================================================================
namespace demo.auth;

// -- Books entity: used to teach ROLE-BASED authorization --------------------
// Viewer role may READ, admin role may do EVERYTHING (* = CRUD).
// Alice (admin+Viewer) passes. Bob (Viewer only) can READ but gets 403 on WRITE.
// Anonymous / unauthenticated gets 401 on ANY access because service requires login.
entity Books {
  key ID     : Integer;
  title      : String(200);
  author     : String(100);
  price      : Decimal(9,2);

  // ATTRIBUTE-BASED example column:
  // We will filter by `country` in srv code using req.user.attr.country.
  // This teaches the "attr" part of diagram box "req.user Created id, roles, attr".
  country    : String(2);
}

// -- Incidents entity: used to teach ATTRIBUTE + OWNERSHIP checks ------------
// Support engineers see only their own department's tickets.
// Implemented in srv code via req.user.attr.department + req.user.id.
entity Incidents {
  key ID         : Integer;
  title          : String(200);
  department     : String(50);
  owner          : String(100); // stores req.user.id of creator
  status         : String(20) default 'open';
}
