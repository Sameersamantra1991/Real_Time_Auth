// ============================================================================
// FILE: auth/generate-token.js
// PURPOSE: Learn diagram boxes "Returns JWT Token" + "Authorization: Bearer JWT"
//          WITHOUT needing BTP. Generates a LOCAL demo JWT shaped like an
//          XSUAA/IAS token so you can paste it into Postman and SEE validation.
// ----------------------------------------------------------------------------
// RUN:  npm run token            (or: node ./auth/generate-token.js alice)
// OUTPUT: a signed JWT + the exact Postman Authorization header to use.
// ----------------------------------------------------------------------------
// SECURITY LESSONS in comments below:
//  1) Structure: header.payload.signature  (all Base64URL, signature = HMAC/RSA)
//  2) Claims: sub=id, scope/roles, exp=expiry, aud=audience, iss=issuer
//  3) CAP/xssec checks signature+exp+aud+iss. THIS demo uses HS256 symmetric
//     secret for LEARNING ONLY. Real XSUAA/IAS use RS256 asymmetric keys
//     published at jwks_uri (see package.json [jwt] profile) so ANYONE can
//     verify but ONLY the IdP can sign. Never accept HS256 tokens in prod.
// ============================================================================
const jwt = require('jsonwebtoken');

// DEV-ONLY secret. In prod the private key lives ONLY inside the Identity
// Provider. If this secret leaks, anyone can FORGE tokens -> full impersonation.
const DEMO_SECRET = process.env.DEMO_JWT_SECRET || 'dev-only-secret-change-me';

function buildToken(username = 'alice') {
  // Mock directory mirrors package.json mocked users, so behavior matches.
  const directory = {
    alice: { roles: ['admin', 'Viewer'], attr: { department: 'sales', country: 'DE' } },
    bob:   { roles: ['Viewer'],          attr: { department: 'marketing', country: 'IN' } },
    erin:  { roles: ['Support'],         attr: { department: 'support', country: 'US' } }
  };
  const profile = directory[username] || directory.alice;

  // --- PAYLOAD = the CLAIMS xssec will validate + CAP maps to req.user ------
  const payload = {
    // 'sub' (subject) -> becomes req.user.id. Immutable user identifier.
    sub: username,
    user_name: username,
    // 'scope'/'groups' -> becomes req.user.roles. XSUAA uses scope strings
    // like "myapp.Viewer"; IAS uses groups. CAP normalizes both to roles.
    scope: profile.roles.map(r => `real-time-auth-demo.${r}`),
    groups: profile.roles,
    // custom attributes -> becomes req.user.attr (department/country demo)
    department: profile.attr.department,
    country: profile.attr.country,
    // 'aud' MUST equal your app id, else xssec rejects (anti-replay).
    aud: 'real-time-auth-demo',
    // 'iss' MUST equal trusted IdP URL, else xssec rejects (anti-forgery).
    iss: 'http://localhost:4004/demo-idp',
    // 'zid' = tenant zone id (multitenancy). Same user in 2 subaccounts = 2 zids.
    zid: 'demo-tenant'
  };

  // --- SIGN with 1h expiry ---------------------------------------------------
  // 'exp' is THE most important claim: stolen JWT works until exp.
  // PROD RULE: keep lifetimes SHORT (5-15 min) + use refresh tokens.
  const token = jwt.sign(payload, DEMO_SECRET, {
    algorithm: 'HS256', // LEARNING ONLY. Prod: RS256 via IdP private key.
    expiresIn: '1h'
  });

  console.log(`\n=== Demo JWT for user '${username}' (LEARNING ONLY, HS256) ===`);
  console.log(`\nPaste into Postman as:\n  Authorization: Bearer ${token}\n`);
  console.log('Decoded payload (what CAP turns into req.user):');
  console.log(JSON.stringify(jwt.decode(token), null, 2));
  console.log('\nNOTE: kind=mocked ignores Bearer and uses Basic instead.');
  console.log('To test Bearer locally, run with --profile jwt + custom validator,');
  console.log('or deploy to BTP where xssec validates REAL IAS/XSUAA RS256 tokens.\n');
  return token;
}

buildToken(process.argv[2] || 'alice');
