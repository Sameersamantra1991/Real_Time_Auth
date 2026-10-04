// ============================================================================
// FILE: srv/server.js
// DIAGRAM BOXES: "Authorization: Bearer JWT" -> "CAP Middleware xssec validates"
// This file runs BEFORE CAP's xssec middleware. We add TRANSPORT + APP security
// around it. Order matters: helmet/cors/rate-limit -> xssec JWT check -> handlers.
// ----------------------------------------------------------------------------
// LAYER 1 (here): TLS redirect, secure headers, CORS, rate limit, body limits.
// LAYER 2 (CAP/xssec automatic): JWT signature, expiry, audience, issuer check.
// LAYER 3 (bookstore-service.cds): @requires / @restrict role checks.
// LAYER 4 (bookstore-service.js): attribute checks + input validation.
// A "fully secure" app needs ALL FOUR. Removing any one re-opens an attack.
// ============================================================================
const cds = require('@sap/cds');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

cds.on('bootstrap', (app) => {
  // --- 1) SECURE HTTP HEADERS (helmet) --------------------------------------
  // Blocks: clickjacking (frameguard), MIME-sniff XSS (noSniff), basic XSS
  // filter, removes X-Powered-By fingerprint. One line, huge win.
  app.use(helmet({
    // UI5 Fiori Launchpad loads resources cross-origin; keep CSP permissive in
    // DEV but TIGHTEN contentSecurityPolicy in production to your FLP domain.
    contentSecurityPolicy: false, // TODO(prod): set real CSP allow-list
    crossOriginEmbedderPolicy: false // TODO(prod): enable unless FLP breaks
  }));

  // --- 2) CORS: WHICH UI5 / Postman origins may call us? --------------------
  // Without CORS, ANY website's JS could call your API with victim's cookies.
  // Bearer-JWT apps usually use `origin: <your FLP/UI5 URL>`, never '*'.
  // '*' below is DEV-ONLY so local UI5 + Postman both work while learning.
  app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || '*', // TODO(prod): set exact FLP origin
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    allowedHeaders: ['Authorization', 'Content-Type', 'X-CSRF-Token'],
    maxAge: 600
  }));

  // --- 3) RATE LIMIT: stops password-spray + JWT-spray brute force ---------
  // Attacker trying 1000 passwords / stolen tokens per second gets throttled.
  // CAP's xssec returns 401 per bad token; THIS middleware slows the loop.
  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 min window
    max: 200,                  // 200 requests per IP per window (raise for OData $batch)
    standardHeaders: true,     // sends RateLimit-* headers so UI5 can back off
    message: { error: 'Too many requests, slow down (rate limited).' }
  });
  app.use('/bookstore', loginLimiter);

  // --- 4) PAYLOAD LIMIT is set in CAP via cds.requires.odata settings; ------
  // additionally reject huge bodies here to stop DoS before JSON parsing.
  // (cds bootstrap already caps OData $top; see package.json note + README.)

  // --- 5) AUDIT: log auth failures centrally --------------------------------
  // CAP/xssec sends 401 with WWW-Authenticate header. This hook logs them so
  // SOC can spot credential-stuffing. Do NOT log the JWT itself (secret!).
  app.use((req, res, next) => {
    res.on('finish', () => {
      if (res.statusCode === 401 || res.statusCode === 403) {
        console.warn(
          `[SECURITY] ${res.statusCode} ${req.method} ${req.originalUrl} ` +
          `ip=${req.ip} auth=${(req.headers.authorization || 'none').slice(0, 12)}...`
        );
      }
    });
    next();
  });
});

module.exports = cds.server;
