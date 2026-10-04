// ============================================================================
// FILE: app/shop/webapp/controller/Main.controller.js
// Same backend, UI5 skin: JSONModel + fetch (like the plain app.js) driving
// sap.m controls. Why NOT ODataModel here? The demo must SEND demo Basic
// credentials per user (alice/bob/erin) to teach the mocked branch, and
// ODataModel hides auth inside the browser (native 401 dialog). Explicit
// fetch keeps every diagram step visible: login -> headers -> 401/403/200.
// ----------------------------------------------------------------------------
// UI5-SPECIFIC SECURITY NOTES:
// [U1] XML-view {bindings} auto-escape HTML — a stored "<script>" book title
//      renders as text in sap.m.Text/Table cells. No escapeHtml() needed.
//      (FormattedText htmlText is the ONE exception: we only feed it our own
//      static strings below, never server data.)
// [U2] Credentials = controller closure vars (memory only). Never put them in
//      a JSONModel (models are inspectable/bindable) or localStorage.
// [U3] Same-origin fetch ('') + credentials:'include': locally the Basic
//      header authenticates; on BTP the approuter session cookie travels and
//      no Authorization header is sent — both diagram branches, one code path.
// [U4] CSRF: approuter sets csrfProtection:true, so cookie-session WRITES need
//      an X-CSRF-Token handshake first. Basic-auth writes skip it (CAP trusts
//      the per-request Authorization header, not cookies).
// ============================================================================
sap.ui.define(
  ['sap/ui/core/mvc/Controller', 'sap/m/MessageBox', 'sap/m/MessageToast', 'sap/ui/model/Filter', 'sap/ui/model/FilterOperator'],
  function (Controller, MessageBox, MessageToast, Filter, FilterOperator) {
    'use strict';

    // [U2] The ONLY copies of the password. Tab closed => gone.
    let basicUser = null;
    let basicPass = null;
    let csrfToken = null;

    return Controller.extend('demo.shop.controller.Main', {
      /* ---------------- request layer (diagram: Bearer/Basic -> xssec) ----- */
      _headers: function (extra) {
        // [U3] Attach Basic only when demo credentials were typed.
        const h = Object.assign({ Accept: 'application/json' }, extra || {});
        if (basicUser) h.Authorization = 'Basic ' + btoa(basicUser + ':' + basicPass);
        if (csrfToken) h['X-CSRF-Token'] = csrfToken; // [U4]
        return h;
      },

      _api: async function (path, opts) {
        const res = await fetch(path, Object.assign(
          { credentials: 'include' }, // [U3] lets the XSUAA session cookie travel
          opts || {},
          { headers: this._headers((opts || {}).headers) }
        ));
        if (res.status === 401) throw Object.assign(new Error('401 Unauthorized — missing or expired credential. Log in again.'), { code: 401 });
        if (res.status === 403) throw Object.assign(new Error('403 Forbidden — logged in, but your roles lack permission.'), { code: 403 });
        if (!res.ok) {
          let detail = '';
          try { detail = (await res.json()).error?.message || ''; } catch { /* non-JSON body */ }
          throw Object.assign(new Error(res.status + ' — ' + (detail || res.statusText)), { code: res.status });
        }
        this._step('stepValidate'); // 2xx proves "xssec validates → Valid? Yes"
        return res.status === 204 ? null : res.json();
      },

      /* [U4] CSRF handshake for cookie-session writes; skipped for Basic. */
      _ensureCsrf: async function () {
        if (basicUser || csrfToken) return;
        try {
          const r = await fetch('/bookstore/BookList?$top=1', { credentials: 'include', headers: { 'X-CSRF-Token': 'Fetch' } });
          const t = r.headers.get('X-CSRF-Token');
          if (t) csrfToken = t;
        } catch { /* local dev: no approuter CSRF, Basic writes still work */ }
      },

      _step: function (id) {
        const el = this.byId(id);
        if (el) el.setState('Success');
      },
      _resetSteps: function () {
        ['stepLogin', 'stepToken', 'stepValidate', 'stepUser', 'stepAuthz'].forEach((id) => this.byId(id).setState('None'));
      },

      /* ---------------- auth (diagram: User -> Login -> req.user) ---------- */
      onLogin: function () {
        this._doLogin(this.byId('userInput').getValue().trim(), this.byId('passInput').getValue());
      },
      onPersona: function (evt) {
        const d = evt.getSource().getCustomData();
        const get = (k) => d.find((c) => c.getKey() === k).getValue();
        this.byId('userInput').setValue(get('user'));
        this.byId('passInput').setValue(get('pass'));
        this._doLogin(get('user'), get('pass'));
      },

      _doLogin: async function (user, pass) {
        basicUser = user; basicPass = pass; csrfToken = null;
        this._resetSteps();
        this.getView().setBusy(true); // busy overlay until identity + data land
        try {
          const data = await this._api('/bookstore/WhoAmI');
          const me = data.value[0];
          let attr = {};
          try { attr = JSON.parse(me.attrDump || '{}'); } catch { attr = {}; }
          const initials = (me.id || '?').slice(0, 2).toUpperCase();
          this.getView().getModel('session').setData({
            loggedIn: true, id: me.id, roles: me.roles,
            rolesCount: (me.roles || '').split(',').filter(Boolean).length,
            tenant: me.tenant, dept: attr.department || '', country: attr.country || '',
            attr: JSON.stringify(attr),
          });
          this.byId('whoPill').setText(me.id + ' · ' + me.roles);
          this.byId('whoPill').setState('Success');
          this.byId('heroAvatar').setInitials(initials);
          this.byId('whoAvatar').setInitials(initials);
          ['stepLogin', 'stepToken', 'stepUser'].forEach((s) => this._step(s));
          await Promise.all([this._loadBooks(), this._loadIncidents()]);
          this._step('stepAuthz');
          this.byId('flowHint').setText('Walking as ' + me.id + ' — create a book as bob to feel the 403.');
          MessageToast.show('Welcome ' + me.id);
        } catch (e) {
          basicUser = basicPass = null; // failed login keeps no credential
          MessageBox.error(e.message, { title: e.code === 401 ? 'Not authenticated (401)' : 'Login failed' });
        } finally {
          this.getView().setBusy(false);
        }
      },

      onLogout: function () {
        // [U2] Drop the only copies. Prod: also kill the IdP session.
        basicUser = basicPass = csrfToken = null;
        if (!this.byId('userInput').getValue()) fetch('/do/logout', { credentials: 'include' }).catch(() => {});
        this.getView().getModel('session').setData({ loggedIn: false, id: '', roles: '', rolesCount: 0, tenant: '', dept: '', country: '', attr: '' });
        this.byId('whoPill').setText('anonymous');
        this.byId('whoPill').setState('None');
        this.byId('heroAvatar').setInitials('?');
        this.byId('whoAvatar').setInitials('?');
        this.byId('bookSearch').setValue('');
        this._resetSteps();
      },

      /* ---------------- books (diagram: Go to Authorization, role gate) ---- */
      _loadBooks: async function () {
        const table = this.byId('bookTable');
        table.setBusy(true);
        try {
          const data = await this._api('/bookstore/BookList?$orderby=ID');
          this.getView().getModel('books').setData(data);
          this.onSearchBooks(); // re-apply any active search text to fresh rows
        } catch (e) {
          MessageBox.warning('Books: ' + e.message, { title: e.code === 403 ? 'Forbidden (403)' : 'Load failed' });
        } finally {
          table.setBusy(false);
        }
      },

      /* Client-side search over the already-authorized rows. Safe: it can only
         NARROW what the server allowed — never widen it (server filter first). */
      onSearchBooks: function () {
        const q = (this.byId('bookSearch').getValue() || '').trim();
        const binding = this.byId('bookTable').getBinding('items');
        if (!binding) return;
        binding.filter(q ? [new Filter({ filters: [
          new Filter('title', FilterOperator.Contains, q),
          new Filter('author', FilterOperator.Contains, q),
        ], and: false })] : []);
      },

      onAddBook: async function () {
        const body = {
          ID: Date.now() % 100000, // demo ids; prod would use server-side UUIDs
          title: this.byId('bTitle').getValue().trim(),
          author: this.byId('bAuthor').getValue().trim(),
          price: Number(this.byId('bPrice').getValue()),
          country: (this.byId('bCountry').getValue().trim() || 'DE').toUpperCase(),
        };
        try {
          await this._ensureCsrf();
          await this._api('/bookstore/BookList', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
          MessageToast.show('Book created');
          this._loadBooks();
        } catch (e) {
          MessageBox.error('Create: ' + e.message, { title: e.code === 403 ? 'Forbidden (403) — need admin' : 'Create failed' });
        }
      },

      onDeleteBook: async function (evt) {
        // Row context gives the key; encodeURIComponent keeps OData key syntax safe.
        const id = evt.getSource().getBindingContext('books').getProperty('ID');
        try {
          await this._ensureCsrf();
          await this._api('/bookstore/BookList(' + encodeURIComponent(id) + ')', { method: 'DELETE' });
          MessageToast.show('Book ' + id + ' deleted');
          this._loadBooks();
        } catch (e) {
          MessageBox.error('Delete: ' + e.message, { title: e.code === 403 ? 'Forbidden (403) — need admin' : 'Delete failed' });
        }
      },

      /* ---------------- incidents (diagram: attr-based row filter) --------- */
      _loadIncidents: async function () {
        const table = this.byId('incidentTable');
        table.setBusy(true);
        try {
          const data = await this._api('/bookstore/IncidentList?$orderby=ID');
          this.getView().getModel('incidents').setData(data);
        } catch (e) {
          MessageBox.warning('Incidents: ' + e.message, { title: e.code === 403 ? 'Forbidden (403)' : 'Load failed' });
        } finally {
          table.setBusy(false);
        }
      },

      /* ---------------- admin action (401 vs 403 teaching) ----------------- */
      onPing: async function () {
        try {
          await this._ensureCsrf();
          const r = await this._api('/bookstore/pingAdminOnly', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
          // [U1] FormattedText exception: value comes from OUR action (not user
          // input), so embedding it as static text is safe here.
          this.byId('pingOut').setHtmlText('<p>' + r.value + '</p>');
        } catch (e) {
          this.byId('pingOut').setHtmlText('<p>' + e.message + '</p>');
          MessageBox.error('Admin action: ' + e.message, { title: e.code === 403 ? 'Forbidden (403) — need admin' : 'Call failed' });
        }
      },
    });
  }
);
