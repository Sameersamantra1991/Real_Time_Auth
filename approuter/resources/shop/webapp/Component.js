// ============================================================================
// FILE: app/shop/webapp/Component.js  (namespace demo.shop -> ./webapp)
// UIComponent = the UI5 app root. It reads manifest.json (metadata manifest)
// and creates the root view. Three NAMED JSONModels act as the client-side
// store: "session" (who is logged in), "books", "incidents" (OData payloads).
// ----------------------------------------------------------------------------
// SECURITY: models hold only DISPLAY data. Credentials live in the Main
// controller's closure variables (memory only) — never in a model, never in
// localStorage, so a stray control or debug console can't leak them.
// ============================================================================
sap.ui.define(
  ['sap/ui/core/UIComponent', 'sap/ui/model/json/JSONModel'],
  function (UIComponent, JSONModel) {
    'use strict';
    return UIComponent.extend('demo.shop.Component', {
      metadata: { manifest: 'json' }, // -> webapp/manifest.json (app descriptor)

      init: function () {
        UIComponent.prototype.init.apply(this, arguments);

        // "session" mirrors diagram box "req.user Created id, roles, attr".
        // Extra display fields (rolesCount/dept/country/initials) are DERIVED
        // from the WhoAmI payload at login — still display-only, no secrets.
        this.setModel(new JSONModel({ loggedIn: false, id: '', roles: '', rolesCount: 0, tenant: '', dept: '', country: '', attr: '' }), 'session');
        // OData V4 service shape: { "@odata.context": ..., "value": [...] }.
        this.setModel(new JSONModel({ value: [] }), 'books');
        this.setModel(new JSONModel({ value: [] }), 'incidents');
      },
    });
  }
);
