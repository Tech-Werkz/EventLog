/**
* @description MeshCentral event log plugin
* @author Ryan Blenis
* @copyright
* @license Apache-2.0
*/

"use strict";

module.exports.eventlog = function (parent) {
    var obj = {};

    obj.parent = parent;
    obj.meshServer = parent.parent;
    obj.db = null;

    // Functions that need to be brought to the front end for processing.
    // (If they need to be accessed in the GUI, they should be here.)
    // NOTE: these are serialized with .toString() and run in the browser.
    //       They must be self-contained and reference each other only via
    //       pluginHandler.eventlog.<fnName>.
    obj.exports = [
      'registerPluginTab',
      'on_device_page',
      'fe_on_message',
      'onRemoteEventLogStateChange',
      'createRemoteEventLog',
      'onDeviceRefreshEnd',
      'onAccess',
      'elCan',
      'elAccessGate',
      'elRequestAccess',
      'elRecheckAccess',
      '_pluginPermissions',
      // new UI
      'elState',
      'elLevelInfo',
      'elHash',
      'elFixText',
      'elNormalize',
      'elFmtTime',
      'elParseIds',
      'elMatch',
      'elFiltered',
      'elFold',
      'elInjectStyles',
      'elEnsureShell',
      'elRenderShell',
      'elUpdate',
      'elRenderChips',
      'elRenderFacets',
      'elRenderBody',
      'elEmptyText',
      'elRenderDetailHtml',
      'elRenderStatus',
      'elSetLayout',
      'elToggleFold',
      'elSetShow',
      'elSetRange',
      'elSelLog',
      'elSelSource',
      'elToggleLevel',
      'elToggleFacet',
      'elFacetsMore',
      'elIdInput',
      'elTextInput',
      'elClearFilter',
      'elResetFilters',
      'elSetSort',
      'elRowClick',
      'elSetDTab',
      'elCopy',
      'elToggleRaw',
      'elFilterBy',
      'elKeyNav',
      'elRequestLive',
      'elAutoTick',
      'elRefresh',
      'elTogglePause',
      'elExportCsv',
      // sizing / density (v0.1.2)
      'elLoadJson',
      'elSetRows',
      'elColDefault',
      'elColW',
      'elSaveCols',
      'elSetColW',
      'elRzDown',
      'elRzFit',
      'elGripDown',
      'elGripReset',
      'elFitAvail',
      'elFitHeight',
      'elResetSizes',
      'elVSplitDown',
      'elVSplitReset',
      'elRowFor',
      'elDetailsText',
      // Linux support (v0.1.5)
      'elPlatform',
      'elIsSupported',
      'elPriName',
      'elLbl',
      'elRawOf',
      'elSelCat',
      // live tunnel gating (v0.1.11)
      'elTabVisible',
      'elStopLive',
      'elEnsureLive',
      'elHookTabSwitch',
      'goPageStart',
      // include/exclude rules for categories and sources (v0.1.12)
      'elRules',
      'elAllowed',
      'elLiveAllowed'
    ];

    obj._pluginPermissions = function() {
        return {
            "deviceLiveTab": "Event Log: Live Tab"
        };
    };

    // ---- Plugin permissions (server side) -----------------------------------------------------
    // Registered with MeshCentral's plugin permission system, so they appear in MeshCentral's permissions dialog
    // (global / device group / device). Default is "denied": only users on the allowed list may use the plugin.
    obj.PERMISSIONS = {
        deviceLiveTab:    { title: 'Event Log: Live Tab',    desc: 'Can open the live event view of a device',            default: 'denied' }
    };
    obj.ACTION_PERMISSION = {};   // no user-initiated server action needs a permission: Live runs through the browser's own relay tunnel
    obj.registerPermissions = function() {
        if (obj._permsRegistered) return true;
        var cands = [obj.parent, obj.meshServer && obj.meshServer.pluginHandler, obj];
        for (var i = 0; i < cands.length; i++) {
            if (cands[i] != null && typeof cands[i].registerPermissions == 'function' && cands[i] !== obj) {
                try { cands[i].registerPermissions('eventlog', obj.PERMISSIONS); obj._permsRegistered = true; return true; }
                catch (e) { console.log('EVENTLOG: could not register plugin permissions: ' + (e.message || e)); }
            }
        }
        return false;
    };
    // MeshCentral's documentation shows `getAccessPermissions(user, context)` returning a checker function, but not
    // where it lives (the plugin object or the plugin handler) or whether the handler's version also takes the plugin
    // name. So the call shape is detected, and the result of every refusal is logged (see logDenied).
    obj.permissionCall = function(user, ctx) {
        if (typeof obj.getAccessPermissions == 'function') {   // attached to the plugin object by MeshCentral
            obj._permMode = 'plugin object: getAccessPermissions(user, context)';
            return Promise.resolve(obj.getAccessPermissions(user, ctx));
        }
        var hosts = [obj.parent, obj.meshServer && obj.meshServer.pluginHandler];
        for (var i = 0; i < hosts.length; i++) {
            var host = hosts[i];
            if (host == null || typeof host.getAccessPermissions != 'function') continue;
            var src = ''; try { src = Function.prototype.toString.call(host.getAccessPermissions); } catch (e) { }
            var m = src.match(/^[^(]*\(\s*([A-Za-z_$][\w$]*)/);
            var takesName = (m != null) && /^(plugin|pluginname|plugin_name|pluginid|shortname|name|id)$/i.test(m[1]);
            obj._permMode = takesName ? 'plugin handler: getAccessPermissions(pluginName, user, context)' : 'plugin handler: getAccessPermissions(user, context)';
            return Promise.resolve(takesName ? host.getAccessPermissions('eventlog', user, ctx) : host.getAccessPermissions(user, ctx));
        }
        return null;   // this MeshCentral has no permission API
    };
    obj.describePermissionApi = function() {
        if (typeof obj.getAccessPermissions == 'function') return 'getAccessPermissions on the plugin object';
        var hosts = [obj.parent, obj.meshServer && obj.meshServer.pluginHandler];
        for (var i = 0; i < hosts.length; i++) {
            if (hosts[i] != null && typeof hosts[i].getAccessPermissions == 'function') {
                var src = ''; try { src = Function.prototype.toString.call(hosts[i].getAccessPermissions).split('\n')[0].substring(0, 120); } catch (e) { }
                return 'getAccessPermissions on the plugin handler: ' + src;
            }
        }
        return 'no getAccessPermissions found';
    };
    // one line per user and permission per minute, so the reason for a refusal can be read from the server log
    obj._decisionLogged = {};
    obj.logDecision = function(granted, user, key, ctx, detail) {
        try {
            var k = (granted ? 'g|' : 'd|') + (user && user._id) + '|' + key + '|' + (ctx && ctx.nodeid), now = Date.now();
            if (obj._decisionLogged[k] != null && (now - obj._decisionLogged[k]) < (granted ? 300000 : 60000)) return;
            obj._decisionLogged[k] = now;
            console.log('EVENTLOG: permission "' + key + '" ' + (granted ? 'granted to ' : 'refused for ') + (user && (user.name || user._id)) + ' (siteadmin=' + (user && user.siteadmin) + ') on ' + (ctx && (ctx.nodeid || ctx.meshid)) + ' - ' + detail + ' [' + (obj._permMode || 'no API') + ']');
        } catch (e) { }
    };
    obj.logDenied = function(user, key, ctx, detail) { obj.logDecision(false, user, key, ctx, detail); };
    // Resolves to true / false. Fails closed. When this MeshCentral has no permission API at all, only full administrators pass.
    obj.canUse = function(user, key, ctx) {
        try {
            if (user == null) return Promise.resolve(false);
            var call = obj.permissionCall(user, ctx);
            if (call == null) {
                var admin = ((user.siteadmin >>> 0) === 0xFFFFFFFF);
                obj.logDecision(admin, user, key, ctx, 'this MeshCentral has no plugin permission API; only full administrators are allowed');
                return Promise.resolve(admin);
            }
            return call.then(function (has) {
                var allowed = false, what;
                if (typeof has == 'function') { var r = has(key); allowed = (r === true); what = 'the permission check returned ' + String(r); }
                else if (has != null && typeof has == 'object') { var r2 = (has[key] !== undefined) ? has[key] : (has.eventlog && has.eventlog[key]); allowed = (r2 === true); what = 'the permission object has ' + key + ' = ' + String(r2); }
                else what = 'getAccessPermissions returned ' + String(has);
                obj.logDecision(allowed, user, key, ctx, what);
                return allowed;
            }).catch(function (e) { obj.logDenied(user, key, ctx, 'permission check threw: ' + ((e && e.message) || e)); return false; });
        } catch (e) { obj.logDenied(user, key, ctx, 'permission check threw: ' + ((e && e.message) || e)); return Promise.resolve(false); }
    };
    // Tell the tab what this user may use on a device.
    obj.sendAccess = function(myparent, command, grandparent) {
        var ctx = { nodeid: command.nodeid, meshid: command.meshid };
        var rights = true;
        try { if (grandparent != null && typeof grandparent.GetNodeRights == 'function') rights = (grandparent.GetNodeRights(myparent.user, command.meshid, command.nodeid) != 0); } catch (e) { }
        var check = rights ? obj.canUse(myparent.user, 'deviceLiveTab', ctx) : Promise.resolve(false);
        return check.then(function (live) {
            try { myparent.ws.send(JSON.stringify({ action: 'plugin', plugin: 'eventlog', method: 'onAccess', nodeid: command.nodeid, live: live })); } catch (e) { }
        });
    };

    obj.server_startup = function() {
        if (!obj.registerPermissions()) console.log('EVENTLOG: this MeshCentral has no plugin permission API (registerPermissions); the Event Log is limited to full administrators');
        else console.log('EVENTLOG: plugin permissions registered; ' + obj.describePermissionApi());
        obj.meshServer.pluginHandler.eventlog_db = require (__dirname + '/db.js').CreateDB(obj.meshServer);
        obj.db = obj.meshServer.pluginHandler.eventlog_db;
    };

    obj.consoleaction = function() {
        // due to this code running on the client side, this hook is actually contained
        //   in the ./modules_meshcore/eventlog.js (note kept here for informational purposes)
    };

    obj.handleAdminReq = function(req, res, user) {
        require(__dirname + '/admin.js').admin(obj).req(req, res, user);
    }

    // ------------------------------------------------------------------
    //  Front end (browser) code below. Serialized into the page.
    // ------------------------------------------------------------------

    // 'windows' | 'linux' | null. Decided from the agent architecture id: on Linux, osdesc is the
    // distro pretty-name ("Ubuntu 24.04.2 LTS") and never contains "linux", so osdesc is only a
    // last-resort fallback for Windows.
    obj.elPlatform = function() {
      if ((typeof currentNode == 'undefined') || (currentNode == null)) return null;
      if (currentNode.agent != null && currentNode.agent.id != null) {
          var id = currentNode.agent.id;
          var win = [1,2,3,4,21,22,34,42,43,10003,10004,10006,11000,11001,11002];
          var lin = [5,6,7,8,9,10,12,13,15,18,19,20,24,25,26,27,28,32,33,35,36,37,40,41,45]; // 11 is macOS despite its 'linux' platform tag
          if (win.indexOf(id) >= 0) return 'windows';
          if (lin.indexOf(id) >= 0) return 'linux';
      }
      if ((typeof currentNode.osdesc == 'string') && (currentNode.osdesc.toLowerCase().indexOf('windows') !== -1)) return 'windows';
      return null;
    };
    obj.elIsSupported = function() {
      var p = pluginHandler.eventlog.elPlatform();
      return (p == 'windows' || p == 'linux');
    };
    // syslog priority name (Linux detail views keep the raw 0-7 priority next to the collapsed level)
    obj.elPriName = function(p) {
      var names = ['Emergency','Alert','Critical','Error','Warning','Notice','Info','Debug'];
      return (names[p] != null) ? names[p] : ('Priority ' + p);
    };
    // column/detail labels differ per OS: journald has categories and PIDs instead of logs and event ids
    obj.elLbl = function(key) {
      var lx = (pluginHandler.eventlog.elState().os == 'linux');
      if (key == 'log') return lx ? 'Category' : 'Log';
      if (key == 'id') return lx ? 'PID' : 'Event ID';
      if (key == 'idShort') return lx ? 'PID' : 'ID';
      return key;
    };
    // the raw event for the JSON pane / copy: full journald record when available, else the reconstructed shape
    obj.elRawOf = function(ev) {
      if (ev._raw) return ev._raw;
      return { Level: ev.level, TimeCreated: new Date(ev.time).toISOString(), LogName: ev.log, ProviderName: ev.source, Id: ev.id, Message: ev.message };
    };

    // Include/exclude rules for a config set's Categories / Sources lists. `list` is an array or a
    // comma-delimited string of names; '*' matches anything; matching is case-insensitive.
    // Returns null when the list is empty (= no filter). The agent carries an ES5 copy of this.
    obj.elRules = function(list, mode) {
        var items = Array.isArray(list) ? list : String(list == null ? '' : list).split(',');
        var res = [];
        for (var i = 0; i < items.length; i++) {
            var pt = String(items[i]).replace(/^\s+|\s+$/g, '');
            if (pt == '') continue;
            res.push(new RegExp('^' + pt.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$', 'i'));
        }
        if (res.length == 0) return null;
        return { exclude: (String(mode || 'exclude').toLowerCase() != 'include'), res: res };
    };
    obj.elAllowed = function(rules, value) {
        if (rules == null) return true;
        var v = String(value == null ? '' : value), hit = false;
        for (var i = 0; i < rules.res.length; i++) { if (rules.res[i].test(v)) { hit = true; break; } }
        return rules.exclude ? !hit : hit;
    };
    // Live view: apply the config set's Live categories (Linux) and sources (all OSes) in the browser,
    // so it works for Windows too, where the agent forwards PowerShell output as-is.
    obj.elLiveAllowed = function(ev) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        var cfg = st.cfg;
        if (cfg == null) return true;
        if (st.os == 'linux' && !ph.elAllowed(ph.elRules(cfg.liveCategories, cfg.liveCategoriesMode), ev.log)) return false;
        return ph.elAllowed(ph.elRules(cfg.liveSources, cfg.liveSourcesMode), ev.source);
    };

    // called to notify the web server that there is a new tab in town
    obj.registerPluginTab = function() {
      if (!pluginHandler.eventlog.elIsSupported()) return { tabId: null, tabTitle: null };
      return {
        tabTitle: "Event Log",
        tabId: "pluginEventLog"
      };
    };

    // called to get the content for that tabs data
    obj.on_device_page = function() {
      return '<div id=pluginEventLog></div>';
    };

    // ---- state ----
    obj.elState = function() {
        var ph = pluginHandler.eventlog;
        if (ph.st == null) {
            ph.byKey = {};
            ph.st = {
                os: ph.elPlatform(),                                 // 'windows' | 'linux' | null (state resets on node change)
                lsel: '',                                            // Linux view selector ('', kernel, auth, audit, boot)
                meta: null,                                          // {os, caps} reported by the agent / server
                layout: getstore('evl_layout', 'ledger'),           // 'ledger' | 'viewer'
                fold: (getstore('evl_fold', '1') == '1'),
                show: Number(getstore('evl_show', '100')),
                range: getstore('evl_range', '24h'),
                rows: getstore('evl_rows', 'normal'),                // 'dense' | 'normal' | 'wrap'
                cols: { ledger: ph.elLoadJson('evl_cols_ledger'), viewer: ph.elLoadJson('evl_cols_viewer') },   // user column widths (px) per layout
                sideW: Number(getstore('evl_side', '0')) || 0,          // Viewer sidebar width (px), 0 = automatic
                heights: { ledger: Number(getstore('evl_h_ledger', '0')) || 0, viewer: Number(getstore('evl_h_viewer', '0')) || 0 }, // user table height (px) per layout, 0 = automatic
                filters: { levels: null, logs: null, sources: null, ids: '', text: '' },
                sort: { key: 'time', dir: -1 },
                cfg: null,                                           // resolved config set for this node (sent by the agent with every live reply)
                selected: null, expanded: {}, dtab: 'general', raw: {},
                srcMore: false,
                paused: false, pending: [],
                live: { events: [], last: null }
            };
        }
        return ph.st;
    };

    obj.elLoadJson = function(name) {
        try { var v = getstore(name, ''); if (v) { var o = JSON.parse(v); if (o && typeof o == 'object') return o; } } catch (e) { }
        return {};
    };

    obj.elLevelInfo = function() {
        return [
            { n: 1, name: 'Critical', cls: 'crit' },
            { n: 2, name: 'Error',    cls: 'err'  },
            { n: 3, name: 'Warning',  cls: 'warn' },
            { n: 4, name: 'Info',     cls: 'info' },
            { n: 5, name: 'Verbose',  cls: 'verb' },
            { n: 0, name: 'LogAlways',cls: 'verb' }
        ];
    };

    obj.elHash = function(s) {
        var h = 5381; s = String(s);
        for (var i = 0; i < s.length; i++) { h = ((h << 5) + h + s.charCodeAt(i)) & 0x7FFFFFFF; }
        return h.toString(36);
    };

    // Repair UTF-8 text that was decoded as Latin-1 on the agent ("Ã„nderungen" -> "Änderungen").
    obj.elFixText = function(v) {
        if (v == null) return '';
        v = String(v);
        if (!/[\u00C2-\u00F4][\u0080-\u00BF]/.test(v)) return v;
        try { return decodeURIComponent(escape(v)); } catch (e) { return v; }
    };

    obj.elNormalize = function(raw) {
        try {
            if (raw == null || typeof raw != 'object') return null;
            var t = (raw.tc != null) ? raw.tc : raw.TimeCreated;
            if (Array.isArray(t)) t = t[0];
            if (typeof t == 'string') { var m = t.match(/\d+/); t = m ? m[0] : 0; }
            t = Number(t); if (isNaN(t)) t = 0;
            var lvl = Number(raw.Level); if (isNaN(lvl)) lvl = 0;
            var lvls = pluginHandler.eventlog.elLevelInfo();
            var li = null;
            for (var i in lvls) { if (lvls[i].n == lvl) li = lvls[i]; }
            if (li == null) li = { n: lvl, name: 'Level ' + lvl, cls: 'verb' };
            var ev = {
                level: lvl, levelName: li.name, levelCls: li.cls,
                time: t,
                log: pluginHandler.eventlog.elFixText(raw.LogName),
                source: pluginHandler.eventlog.elFixText(raw.ProviderName),
                id: (raw.Id == null) ? '' : String(raw.Id),
                message: pluginHandler.eventlog.elFixText(raw.Message),
                pri: (raw.Priority != null && !isNaN(Number(raw.Priority))) ? Number(raw.Priority) : null,
                unit: (raw.Unit != null) ? pluginHandler.eventlog.elFixText(raw.Unit) : '',
                transport: (raw.Transport != null) ? String(raw.Transport) : ''
            };
            ev.sig = pluginHandler.eventlog.elHash(ev.level + '|' + ev.log + '|' + ev.source + '|' + ev.id + '|' + ev.message);
            ev.key = pluginHandler.eventlog.elHash(ev.sig + '|' + ev.time);
            ev._raw = raw;   // full record for the JSON pane / copy (journald fields on Linux)
            return ev;
        } catch (e) { return null; }
    };

    obj.elFmtTime = function(ms, timeOnly) {
        if (!ms) return '-';
        var d = new Date(Number(ms));
        if (timeOnly) return d.toLocaleTimeString();
        return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
    };

    obj.elParseIds = function(str) {
        var out = [];
        String(str || '').split(',').forEach(function(part) {
            part = part.trim(); if (part == '') return;
            var m = part.match(/^(\d+)\s*-\s*(\d+)$/);
            if (m) { out.push([Number(m[1]), Number(m[2])]); }
            else if (part.match(/^\d+$/)) { out.push([Number(part), Number(part)]); }
        });
        return out;
    };

    obj.elMatch = function(ev, ignore) {
        var st = pluginHandler.eventlog.elState(), f = st.filters;
        if (ignore != 'level'  && f.levels  != null && !f.levels[ev.level])   return false;
        if (ignore != 'log'    && f.logs    != null && !f.logs[ev.log])       return false;
        if (ignore != 'source' && f.sources != null && !f.sources[ev.source]) return false;
        if (st._idRanges && st._idRanges.length) {
            var idn = Number(ev.id), ok = false;
            for (var i in st._idRanges) { if (idn >= st._idRanges[i][0] && idn <= st._idRanges[i][1]) { ok = true; break; } }
            if (!ok) return false;
        }
        if (st._cutoff && ev.time && ev.time < st._cutoff) return false;
        if (st._text) {
            var hay = (ev.message + ' ' + ev.source + ' ' + ev.log + ' ' + ev.id).toLowerCase();
            if (hay.indexOf(st._text) === -1) return false;
        }
        return true;
    };

    obj.elFiltered = function() {
        var ph = pluginHandler.eventlog, st = ph.elState();
        st._idRanges = ph.elParseIds(st.filters.ids);
        st._text = String(st.filters.text || '').trim().toLowerCase();
        var ranges = { '1h': 3600e3, '24h': 86400e3, '7d': 7 * 86400e3, '30d': 30 * 86400e3 };
        st._cutoff = ranges[st.range] ? (Date.now() - ranges[st.range]) : 0;
        var evs = st.live.events;
        var rows = [], counts = { level: {}, log: {}, source: {} };
        for (var i in evs) {
            var ev = evs[i];
            if (ph.elMatch(ev, 'level'))  { counts.level[ev.level] = (counts.level[ev.level] || 0) + 1; }
            if (ph.elMatch(ev, 'log'))    { counts.log[ev.log] = (counts.log[ev.log] || 0) + 1; }
            if (ph.elMatch(ev, 'source')) { counts.source[ev.source] = (counts.source[ev.source] || 0) + 1; }
            if (ph.elMatch(ev, null)) rows.push(ev);
        }
        var k = st.sort.key, dir = st.sort.dir;
        rows.sort(function(a, b) {
            var x = a[k], y = b[k];
            if (k == 'id') { x = Number(x); y = Number(y); }
            if (x < y) return -1 * dir;
            if (x > y) return 1 * dir;
            return (a.time < b.time) ? 1 : -1; // stable-ish secondary: newest first
        });
        st._total = evs.length;
        st._shown = rows.length;
        return { rows: rows, counts: counts };
    };

    obj.elFold = function(rows) {
        var out = [], map = {};
        for (var i in rows) {
            var ev = rows[i];
            if (map[ev.sig] == null) {
                map[ev.sig] = { ev: ev, count: 0, times: [] };
                out.push(map[ev.sig]);
            }
            map[ev.sig].count++;
            if (map[ev.sig].times.length < 24) map[ev.sig].times.push(ev.time);
        }
        return out;
    };

    // ---- rendering ----
    obj.elInjectStyles = function() {
        if (document.getElementById('evlStyles')) return;
        var css = `
#pluginEventLog {
  --evl-ink:#1c1c1c; --evl-muted:#5a6360; --evl-line:#c9c9c9; --evl-line2:#e6e6e6; --evl-bg:#fff;
  --evl-alt:#f4f6f5; --evl-hover:#e9f0f1; --evl-sel:#dbe9eb; --evl-chip:#eef1f0; --evl-input:#fff;
  --evl-acc:#1F6F78; --evl-acc-ink:#fff; --evl-ok:#1e8a4c; --evl-bline:#c9c9c9;
  --evl-crit:#8E1B1B; --evl-err:#C9352B; --evl-warn:#B86F00; --evl-info:#2E6DBF; --evl-verb:#7F8A86;
  color: var(--evl-ink);
}
body.night #pluginEventLog {
  --evl-ink:#bbbbbb; --evl-muted:#8b9591; --evl-line:#333; --evl-line2:#222; --evl-bg:#000;
  --evl-alt:#0d1110; --evl-hover:#18201f; --evl-sel:#18302f; --evl-chip:#1a1f1e; --evl-input:#111;
  --evl-acc:#5fb3bb; --evl-acc-ink:#000; --evl-ok:#3dbf7a; --evl-bline:#4a5250;
  --evl-crit:#ff7b73; --evl-err:#ff8a7e; --evl-warn:#f0b848; --evl-info:#8bb8ff; --evl-verb:#8b9591;
}
#pluginEventLog .evlMono { font-family: Consolas, "DejaVu Sans Mono", monospace; font-size: 12px; font-variant-numeric: tabular-nums; }
#pluginEventLog .evlBar { display:flex; align-items:center; gap:6px; flex-wrap:wrap; padding:2px 0 6px; }
#pluginEventLog .evlSeg { display:inline-flex; border:1px solid var(--evl-bline); border-radius:3px; overflow:hidden; }
#pluginEventLog .evlSeg button { border:0; background:var(--evl-input); color:var(--evl-muted); padding:4px 11px; cursor:pointer; font:inherit; }
#pluginEventLog .evlSeg button.on { background:var(--evl-acc); color:var(--evl-acc-ink); font-weight:bold; }
#pluginEventLog .evlSeg button:focus-visible, #pluginEventLog .evlBtn:focus-visible { outline:2px solid var(--evl-acc); outline-offset:-2px; }
#pluginEventLog input.evlIn, #pluginEventLog select.evlSel { border:1px solid var(--evl-line); background:var(--evl-input); color:var(--evl-ink); border-radius:3px; padding:4px 6px; font:inherit; max-width:240px; }
#pluginEventLog input.evlIn::placeholder { color:var(--evl-muted); }
#pluginEventLog .evlGrow { flex:1; min-width:140px; }
#pluginEventLog .evlBtn { border:1px solid var(--evl-bline); background:var(--evl-input); color:var(--evl-ink); border-radius:3px; padding:4px 9px; cursor:pointer; font:inherit; }
#pluginEventLog .evlBtn.on { background:var(--evl-acc); color:var(--evl-acc-ink); border-color:var(--evl-acc); }
#pluginEventLog .evlBtn.mini { padding:1px 7px; font-size:12px; }
#pluginEventLog .evlBtn:hover { background:var(--evl-hover); border-color:var(--evl-acc); }
#pluginEventLog .evlBtn:active { background:var(--evl-sel); transform:translateY(1px); }
#pluginEventLog .evlBtn.on:hover { border-color:var(--evl-acc); filter:brightness(1.08); }
#pluginEventLog .evlBtn.ok { color:var(--evl-ok); border-color:var(--evl-ok); }
#pluginEventLog .evlSeg button:hover:not(.on) { background:var(--evl-hover); color:var(--evl-ink); }
#pluginEventLog .evlSeg button:active:not(.on) { background:var(--evl-sel); }
#pluginEventLog .evlChip:hover { border-color:var(--evl-acc); }
#pluginEventLog .evlFacet:hover .t { color:var(--evl-acc); }
#pluginEventLog .evlDTabs button:hover:not(.on) { color:var(--evl-ink); }
#pluginEventLog .evlLink:hover { text-decoration-style:solid; }
#pluginEventLog table.evlLog th:hover { color:var(--evl-ink); }
#pluginEventLog .evlLbl { color:var(--evl-muted); }
#pluginEventLog .evlChips { display:flex; align-items:center; gap:6px; flex-wrap:wrap; padding:0 0 6px; }
#pluginEventLog .evlChip { display:inline-flex; align-items:center; gap:6px; border:1px solid var(--evl-line); border-radius:12px; padding:2px 10px 2px 8px; background:var(--evl-chip); color:var(--evl-ink); cursor:pointer; font-size:12px; }
#pluginEventLog .evlChip .sw { width:8px; height:8px; border-radius:50%; display:inline-block; }
#pluginEventLog .evlChip .n { color:var(--evl-muted); font-variant-numeric:tabular-nums; }
#pluginEventLog .evlChip.off { opacity:.45; text-decoration:line-through; }
#pluginEventLog .evlChip.filt { border-color:var(--evl-acc); background:transparent; }
#pluginEventLog .evlChip .x { color:var(--evl-muted); margin-left:2px; }
#pluginEventLog table.evlLog { width:100%; border-collapse:collapse; table-layout:fixed; }
#pluginEventLog table.evlLog th { text-align:left; font-weight:bold; color:var(--evl-muted); font-size:12px; padding:5px 8px; border-bottom:1px solid var(--evl-line); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; cursor:pointer; position:sticky; top:0; background:var(--evl-bg); z-index:1; }
#pluginEventLog .evlRz { position:absolute; top:0; right:0; width:8px; height:100%; cursor:col-resize; z-index:2; user-select:none; touch-action:none; }
#pluginEventLog .evlRz::after { content:""; position:absolute; top:25%; bottom:25%; right:3px; width:1px; background:var(--evl-line); }
#pluginEventLog .evlRz:hover::after, #pluginEventLog .evlRz.active::after { top:0; bottom:0; width:2px; right:2px; background:var(--evl-acc); }
#pluginEventLog .evlGuide { position:absolute; width:0; border-left:1px dashed var(--evl-acc); pointer-events:none; z-index:3; }
#pluginEventLog .evlGuide span { position:absolute; top:6px; left:6px; background:var(--evl-acc); color:var(--evl-acc-ink); font-size:11px; padding:1px 6px; border-radius:3px; white-space:nowrap; font-family:Consolas,"DejaVu Sans Mono",monospace; }
#pluginEventLog .evlResizing, #pluginEventLog .evlResizing * { cursor:col-resize !important; user-select:none; }
#pluginEventLog .evlResizing table.evlLog tbody tr:hover:not(.evlExpand) td { background:inherit; }
#pluginEventLog .evlGrip, #pluginEventLog .evlSplit { height:9px; cursor:row-resize; background:var(--evl-alt); border-top:1px solid var(--evl-line2); position:relative; touch-action:none; user-select:none; }
#pluginEventLog .evlSplit { height:7px; border-top:1px solid var(--evl-line); border-bottom:1px solid var(--evl-line); }
#pluginEventLog .evlGrip::after, #pluginEventLog .evlSplit::after { content:""; position:absolute; left:50%; top:3px; width:34px; height:1px; margin-left:-17px; background:var(--evl-line); box-shadow:0 2px 0 var(--evl-line); }
#pluginEventLog .evlSplit::after { top:2px; }
#pluginEventLog .evlGrip:hover, #pluginEventLog .evlGrip.active, #pluginEventLog .evlSplit:hover, #pluginEventLog .evlSplit.active { background:var(--evl-sel); }
#pluginEventLog .evlGrip:hover::after, #pluginEventLog .evlGrip.active::after, #pluginEventLog .evlSplit:hover::after, #pluginEventLog .evlSplit.active::after { background:var(--evl-acc); box-shadow:0 2px 0 var(--evl-acc); }
#pluginEventLog .evlDense table.evlLog tr:not(.evlExpand) td { padding:1px 8px; font-size:12px; }
#pluginEventLog .evlDense table.evlLog th { padding:3px 8px; }
#pluginEventLog .evlWrap table.evlLog tr:not(.evlExpand) td { white-space:normal; word-break:break-word; }
#pluginEventLog .evlWrap table.evlLog tr:not(.evlExpand) td.evlCLv, #pluginEventLog .evlWrap table.evlLog tr:not(.evlExpand) td.evlCTm, #pluginEventLog .evlWrap table.evlLog tr:not(.evlExpand) td.evlCId { white-space:nowrap; }
#pluginEventLog .evlLink { color:var(--evl-acc); cursor:pointer; text-decoration:underline dotted; }
#pluginEventLog table.evlLog th.sorted { color:var(--evl-ink); }
#pluginEventLog table.evlLog td.evlCId { text-align:right; }
#pluginEventLog table.evlLog td { padding:4px 8px; border-bottom:1px solid var(--evl-line2); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; vertical-align:top; }
#pluginEventLog table.evlLog tbody tr { cursor:pointer; }
#pluginEventLog table.evlLog tbody tr:nth-child(even):not(.evlExpand) td { background:var(--evl-alt); }
#pluginEventLog table.evlLog tbody tr:hover:not(.evlExpand) td { background:var(--evl-hover); }
#pluginEventLog table.evlLog tr.evlSelRow td { background:var(--evl-sel) !important; }
#pluginEventLog .evlLv { display:inline-flex; align-items:center; gap:6px; font-weight:bold; }
#pluginEventLog .evlLv i { width:9px; height:9px; border-radius:50%; display:inline-block; flex:none; }
#pluginEventLog .evlLv.crit { color:var(--evl-crit); } #pluginEventLog .evlLv.crit i { background:var(--evl-crit); }
#pluginEventLog .evlLv.err  { color:var(--evl-err);  } #pluginEventLog .evlLv.err i  { background:var(--evl-err); }
#pluginEventLog .evlLv.warn { color:var(--evl-warn); } #pluginEventLog .evlLv.warn i { background:var(--evl-warn); }
#pluginEventLog .evlLv.info { color:var(--evl-info); } #pluginEventLog .evlLv.info i { background:var(--evl-info); }
#pluginEventLog .evlLv.verb { color:var(--evl-verb); } #pluginEventLog .evlLv.verb i { background:var(--evl-verb); }
#pluginEventLog .evlRep { display:inline-block; border:1px solid var(--evl-line); border-radius:10px; padding:0 7px; font-size:11px; color:var(--evl-muted); background:var(--evl-chip); margin-right:6px; }
#pluginEventLog .evlRep b { color:var(--evl-ink); }
#pluginEventLog tr.evlExpand td { white-space:normal; background:var(--evl-sel) !important; padding:10px 12px 12px 32px; cursor:default; }
#pluginEventLog .evlMsgFull { white-space:pre-wrap; max-width:110ch; line-height:1.45; }
#pluginEventLog .evlMeta { display:flex; gap:20px; color:var(--evl-muted); margin-top:8px; flex-wrap:wrap; }
#pluginEventLog .evlMeta b { color:var(--evl-ink); }
#pluginEventLog .evlActs { margin-top:9px; display:flex; gap:7px; flex-wrap:wrap; }
#pluginEventLog pre.evlRaw { background:var(--evl-chip); border:1px solid var(--evl-line2); padding:8px; overflow:auto; max-height:240px; margin:8px 0 0; font-size:11px; color:var(--evl-ink); white-space:pre-wrap; word-break:break-word; }
#pluginEventLog .evlStatus { display:flex; gap:16px; color:var(--evl-muted); font-size:12px; padding:7px 2px; align-items:center; flex-wrap:wrap; border-top:1px solid var(--evl-line2); margin-top:-1px; }
#pluginEventLog .evlStatus .live { color:var(--evl-ok); }
#pluginEventLog .evlStatus .warn { color:var(--evl-warn); }
#pluginEventLog .evlViewer { display:grid; grid-template-columns:var(--evl-side, 215px) 7px minmax(0, 1fr); border:1px solid var(--evl-line); border-radius:3px; overflow:hidden; }
#pluginEventLog .evlFacets { padding:9px 11px; background:var(--evl-alt); min-width:0; overflow-x:hidden; overflow-y:auto; contain:size; }
#pluginEventLog .evlVSplit { cursor:col-resize; background:var(--evl-alt); border-right:1px solid var(--evl-line); position:relative; touch-action:none; user-select:none; }
#pluginEventLog .evlVSplit::after { content:""; position:absolute; top:50%; left:2px; height:34px; width:1px; margin-top:-17px; background:var(--evl-line); box-shadow:2px 0 0 var(--evl-line); }
#pluginEventLog .evlVSplit:hover, #pluginEventLog .evlVSplit.active { background:var(--evl-sel); }
#pluginEventLog .evlVSplit:hover::after, #pluginEventLog .evlVSplit.active::after { background:var(--evl-acc); box-shadow:2px 0 0 var(--evl-acc); }
#pluginEventLog .evlFacets h4 { margin:11px 0 5px; font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--evl-muted); }
#pluginEventLog .evlFacets h4:first-child { margin-top:0; }
#pluginEventLog .evlFacet { display:flex; align-items:center; gap:7px; padding:2px 0; cursor:pointer; }
#pluginEventLog .evlFacet .cb { width:12px; height:12px; border:1px solid var(--evl-line); border-radius:2px; background:var(--evl-input); flex:none; display:inline-grid; place-items:center; font-size:9px; color:var(--evl-acc-ink); line-height:1; }
#pluginEventLog .evlFacet .cb.on { background:var(--evl-acc); border-color:var(--evl-acc); }
#pluginEventLog .evlFacet .t { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
#pluginEventLog .evlFacet .n { margin-left:auto; color:var(--evl-muted); font-variant-numeric:tabular-nums; font-size:12px; }
#pluginEventLog .evlMore { color:var(--evl-acc); font-size:12px; cursor:pointer; display:inline-block; margin-top:3px; }
#pluginEventLog .evlScroll { overflow:auto; max-height:calc(100vh - 270px); min-height:160px; position:relative; }
#pluginEventLog .evlVList { overflow:auto; max-height:max(200px, calc(100vh - 520px)); outline:none; position:relative; }
#pluginEventLog .evlVList table.evlLog th { top:0; }
#pluginEventLog .evlDetails { border-top:1px solid var(--evl-line); max-height:40vh; overflow:auto; }
#pluginEventLog .evlDTabs { display:flex; align-items:center; border-bottom:1px solid var(--evl-line); background:var(--evl-alt); }
#pluginEventLog .evlDTabs button { border:0; background:none; color:var(--evl-muted); padding:6px 14px; cursor:pointer; font:inherit; }
#pluginEventLog .evlDTabs button.on { color:var(--evl-ink); font-weight:bold; border-bottom:2px solid var(--evl-acc); margin-bottom:-1px; }
#pluginEventLog .evlDTabs .sp { flex:1; }
#pluginEventLog .evlDBody { display:grid; grid-template-columns:1fr 320px; gap:16px; padding:11px 13px; }
#pluginEventLog .evlKv { display:grid; grid-template-columns:auto 1fr; gap:3px 13px; font-size:12px; align-content:start; margin:0; }
#pluginEventLog .evlKv dt { color:var(--evl-muted); } #pluginEventLog .evlKv dd { margin:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
#pluginEventLog .evlEmpty { padding:26px 10px; color:var(--evl-muted); text-align:center; }
@media (max-width: 1000px) {
  #pluginEventLog .evlViewer { grid-template-columns:1fr; }
  #pluginEventLog .evlVSplit { display:none; }
  #pluginEventLog .evlFacets { border-bottom:1px solid var(--evl-line); contain:none; max-height:30vh; }
  #pluginEventLog .evlDBody { grid-template-columns:1fr; }
}
`;
        var s = document.createElement('style');
        s.id = 'evlStyles';
        s.appendChild(document.createTextNode(css));
        document.head.appendChild(s);
    };

    // ---- Plugin permissions (browser side) ----------------------------------------------------
    // The server decides (MeshCentral's plugin permissions: deviceLiveTab). The tab only asks
    // once per device and shows or hides its views accordingly. Until the answer arrives nothing is shown or started.
    obj.elCan = function(what) {
        var a = pluginHandler.eventlog.elAccess;
        return (a != null && typeof currentNode != 'undefined' && currentNode != null && a.nodeid == currentNode._id && a[what] === true);
    };
    obj.elRequestAccess = function() {
        var ph = pluginHandler.eventlog;
        if (typeof currentNode == 'undefined' || currentNode == null) return;
        var now = Date.now(), asked = ph._accessAsked;
        if (asked != null && asked.nodeid == currentNode._id && (now - asked.t) < 5000) return;   // one request per device and 5 s
        ph._accessAsked = { nodeid: currentNode._id, t: now };
        meshserver.send({ action: 'plugin', plugin: 'eventlog', pluginaction: 'checkAccess', nodeid: currentNode._id, meshid: currentNode.meshid });
    };
    obj.elRecheckAccess = function() {   // "Check again" in the notice: pick up a permission granted a moment ago
        var ph = pluginHandler.eventlog;
        ph._accessAsked = null; ph.elAccess = null;
        ph.elAccessGate();
        return false;
    };
    // true when the tab may be drawn; otherwise draws a notice in its place
    obj.elAccessGate = function() {
        var ph = pluginHandler.eventlog;
        if (!Q('pluginEventLog')) return false;
        var a = ph.elAccess, known = (a != null && typeof currentNode != 'undefined' && currentNode != null && a.nodeid == currentNode._id);
        if (known && a.live) {
            if (Q('evlNotice')) QH('pluginEventLog', '');   // permission was granted since the notice was drawn
            return true;
        }
        var key = known ? 'denied' : 'checking';
        if (!Q('evlNotice') || Q('evlNotice').getAttribute('data-k') != key) {
            QH('pluginEventLog', '<div id=evlNotice data-k=' + key + ' style="padding:18px 14px;opacity:.85">' +
                (known ? 'You do not have permission to use the Event Log for this device. Ask a MeshCentral administrator to grant it in the permissions dialog. <a href=# onclick="return pluginHandler.eventlog.elRecheckAccess()">Check again</a>'
                       : 'Checking permissions&hellip;') + '</div>');
        }
        if (!known) ph.elRequestAccess();
        return false;
    };
    obj.onAccess = function(server, message) {
        var ph = pluginHandler.eventlog, prev = ph.elAccess;
        ph.elAccess = { nodeid: message.nodeid, live: (message.live === true) };
        if (typeof currentNode == 'undefined' || currentNode == null || currentNode._id != message.nodeid) return;
        if (prev != null && prev.nodeid == ph.elAccess.nodeid && prev.live == ph.elAccess.live && (Q('evlWrap') || Q('evlNotice'))) return;   // nothing changed: keep the tab as it is
        if (!ph.elAccess.live) ph.elStopLive();
        if (Q('evlWrap')) QH('pluginEventLog', '');   // rebuild the shell with the views this user may use
        ph.elEnsureShell();
        setTimeout(function() { try { pluginHandler.eventlog.elEnsureLive(); } catch (e) { } }, 0);
    };

    obj.elEnsureShell = function() {
        var ph = pluginHandler.eventlog;
        ph.elInjectStyles();
        if (!Q('pluginEventLog')) return false;
        if (!ph.elAccessGate()) return false;
        if (!Q('evlWrap')) {
            QH('pluginEventLog', '<div id=evlWrap><div id=evlToolbar></div><div id=evlChips class=evlChips></div><div id=evlBody></div><div id=evlStatus class=evlStatus></div></div>');
            ph.elRenderShell();
        }
        ph.elFitHeight();   // the tab may have been hidden during the last render
        if (!ph._fitBound) { ph._fitBound = true; window.addEventListener('resize', function() { pluginHandler.eventlog.elFitHeight(); }); }
        return true;
    };

    obj.elRenderShell = function() {
        var ph = pluginHandler.eventlog, st = ph.elState();
        var esc = EscapeHtml;
        var h = '<div class=evlBar>';
        if (st.os == 'linux') {
            h += '<span class=evlLbl>View</span> <select id=evlLxSel class=evlSel title="Log view - queried from journalctl directly (Kernel = -k, Security = auth facilities, This boot = -b)" onchange="return pluginHandler.eventlog.elSelCat(this.value)">';
            [['','All'],['kernel','Kernel'],['auth','Security (auth)'],['audit','Audit'],['boot','This boot']].forEach(function(o){ h += '<option value="' + o[0] + '"' + (st.lsel == o[0] ? ' selected' : '') + '>' + o[1] + '</option>'; });
            h += '</select>';
        }
        if (st.layout == 'ledger') {
            h += '<span class=evlLbl>' + ph.elLbl('log') + '</span> <select id=evlLogSel class=evlSel onchange="return pluginHandler.eventlog.elSelLog(this)"><option value="">All</option></select>';
            h += '<span class=evlLbl>Source</span> <select id=evlSrcSel class=evlSel onchange="return pluginHandler.eventlog.elSelSource(this)"><option value="">All</option></select>';
        }
        h += '<input id=evlIdIn class=evlIn style=width:120px placeholder="IDs: 1112, 100-199" value="' + esc(st.filters.ids) + '" oninput="return pluginHandler.eventlog.elIdInput(this)">';
        h += '<input id=evlTxtIn class="evlIn evlGrow" placeholder="Search message, source, ID&hellip;" value="' + esc(st.filters.text) + '" oninput="return pluginHandler.eventlog.elTextInput(this)">';
        h += '<select id=evlRangeSel class=evlSel title="Time range" onchange="return pluginHandler.eventlog.elSetRange(this.value)">';
        [['all','Any time'],['1h','Last hour'],['24h','Last 24 h'],['7d','Last 7 days'],['30d','Last 30 days']].forEach(function(o){ h += '<option value=' + o[0] + (st.range == o[0] ? ' selected' : '') + '>' + o[1] + '</option>'; });
        h += '</select>';
        h += '<span class=evlLbl>Show</span> <select id=evlShowSel class=evlSel title="Entries per log" onchange="return pluginHandler.eventlog.elSetShow(this.value)">';
        [10,15,25,50,100,250,500].forEach(function(n){ h += '<option value=' + n + (st.show == n ? ' selected' : '') + '>' + n + '</option>'; });
        h += '</select>';
        h += '<span class=evlLbl>Rows</span> <select id=evlRowsSel class=evlSel title="Row density: Compact (tight), Normal, Wrap (message text wraps onto several lines)" onchange="return pluginHandler.eventlog.elSetRows(this.value)">';
        [['dense','Compact'],['normal','Normal'],['wrap','Wrap']].forEach(function(o){ h += '<option value=' + o[0] + (st.rows == o[0] ? ' selected' : '') + '>' + o[1] + '</option>'; });
        h += '</select>';
        h += '<button id=evlFoldBtn class="evlBtn ' + (st.fold ? 'on' : '') + '" title="Fold repeated events into one line" onclick="return pluginHandler.eventlog.elToggleFold()">&#8659; Fold repeats</button>';
        h += '<button id=evlPauseBtn class=evlBtn title="Pause live updates" onclick="return pluginHandler.eventlog.elTogglePause()">' + (st.paused ? '&#9654;' : '&#10074;&#10074;') + '</button>';
        h += '<button class=evlBtn title="Refresh" onclick="return pluginHandler.eventlog.elRefresh()">&#8635;</button>';
        h += '<button class=evlBtn title="Export the filtered rows as CSV" onclick="return pluginHandler.eventlog.elExportCsv()">&#10515; CSV</button>';
        h += '<div class=evlSeg title="Layout">' +
             '<button class="' + (st.layout == 'ledger' ? 'on' : '') + '" onclick="return pluginHandler.eventlog.elSetLayout(\'ledger\')">Table</button>' +
             '<button class="' + (st.layout == 'viewer' ? 'on' : '') + '" onclick="return pluginHandler.eventlog.elSetLayout(\'viewer\')">Viewer</button></div>';
        h += '</div>';
        QH('evlToolbar', h);
        ph.elUpdate();
    };

    obj.elUpdate = function() {
        var ph = pluginHandler.eventlog, st = ph.elState();
        if (!Q('evlWrap')) return;
        var fr = ph.elFiltered();
        ph.elRenderChips(fr);
        ph.elRenderBody(fr);
        ph.elRenderStatus();
        // refresh the Log/Source dropdown options (ledger layout)
        if (st.layout == 'ledger') {
            var esc = EscapeHtml;
            var counts = fr.counts;
            [['evlLogSel', 'log', st.filters.logs], ['evlSrcSel', 'source', st.filters.sources]].forEach(function(cfg) {
                var sel = Q(cfg[0]); if (!sel) return;
                var names = Object.keys(counts[cfg[1]]).sort();
                var cur = null;
                if (cfg[2] != null) { var kk = Object.keys(cfg[2]); if (kk.length == 1) cur = kk[0]; else cur = '_multi'; }
                var oh = '<option value="">All (' + names.length + ')</option>';
                if (cur == '_multi') oh += '<option value="_multi" selected>(multiple)</option>';
                names.forEach(function(n) { oh += '<option value="' + esc(n) + '"' + (cur == n ? ' selected' : '') + '>' + esc(n) + ' (' + counts[cfg[1]][n] + ')</option>'; });
                sel.innerHTML = oh;
            });
        }
    };

    obj.elRenderChips = function(fr) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        var esc = EscapeHtml, h = '';
        var counts = fr.counts;
        h += '<span class=evlLbl>Level</span>';
        ph.elLevelInfo().forEach(function(li) {
            if (li.n == 0 && !counts.level[0]) return; // hide LogAlways unless present
            var off = (st.filters.levels != null && !st.filters.levels[li.n]);
            h += '<span class="evlChip' + (off ? ' off' : '') + '" role=button tabindex=0 onclick="return pluginHandler.eventlog.elToggleLevel(' + li.n + ')" onkeypress="if(event.key==\'Enter\')pluginHandler.eventlog.elToggleLevel(' + li.n + ')">' +
                 '<i class=sw style="background:var(--evl-' + li.cls + ')"></i>' + li.name + ' <span class=n>' + (counts.level[li.n] || 0) + '</span></span>';
        });
        var filts = [];
        if (st.filters.logs != null)    { var k1 = Object.keys(st.filters.logs);    filts.push(['logs',    'Log: '    + (k1.length == 1 ? esc(k1[0]) : k1.length + ' selected')]); }
        if (st.filters.sources != null) { var k2 = Object.keys(st.filters.sources); filts.push(['sources', 'Source: ' + (k2.length == 1 ? esc(k2[0]) : k2.length + ' selected')]); }
        if (String(st.filters.ids).trim()  != '') filts.push(['ids',  'ID: '     + esc(st.filters.ids)]);
        if (String(st.filters.text).trim() != '') filts.push(['text', 'Search: ' + esc(st.filters.text)]);
        if (filts.length) {
            h += '<span class=evlLbl style=margin-left:12px>Active</span>';
            filts.forEach(function(f) {
                h += '<span class="evlChip filt" role=button tabindex=0 onclick="return pluginHandler.eventlog.elClearFilter(\'' + f[0] + '\')">' + f[1] + ' <span class=x>&#10005;</span></span>';
            });
            h += '<span class="evlChip" role=button tabindex=0 onclick="return pluginHandler.eventlog.elResetFilters()">Reset all</span>';
        }
        QH('evlChips', h);
    };

    obj.elRenderFacets = function(fr) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        var esc = EscapeHtml, h = '';
        var facet = function(kind, name, count, on) {
            return '<div class=evlFacet role=button tabindex=0 onclick="return pluginHandler.eventlog.elToggleFacet(\'' + kind + '\',\'' + esc(name).replace(/'/g, '&apos;') + '\')">' +
                   '<span class="cb' + (on ? ' on' : '') + '">' + (on ? '&#10003;' : '') + '</span><span class=t title="' + esc(name) + '">' + esc(name) + '</span><span class=n>' + count + '</span></div>';
        };
        var counts = fr.counts;
        h += '<h4>' + ph.elLbl('log') + '</h4>';
        Object.keys(counts.log).sort().forEach(function(n) {
            h += facet('logs', n, counts.log[n], (st.filters.logs == null || st.filters.logs[n]));
        });
        h += '<h4>Source</h4>';
        var srcs = Object.keys(counts.source).sort(function(a, b) { return counts.source[b] - counts.source[a]; });
        var lim = st.srcMore ? srcs.length : 10;
        srcs.slice(0, lim).forEach(function(n) {
            h += facet('sources', n, counts.source[n], (st.filters.sources == null || st.filters.sources[n]));
        });
        if (srcs.length > 10) h += '<span class=evlMore role=button tabindex=0 onclick="return pluginHandler.eventlog.elFacetsMore()">' + (st.srcMore ? 'show fewer' : 'show ' + (srcs.length - 10) + ' more&hellip;') + '</span>';
        return h;
    };

    obj.elRenderBody = function(fr) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        var esc = EscapeHtml;
        var frows = st.fold ? ph.elFold(fr.rows) : fr.rows.map(function(ev) { return { ev: ev, count: 1, times: [ev.time] }; });
        st._matching = frows.length;
        if (frows.length > st.show) frows = frows.slice(0, st.show); // "Show N" = N displayed rows
        st._visible = frows.length;
        var sortTh = function(key, label) {
            var s = (st.sort.key == key) ? (' class=sorted') : '';
            var ar = (st.sort.key == key) ? (st.sort.dir == -1 ? ' &#9660;' : ' &#9650;') : '';
            var w = ph.elColW(key);
            var rz = (key != 'message') ? '<span class=evlRz title="Drag to resize &middot; double-click to fit" onpointerdown="return pluginHandler.eventlog.elRzDown(event,\'' + key + '\')" ondblclick="return pluginHandler.eventlog.elRzFit(event,\'' + key + '\')" onclick="event.stopPropagation();return false"></span>' : '';
            return '<th' + (w ? ' style=width:' + w + 'px' : '') + s + ' onclick="return pluginHandler.eventlog.elSetSort(\'' + key + '\')">' + label + ar + rz + '</th>';
        };
        var dens = (st.rows == 'dense') ? ' evlDense' : (st.rows == 'wrap') ? ' evlWrap' : '';
        var hstyle = st.heights[st.layout] ? ' style="height:' + st.heights[st.layout] + 'px;max-height:none;min-height:0"' : '';
        var rowHtml = function(r, mode) {
            var ev = r.ev;
            var selCls = (mode == 'viewer' && st.selected == ev.key) || (mode == 'ledger' && st.expanded[ev.key]) ? ' class=evlSelRow' : '';
            var rep = (r.count > 1) ? '<span class=evlRep title="Identical event repeated"><b>&times;' + r.count + '</b></span>' : '';
            var h = '<tr' + selCls + ' onclick="return pluginHandler.eventlog.elRowClick(\'' + ev.key + '\')">';
            h += '<td class=evlCLv><span class="evlLv ' + ev.levelCls + '"><i></i>' + esc(ev.levelName) + '</span></td>';
            h += '<td class="evlCTm evlMono">' + ph.elFmtTime(ev.time) + '</td>';
            if (mode == 'ledger') h += '<td class=evlCLog title="' + esc(ev.log) + '">' + esc(ev.log) + '</td>';
            h += '<td class=evlCSrc title="' + esc(ev.source) + '">' + esc(ev.source) + '</td>';
            h += '<td class="evlCId evlMono">' + esc(ev.id) + '</td>';
            h += '<td class=evlCMsg title="' + esc(ev.message).substring(0, 500) + '">' + rep + esc(ev.message) + '</td></tr>';
            if (mode == 'ledger' && st.expanded[ev.key]) {
                h += '<tr class=evlExpand onclick="event.stopPropagation()"><td colspan=6>' + ph.elRenderDetailHtml(r) + '</td></tr>';
            }
            return h;
        };
        var h = '';
        if (st.layout == 'viewer') {
            h += '<div class=evlViewer id=evlViewer' + (st.sideW ? ' style="--evl-side:' + st.sideW + 'px"' : '') + '><div class=evlFacets id=evlFacets>' + ph.elRenderFacets(fr) + '</div>';
            h += '<div class=evlVSplit title="Drag to change the sidebar width &middot; double-click to reset" onpointerdown="return pluginHandler.eventlog.elVSplitDown(event)" ondblclick="return pluginHandler.eventlog.elVSplitReset()"></div>';
            h += '<div><div class="evlVList' + dens + '" id=evlVList tabindex=0' + hstyle + ' onkeydown="return pluginHandler.eventlog.elKeyNav(event)"><table class=evlLog><thead><tr>' +
                 sortTh('level', 'Level') + sortTh('time', 'Time') + sortTh('source', 'Source') + sortTh('id', ph.elLbl('idShort')) + sortTh('message', 'Message') +
                 '</tr></thead><tbody>';
            var selRep = null;
            frows.forEach(function(r) { h += rowHtml(r, 'viewer'); if (st.selected == r.ev.key) selRep = r; });
            if (!frows.length) h += '<tr><td colspan=5><div class=evlEmpty>' + ph.elEmptyText() + '</div></td></tr>';
            h += '</tbody></table></div>';
            h += '<div class=evlSplit title="Drag to change the list height &middot; double-click to reset" onpointerdown="return pluginHandler.eventlog.elGripDown(event,\'evlVList\')" ondblclick="return pluginHandler.eventlog.elGripReset()"></div>';
            if (selRep == null && frows.length) { selRep = frows[0]; st.selected = selRep.ev.key; }
            h += '<div class=evlDetails id=evlDetails>';
            if (selRep) {
                h += '<div class=evlDTabs>' +
                     '<button class="' + (st.dtab == 'general' ? 'on' : '') + '" onclick="return pluginHandler.eventlog.elSetDTab(\'general\')">General</button>' +
                     '<button class="' + (st.dtab == 'json' ? 'on' : '') + '" onclick="return pluginHandler.eventlog.elSetDTab(\'json\')">Details (JSON)</button><span class=sp></span>' +
                     '<button class="evlBtn mini" style=margin:4px title="' + (st.dtab == 'json' ? 'Copy the JSON shown below' : 'Copy this event as text (log, source, date, ID, level, message)') + '" onclick="return pluginHandler.eventlog.elCopy(\'' + selRep.ev.key + '\',\'' + (st.dtab == 'json' ? 'json' : 'details') + '\',this)">Copy</button>' +
                     '<button class="evlBtn mini" style=margin:4px onclick="return pluginHandler.eventlog.elFilterBy(\'source\',\'' + selRep.ev.key + '\')">Filter: this source</button>' +
                     '<button class="evlBtn mini" style=margin:4px onclick="return pluginHandler.eventlog.elFilterBy(\'id\',\'' + selRep.ev.key + '\')">Filter: ID ' + esc(selRep.ev.id) + '</button></div>';
                if (st.dtab == 'json') {
                    h += '<pre class=evlRaw style="margin:10px 13px">' + esc(JSON.stringify(ph.elRawOf(selRep.ev), null, 2)) + '</pre>';
                } else {
                    h += '<div class=evlDBody><div class=evlMsgFull>' + esc(selRep.ev.message) + '</div><dl class=evlKv>' +
                         '<dt>' + ph.elLbl('log') + '</dt><dd>' + esc(selRep.ev.log) + '</dd><dt>Source</dt><dd title="' + esc(selRep.ev.source) + '">' + esc(selRep.ev.source) + '</dd>' +
                         '<dt>' + ph.elLbl('id') + '</dt><dd class=evlMono>' + esc(selRep.ev.id) + '</dd><dt>Level</dt><dd>' + esc(selRep.ev.levelName) + ' (' + selRep.ev.level + ')</dd>' +
                         (selRep.ev.unit ? '<dt>Unit</dt><dd title="' + esc(selRep.ev.unit) + '">' + esc(selRep.ev.unit) + '</dd>' : '') +
                         (selRep.ev.pri != null ? '<dt>Priority</dt><dd>' + esc(ph.elPriName(selRep.ev.pri)) + ' (' + selRep.ev.pri + ')</dd>' : '') +
                         '<dt>Recorded</dt><dd class=evlMono>' + ph.elFmtTime(selRep.ev.time) + '</dd>' +
                         (selRep.count > 1 ? '<dt>Seen</dt><dd>' + selRep.count + '&times; &mdash; ' + selRep.times.slice(0, 6).map(function(t) { return ph.elFmtTime(t, true); }).join(', ') + (selRep.times.length > 6 ? '&hellip;' : '') + '</dd>' : '') +
                         '</dl></div>';
                }
            } else { h += '<div class=evlEmpty>Select an event to see its details.</div>'; }
            h += '</div></div></div>';
        } else {
            h += '<div class="evlScroll' + dens + '" id=evlScroll' + hstyle + '><table class=evlLog><thead><tr>' +
                 sortTh('level', 'Level') + sortTh('time', 'Time') + sortTh('log', ph.elLbl('log')) + sortTh('source', 'Source') + sortTh('id', ph.elLbl('id')) + sortTh('message', 'Message') +
                 '</tr></thead><tbody>';
            frows.forEach(function(r) { h += rowHtml(r, 'ledger'); });
            if (!frows.length) h += '<tr><td colspan=6><div class=evlEmpty>' + ph.elEmptyText() + '</div></td></tr>';
            h += '</tbody></table></div>';
            h += '<div class=evlGrip title="Drag to change the table height &middot; double-click to reset" onpointerdown="return pluginHandler.eventlog.elGripDown(event,\'evlScroll\')" ondblclick="return pluginHandler.eventlog.elGripReset()"></div>';
        }
        QH('evlBody', h);
        ph.elFitHeight();
    };

    obj.elEmptyText = function() {
        var st = pluginHandler.eventlog.elState();
        if (st._total == 0) return 'Waiting for events from the device&hellip;';
        return 'No events match the current filters. Adjust the filters above or reset them.';
    };

    obj.elRenderDetailHtml = function(r) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        var esc = EscapeHtml, ev = r.ev;
        var h = '<div class=evlMsgFull>' + esc(ev.message) + '</div>';
        h += '<div class=evlMeta><span>' + ph.elLbl('log') + ' <b>' + esc(ev.log) + '</b></span><span>Source <b>' + esc(ev.source) + '</b></span>' +
             '<span>' + ph.elLbl('id') + ' <b class=evlMono>' + esc(ev.id) + '</b></span><span>Level <b>' + esc(ev.levelName) + ' (' + ev.level + ')</b></span>' +
             (ev.unit ? '<span>Unit <b>' + esc(ev.unit) + '</b></span>' : '') +
             (ev.pri != null ? '<span>Priority <b>' + esc(ph.elPriName(ev.pri)) + ' (' + ev.pri + ')</b></span>' : '') +
             '<span>Recorded <b class=evlMono>' + ph.elFmtTime(ev.time) + '</b></span></div>';
        if (r.count > 1) {
            h += '<div class=evlMeta><span>Occurrences (' + r.count + ')</span><span class=evlMono>' + r.times.slice(0, 12).map(function(t) { return ph.elFmtTime(t, true); }).join(' &middot; ') + (r.times.length > 12 ? ' &hellip;' : '') + '</span></div>';
        }
        h += '<div class=evlActs>' +
             '<button class="evlBtn mini" title="Copy this event as text (log, source, date, ID, level, message)" onclick="return pluginHandler.eventlog.elCopy(\'' + ev.key + '\',\'details\',this)">Copy details</button>' +
             '<button class="evlBtn mini" title="Copy only the message text" onclick="return pluginHandler.eventlog.elCopy(\'' + ev.key + '\',\'message\',this)">Copy message</button>' +
             '<button class="evlBtn mini" onclick="return pluginHandler.eventlog.elFilterBy(\'source\',\'' + ev.key + '\')">Filter: this source</button>' +
             '<button class="evlBtn mini" onclick="return pluginHandler.eventlog.elFilterBy(\'id\',\'' + ev.key + '\')">Filter: ID ' + esc(ev.id) + '</button>' +
             '<button class="evlBtn mini" onclick="return pluginHandler.eventlog.elToggleRaw(\'' + ev.key + '\')">' + (st.raw[ev.key] ? 'Hide' : 'Show') + ' raw JSON</button></div>';
        if (st.raw[ev.key]) {
            h += '<pre class=evlRaw>' + esc(JSON.stringify(ph.elRawOf(ev), null, 2)) + '</pre>';
        }
        return h;
    };

    obj.elRenderStatus = function() {
        var ph = pluginHandler.eventlog, st = ph.elState();
        if (!Q('evlStatus')) return;
        var h = '';
        if (ph.livelog == null) h += '<span class=warn>&#9679; Agent not connected &mdash; live view resumes when it reconnects</span>';
        else if (st.paused) h += '<span class=warn>&#10074;&#10074; Paused' + (st.pending.length ? ' &middot; ' + st.pending.length + ' new buffered' : '') + '</span>';
        else h += '<span class=live>&#9679; Live &middot; auto-refresh every 30 s</span>';
        h += '<span>Showing ' + (st._visible || 0) + ' of ' + (st._matching || 0) + (st.fold ? ' folded rows' : ' rows') + ' &middot; ' + st._total + ' events loaded' + (st._total - st._shown > 0 ? ' &middot; ' + (st._total - st._shown) + ' hidden by filters' : '') + '</span>';
        if (st.live.last) h += '<span>Last update <span class=evlMono>' + st.live.last.toLocaleTimeString() + '</span></span>';
        if (st.os == 'linux' && st.meta && st.meta.caps) {
            if (st.meta.caps.journalctl === false) h += '<span class=warn>systemd-journald not found on this device &mdash; flat-file /var/log support arrives in a later plugin version</span>';
            else if (st.meta.caps.persistent === false) h += '<span title="The journal is stored in memory only (/run/log/journal).">Volatile journal: the endpoint keeps logs since its last boot only</span>';
        }
        var parts = [];
        if (Object.keys(st.cols[st.layout] || {}).length > 0) parts.push('column widths');
        if (st.heights[st.layout]) parts.push('height');
        if (st.layout == 'viewer' && st.sideW) parts.push('sidebar width');
        if (parts.length) h += '<span class=evlLink title="Back to the automatic sizes" onclick="return pluginHandler.eventlog.elResetSizes()">Reset ' + (parts.length > 2 ? 'sizes' : parts.join(' &amp; ')) + '</span>';
        QH('evlStatus', h);
        ph.elFitHeight();
    };

    // ---- interactions ----
    obj.elSetLayout = function(l) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        st.layout = l; putstore('evl_layout', l);
        ph.elRenderShell();
        return false;
    };
    obj.elToggleFold = function() {
        var ph = pluginHandler.eventlog, st = ph.elState();
        st.fold = !st.fold; putstore('evl_fold', st.fold ? '1' : '0');
        var b = Q('evlFoldBtn'); if (b) b.classList.toggle('on', st.fold);
        if (st.fold) ph.elRequestLive(null);
        ph.elUpdate();
        return false;
    };
    obj.elSetShow = function(n) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        st.show = Number(n) || 100; putstore('evl_show', String(st.show));
        ph.elRequestLive(null);
        ph.elUpdate();
        return false;
    };
    obj.elSetRange = function(r) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        st.range = r; putstore('evl_range', r);
        ph.elUpdate();
        return false;
    };
    // Linux view selector: in Live view the selection is pushed down to journalctl; in both views
    // it also drives the client-side Category filter so the table follows immediately.
    obj.elSelCat = function(v) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        st.lsel = v;
        var catMap = { kernel: 'Kernel', auth: 'Auth', audit: 'Audit' };
        if (catMap[v]) { st.filters.logs = {}; st.filters.logs[catMap[v]] = 1; } else { st.filters.logs = null; }
        ph.elRequestLive(null);
        ph.elUpdate();
        return false;
    };
    obj.elSelLog = function(el) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        if (el.value == '_multi') return false;
        if (el.value == '') st.filters.logs = null; else { st.filters.logs = {}; st.filters.logs[el.value] = 1; }
        ph.elUpdate();
        return false;
    };
    obj.elSelSource = function(el) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        if (el.value == '_multi') return false;
        if (el.value == '') st.filters.sources = null; else { st.filters.sources = {}; st.filters.sources[el.value] = 1; }
        ph.elUpdate();
        return false;
    };
    obj.elToggleLevel = function(n) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        if (st.filters.levels == null) { st.filters.levels = {}; ph.elLevelInfo().forEach(function(li) { st.filters.levels[li.n] = 1; }); }
        if (st.filters.levels[n]) delete st.filters.levels[n]; else st.filters.levels[n] = 1;
        var all = true; ph.elLevelInfo().forEach(function(li) { if (!st.filters.levels[li.n]) all = false; });
        if (all) st.filters.levels = null;
        ph.elUpdate();
        return false;
    };
    obj.elToggleFacet = function(kind, name) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        var counts = ph.elFiltered().counts;
        var universe = Object.keys(kind == 'logs' ? counts.log : counts.source);
        if (st.filters[kind] == null) { st.filters[kind] = {}; universe.forEach(function(n) { st.filters[kind][n] = 1; }); }
        if (st.filters[kind][name]) delete st.filters[kind][name]; else st.filters[kind][name] = 1;
        var all = true; universe.forEach(function(n) { if (!st.filters[kind][n]) all = false; });
        if (all) st.filters[kind] = null;
        ph.elUpdate();
        return false;
    };
    obj.elFacetsMore = function() {
        var ph = pluginHandler.eventlog, st = ph.elState();
        st.srcMore = !st.srcMore; ph.elUpdate();
        return false;
    };
    obj.elIdInput = function(el) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        st.filters.ids = el.value;
        if (st._deb) clearTimeout(st._deb);
        st._deb = setTimeout(function() { pluginHandler.eventlog.elUpdate(); }, 200);
        return false;
    };
    obj.elTextInput = function(el) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        st.filters.text = el.value;
        if (st._deb) clearTimeout(st._deb);
        st._deb = setTimeout(function() { pluginHandler.eventlog.elUpdate(); }, 200);
        return false;
    };
    obj.elClearFilter = function(kind) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        if (kind == 'ids' || kind == 'text') { st.filters[kind] = ''; var el = Q(kind == 'ids' ? 'evlIdIn' : 'evlTxtIn'); if (el) el.value = ''; }
        else st.filters[kind] = null;
        ph.elUpdate();
        return false;
    };
    obj.elResetFilters = function() {
        var ph = pluginHandler.eventlog, st = ph.elState();
        st.filters = { levels: null, logs: null, sources: null, ids: '', text: '' };
        var e1 = Q('evlIdIn'); if (e1) e1.value = '';
        var e2 = Q('evlTxtIn'); if (e2) e2.value = '';
        ph.elUpdate();
        return false;
    };
    obj.elSetRows = function(v) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        st.rows = v; putstore('evl_rows', v);
        ph.elUpdate();
        return false;
    };

    // ---- column widths / heights ----
    // Default column widths: measured from the real fonts (level names and the locale's time format vary), cached.
    obj.elColDefault = function(key) {
        var ph = pluginHandler.eventlog;
        var fixed = { level: 110, time: 175, log: 110, source: 230, id: 80 };
        if (!ph._autoW) {
            var host = Q('pluginEventLog'); if (!host) return fixed[key];
            var m = document.createElement('div'); m.style.cssText = 'position:absolute;visibility:hidden;white-space:nowrap;left:-9999px;top:0;';
            host.appendChild(m);
            var meas = function(html) { m.innerHTML = html; return m.firstChild ? m.firstChild.getBoundingClientRect().width : 0; };
            var lv = 0; ph.elLevelInfo().forEach(function(li) { lv = Math.max(lv, meas('<span class="evlLv ' + li.cls + '"><i></i>' + li.name + '</span>')); });
            var tm = meas('<span class=evlMono>' + ph.elFmtTime(new Date(2026, 11, 28, 22, 58, 58).getTime()) + '</span>');
            var id = meas('<span class=evlMono>88888</span>');
            host.removeChild(m);
            if (!(lv > 0 && tm > 0)) return fixed[key];   // tab not visible yet: use the fallbacks, measure again next render
            ph._autoW = { level: Math.ceil(lv) + 20, time: Math.ceil(tm) + 20, id: Math.max(fixed.id, Math.ceil(id) + 20) };
        }
        return ph._autoW[key] || fixed[key];
    };
    obj.elColW = function(key) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        if (key == 'message') return 0;
        var u = st.cols[st.layout] && st.cols[st.layout][key];
        return (u > 0) ? u : ph.elColDefault(key);
    };
    obj.elSaveCols = function() {
        var st = pluginHandler.eventlog.elState();
        putstore('evl_cols_' + st.layout, JSON.stringify(st.cols[st.layout] || {}));
    };
    obj.elSetColW = function(key, w) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        if (!st.cols[st.layout]) st.cols[st.layout] = {};
        st.cols[st.layout][key] = w;
        ph.elSaveCols();
    };
    obj.elRzDown = function(ev, key) {
        var ph = pluginHandler.eventlog;
        var hd = ev.currentTarget || ev.target, th = hd.parentNode, sc = th.closest('.evlScroll, .evlVList');
        if (!th || !sc) return false;
        ev.preventDefault(); ev.stopPropagation();
        try { hd.setPointerCapture(ev.pointerId); } catch (e) { }
        hd.classList.add('active'); sc.classList.add('evlResizing');
        var guide = document.createElement('div'); guide.className = 'evlGuide'; guide.innerHTML = '<span></span>'; sc.appendChild(guide);
        var x0 = ev.clientX, w0 = th.getBoundingClientRect().width, w = 0;
        var mv = function(e) {
            w = Math.max(40, Math.round(w0 + e.clientX - x0));
            th.style.width = w + 'px';
            var r = sc.getBoundingClientRect(), t = th.getBoundingClientRect();
            guide.style.left = (t.right - r.left + sc.scrollLeft) + 'px'; guide.style.top = sc.scrollTop + 'px'; guide.style.height = sc.clientHeight + 'px';
            guide.firstChild.textContent = w + ' px';
        };
        var up = function() {
            hd.removeEventListener('pointermove', mv); hd.removeEventListener('pointerup', up); hd.removeEventListener('pointercancel', up);
            hd.classList.remove('active'); sc.classList.remove('evlResizing');
            if (guide.parentNode) guide.parentNode.removeChild(guide);
            ph._rzUntil = Date.now() + 400;   // swallow the click that follows the drag (would sort the column)
            if (w) { ph.elSetColW(key, w); ph.elRenderStatus(); }
        };
        hd.addEventListener('pointermove', mv); hd.addEventListener('pointerup', up); hd.addEventListener('pointercancel', up);
        return false;
    };
    // double-click on a handle: fit the column to its widest cell (capped at 60% of the table)
    obj.elRzFit = function(ev, key) {
        var ph = pluginHandler.eventlog;
        var hd = ev.currentTarget || ev.target, th = hd.parentNode, sc = th.closest('.evlScroll, .evlVList'), tbl = th.closest('table');
        ev.preventDefault(); ev.stopPropagation();
        if (!th || !sc || !tbl) return false;
        var idx = th.cellIndex, w = th.scrollWidth + 2;
        var rows = tbl.tBodies[0] ? tbl.tBodies[0].rows : [];
        for (var i = 0; i < rows.length; i++) { if (rows[i].className.indexOf('evlExpand') >= 0) continue; var c = rows[i].cells[idx]; if (c) w = Math.max(w, c.scrollWidth + 2); }
        w = Math.max(40, Math.min(w, Math.round(sc.clientWidth * 0.6)));
        th.style.width = w + 'px';
        ph._rzUntil = Date.now() + 400;
        ph.elSetColW(key, w); ph.elRenderStatus();
        return false;
    };
    obj.elGripDown = function(ev, targetId) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        var g = ev.currentTarget || ev.target, t = Q(targetId);
        if (!t) return false;
        ev.preventDefault();
        try { g.setPointerCapture(ev.pointerId); } catch (e) { }
        g.classList.add('active');
        var y0 = ev.clientY, h0 = t.getBoundingClientRect().height, hh = 0, cap = ph.elFitAvail() || 1e6;
        var mv = function(e) { hh = Math.min(cap, Math.max(90, Math.round(h0 + e.clientY - y0))); t.style.height = hh + 'px'; t.style.maxHeight = 'none'; t.style.minHeight = '0'; };
        var up = function() {
            g.removeEventListener('pointermove', mv); g.removeEventListener('pointerup', up); g.removeEventListener('pointercancel', up);
            g.classList.remove('active');
            if (hh) { st.heights[st.layout] = hh; putstore('evl_h_' + st.layout, String(hh)); ph.elRenderStatus(); }
        };
        g.addEventListener('pointermove', mv); g.addEventListener('pointerup', up); g.addEventListener('pointercancel', up);
        return false;
    };
    // Height (px) the table can take so that everything below it (details, status line) still fits in the
    // window. 0 = unknown (tab hidden).
    obj.elFitAvail = function() {
        var ph = pluginHandler.eventlog, st = ph.elState();
        var t = Q(st.layout == 'viewer' ? 'evlVList' : 'evlScroll'), wrap = Q('evlWrap');
        if (!t || !wrap || !t.offsetParent) return 0;
        var r = t.getBoundingClientRect(), top = r.top, bottom = window.innerHeight, sc = null;
        for (var p = wrap.parentNode; p && p.nodeType == 1 && p != document.body && p != document.documentElement; p = p.parentNode) {
            var oy = getComputedStyle(p).overflowY;
            if (oy == 'auto' || oy == 'scroll') { sc = p; break; }
        }
        // measure from where the table sits when the page is scrolled to the top
        if (sc) { top += sc.scrollTop; bottom = Math.min(bottom, sc.getBoundingClientRect().bottom); }
        else top += (window.pageYOffset || 0);
        var below = wrap.getBoundingClientRect().bottom - r.bottom;
        return Math.max(90, Math.floor(bottom - top - below - 6));
    };
    // Automatic height fills the window; a user-dragged height is kept but never grows past it.
    obj.elFitHeight = function() {
        var ph = pluginHandler.eventlog, st = ph.elState();
        var t = Q(st.layout == 'viewer' ? 'evlVList' : 'evlScroll'), avail = ph.elFitAvail();
        if (!t || !avail) return;
        var uh = st.heights[st.layout];
        if (uh) { t.style.height = Math.min(uh, avail) + 'px'; t.style.maxHeight = 'none'; t.style.minHeight = '0'; }
        else { t.style.height = ''; t.style.maxHeight = avail + 'px'; t.style.minHeight = (st.layout == 'ledger') ? Math.min(160, avail) + 'px' : ''; }
    };
    obj.elGripReset = function() {
        var ph = pluginHandler.eventlog, st = ph.elState();
        st.heights[st.layout] = 0; putstore('evl_h_' + st.layout, '0');
        ph.elUpdate();
        return false;
    };
    obj.elResetSizes = function() {
        var ph = pluginHandler.eventlog, st = ph.elState();
        st.cols[st.layout] = {}; putstore('evl_cols_' + st.layout, '');
        st.heights[st.layout] = 0; putstore('evl_h_' + st.layout, '0');
        if (st.layout == 'viewer') { st.sideW = 0; putstore('evl_side', '0'); }
        ph.elUpdate();
        return false;
    };
    obj.elVSplitDown = function(ev) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        var g = ev.currentTarget || ev.target, v = Q('evlViewer'), side = Q('evlFacets');
        if (!v || !side) return false;
        ev.preventDefault();
        try { g.setPointerCapture(ev.pointerId); } catch (e) { }
        g.classList.add('active');
        var x0 = ev.clientX, w0 = side.getBoundingClientRect().width, ww = 0, max = Math.max(160, Math.round(v.getBoundingClientRect().width * 0.5));
        var mv = function(e) { ww = Math.min(max, Math.max(120, Math.round(w0 + e.clientX - x0))); v.style.setProperty('--evl-side', ww + 'px'); };
        var up = function() {
            g.removeEventListener('pointermove', mv); g.removeEventListener('pointerup', up); g.removeEventListener('pointercancel', up);
            g.classList.remove('active');
            if (ww) { st.sideW = ww; putstore('evl_side', String(ww)); ph.elRenderStatus(); }
        };
        g.addEventListener('pointermove', mv); g.addEventListener('pointerup', up); g.addEventListener('pointercancel', up);
        return false;
    };
    obj.elVSplitReset = function() {
        var ph = pluginHandler.eventlog, st = ph.elState();
        st.sideW = 0; putstore('evl_side', '0');
        ph.elUpdate();
        return false;
    };

    obj.elSetSort = function(k) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        if (ph._rzUntil && Date.now() < ph._rzUntil) return false;   // click right after a resize drag
        if (st.sort.key == k) st.sort.dir = -st.sort.dir;
        else { st.sort.key = k; st.sort.dir = (k == 'time') ? -1 : 1; }
        ph.elUpdate();
        return false;
    };
    obj.elRowClick = function(key) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        if (st.layout == 'viewer') { st.selected = key; }
        else { st.expanded[key] = !st.expanded[key]; }
        ph.elUpdate();
        return false;
    };
    obj.elSetDTab = function(t) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        st.dtab = t; ph.elUpdate();
        return false;
    };
    // the (possibly folded) row currently displayed for an event key
    obj.elRowFor = function(key) {
        var ph = pluginHandler.eventlog, st = ph.elState(), ev = ph.byKey[key];
        if (!ev) return null;
        if (st.fold) { var rows = ph.elFold(ph.elFiltered().rows); for (var i = 0; i < rows.length; i++) { if (rows[i].ev.key == key) return rows[i]; } }
        return { ev: ev, count: 1, times: [ev.time] };
    };
    // plain-text rendition of an event, in the layout of Windows Event Viewer's "Copy Details as Text"
    obj.elDetailsText = function(key) {
        var ph = pluginHandler.eventlog, r = ph.elRowFor(key);
        if (!r) return '';
        var ev = r.ev, st = ph.elState(), lx = (st.os == 'linux'), pad = function(l) { return (l + '              ').substring(0, 15); };
        var t = pad((lx ? 'Category:' : 'Log Name:')) + ev.log + '\n' + pad('Source:') + ev.source + '\n' + pad('Date:') + ph.elFmtTime(ev.time) + '\n' +
                pad((lx ? 'PID:' : 'Event ID:')) + ev.id + '\n' + pad('Level:') + ev.levelName + ' (' + ev.level + ')' + '\n';
        if (ev.unit) t += pad('Unit:') + ev.unit + '\n';
        if (ev.pri != null) t += pad('Priority:') + ph.elPriName(ev.pri) + ' (' + ev.pri + ')' + '\n';
        if (r.count > 1) t += pad('Occurrences:') + r.count + ' (' + r.times.slice(0, 12).map(function(x) { return ph.elFmtTime(x); }).join(', ') + (r.times.length > 12 ? ', ...' : '') + ')\n';
        t += 'Description:\n' + ev.message;
        return t;
    };
    // what = 'details' (default) | 'json' | 'message'; btn (optional) flashes "Copied" for a moment
    obj.elCopy = function(key, what, btn) {
        var ph = pluginHandler.eventlog, ev = ph.byKey[key];
        if (!ev) return false;
        var txt;
        if (what == 'json') txt = JSON.stringify(ph.elRawOf(ev), null, 2);
        else if (what == 'message') txt = ev.message;
        else txt = ph.elDetailsText(key);
        var fallback = function() {
            var ta = document.createElement('textarea'); ta.value = txt; ta.style.cssText = 'position:fixed;left:-9999px;top:0'; document.body.appendChild(ta); ta.select();
            try { document.execCommand('copy'); } catch (e2) { }
            document.body.removeChild(ta);
        };
        try { if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(txt).catch(fallback); else fallback(); } catch (e) { fallback(); }
        if (btn && btn.tagName) {
            var old = btn.innerHTML; btn.innerHTML = 'Copied &#10003;'; btn.classList.add('ok');
            setTimeout(function() { try { btn.innerHTML = old; btn.classList.remove('ok'); } catch (e) { } }, 1200);
        }
        return false;
    };
    obj.elToggleRaw = function(key) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        st.raw[key] = !st.raw[key]; ph.elUpdate();
        return false;
    };
    obj.elFilterBy = function(what, key) {
        var ph = pluginHandler.eventlog, st = ph.elState(), ev = ph.byKey[key];
        if (!ev) return false;
        if (what == 'source') { st.filters.sources = {}; st.filters.sources[ev.source] = 1; }
        if (what == 'id') { st.filters.ids = String(ev.id); var el = Q('evlIdIn'); if (el) el.value = st.filters.ids; }
        ph.elUpdate();
        return false;
    };
    obj.elKeyNav = function(ev) {
        if (ev.key != 'ArrowDown' && ev.key != 'ArrowUp') return true;
        var ph = pluginHandler.eventlog, st = ph.elState();
        var fr = ph.elFiltered();
        var frows = st.fold ? ph.elFold(fr.rows) : fr.rows.map(function(e) { return { ev: e }; });
        var idx = -1;
        frows.forEach(function(r, i) { if (r.ev.key == st.selected) idx = i; });
        idx += (ev.key == 'ArrowDown') ? 1 : -1;
        if (idx < 0) idx = 0; if (idx >= frows.length) idx = frows.length - 1;
        if (frows[idx]) { st.selected = frows[idx].ev.key; ph.elUpdate(); var l = Q('evlVList'); if (l) l.focus(); }
        ev.preventDefault();
        return false;
    };

    obj.elExportCsv = function() {
        var ph = pluginHandler.eventlog, st = ph.elState();
        var fr = ph.elFiltered();
        var q = function(v) { return '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"'; };
        var lx = (st.os == 'linux');
        var lines = ['Level,Time,' + (lx ? 'Category' : 'Log') + ',Source,' + (lx ? 'PID' : 'EventId') + ',Message'];
        fr.rows.forEach(function(ev) {
            lines.push([q(ev.levelName), q(new Date(ev.time).toISOString()), q(ev.log), q(ev.source), q(ev.id), q(ev.message)].join(','));
        });
        var name = 'eventlog-' + ((typeof currentNode != 'undefined' && currentNode) ? String(currentNode.name).replace(/[^\w.-]+/g, '_') : 'device') + '-live.csv';
        try {
            var blob = new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
            var a = document.createElement('a');
            a.href = URL.createObjectURL(blob); a.download = name;
            document.body.appendChild(a); a.click();
            setTimeout(function() { URL.revokeObjectURL(a.href); document.body.removeChild(a); }, 1000);
        } catch (e) { }
        return false;
    };

    // ---- live data ----
    obj.elRequestLive = function(since) {
        var ph = pluginHandler.eventlog, st = ph.elState();
        try {
            if (ph.livelog != null && ph.livelog.State == 3) {
                // when folding repeats, fetch a larger batch so that N distinct rows can be shown
                var cmd = { action: 'plugin', plugin: 'eventlog', pluginaction: 'getlivelogs', num: st.fold ? Math.min(1000, st.show * 4) : st.show };
                if (since != null) cmd.since = since;
                if (st.os == 'linux' && st.lsel) cmd.lsel = st.lsel;
                ph.livelog.sendText(cmd);
            }
        } catch (e) { }
        return false;
    };
    obj.elAutoTick = function() {
        var ph = pluginHandler.eventlog, st = ph.elState();
        // The tab can be left without another gotoDevice() (back button, plugin tab switch), so the
        // timer is also where an orphaned tunnel gets cleaned up.
        if (!ph.elTabVisible()) { ph.elStopLive(); return; }
        if ((typeof document != 'undefined') && (document.hidden === true)) return; // browser tab in the background
        ph.elRequestAccess();   // permissions can change while the tab is open (also stops Live when it is revoked)
        if (!ph.elCan('live')) return;
        if (st.paused) return;
        var newest = 0;
        st.live.events.forEach(function(ev) { if (ev.time > newest) newest = ev.time; });
        ph.elRequestLive(newest ? Math.floor(newest / 1000) : null);
    };
    obj.elRefresh = function() {
        var ph = pluginHandler.eventlog, st = ph.elState();
        ph.elRequestLive(null);
        return false;
    };
    obj.elTogglePause = function() {
        var ph = pluginHandler.eventlog, st = ph.elState();
        st.paused = !st.paused;
        if (!st.paused && st.pending.length) {
            st.pending.forEach(function(ev) { st.live.events.push(ev); });
            st.pending = [];
        }
        var b = Q('evlPauseBtn');
        if (b) { b.innerHTML = st.paused ? '&#9654;' : '&#10074;&#10074;'; b.title = st.paused ? 'Resume live updates' : 'Pause live updates'; }
        ph.elUpdate();
        return false;
    };

    // ---- plumbing (tunnel to the agent) ----

    // called when a new plugin message is received on the front end
    obj.fe_on_message = function(server, message) {
      var ph = pluginHandler.eventlog;
      var data = JSON.parse(message);
      if (data.type == 'close') {
        if (ph.livelog) { ph.livelog.Stop(); ph.livelog = null; }
        return;
      }
      if (!ph.elEnsureShell()) return;
      var st = ph.elState();
      if (data.caps) st.meta = { os: data.os || st.os, caps: data.caps };
      if (data.cfg) st.cfg = data.cfg;   // the config set the agent holds (live category / source rules)
      var evs = data.data;
      if (evs == null) return;
      if (!Array.isArray(evs)) evs = [evs];
      var tgt = st.paused ? st.pending : st.live.events;
      var added = false;
      for (var i in evs) {
          var n = ph.elNormalize(evs[i]);
          if (n == null || n.log == '' && n.source == '') continue;
          if (!ph.elLiveAllowed(n)) continue;   // config set's Live include/exclude rules
          if (ph.byKey[n.key]) {
              // already known: skip if it is already in the live buffer
              var known = false;
              st.live.events.forEach(function(e) { if (e.key == n.key) known = true; });
              st.pending.forEach(function(e) { if (e.key == n.key) known = true; });
              if (known) continue;
          }
          ph.byKey[n.key] = n;
          tgt.push(n); added = true;
      }
      // cap the live buffer
      if (st.live.events.length > 2000) {
          st.live.events.sort(function(a, b) { return b.time - a.time; });
          st.live.events.length = 2000;
      }
      st.live.last = new Date();
      if (st.paused && added) ph.elRenderStatus(); else ph.elUpdate();
    };

    obj.onRemoteEventLogStateChange = function(xdata, state) {
        var ph = pluginHandler.eventlog;
        switch (state) {
            case 0:
                ph.elStopLive();
                ph.elRenderStatus();
                break;
            case 3:
                if (!ph.elTabVisible()) { ph.elStopLive(); return; }   // tab was left while the tunnel was still connecting
                ph.elEnsureShell();
                ph.elRequestLive(null);
                if (ph.autoTimer != null) { clearInterval(ph.autoTimer); }
                ph.autoTimer = setInterval(function() { try { pluginHandler.eventlog.elAutoTick(); } catch (e) { } }, 30000);
                break;
            default:
            break;
        }
    }

    obj.createRemoteEventLog = function(onEventLogUpdate) {
        var myobj = { protocol: 7 }; // we're a plugin
        myobj.onEventLogUpdate = onEventLogUpdate;
        myobj.xxStateChange = function(state) { }
        myobj.ProcessData = function(data) { onEventLogUpdate(null, data); }
        return myobj;
    }

    // True only when the Event Log tab is the plugin tab the user is actually looking at.
    // The live tunnel keeps an agent relay open and makes the endpoint run a collector every 30 s
    // (a PowerShell process on Windows), so it must not exist while the user is on the Desktop /
    // Terminal / Files tab or on another plugin's tab.
    obj.elTabVisible = function() {
        try {
            if ((typeof xxcurrentView != 'undefined') && (xxcurrentView != 19)) return false;   // 19 = the device Plugins panel
            var p = Q('p19');
            if ((p != null) && (p.style.display == 'none')) return false;
            var tab = Q('p19ph-pluginEventLog');
            if (tab == null) return false;
            if (tab.classList != null) return tab.classList.contains('on');
            return ((' ' + tab.className + ' ').indexOf(' on ') !== -1);
        } catch (e) { return false; }
    };

    obj.elStopLive = function() {
        var ph = pluginHandler.eventlog;
        if (ph.autoTimer != null) { clearInterval(ph.autoTimer); ph.autoTimer = null; }
        // clear the reference first: Stop() fires onStateChanged(0), which would otherwise stop it again
        var l = ph.livelog; ph.livelog = null;
        if (l != null) { try { l.Stop(); } catch (e) { } }
    };

    // Bring the tunnel in line with what is on screen. Safe to call repeatedly.
    obj.elEnsureLive = function() {
        var ph = pluginHandler.eventlog;
        if (!ph.elTabVisible()) { ph.elStopLive(); return; }
        if ((typeof currentNode == 'undefined') || (currentNode == null) || !ph.elIsSupported()) return;
        if (!ph.elEnsureShell()) return;
        if (!ph.elCan('live')) { ph.elStopLive(); return; }   // no permission for the Live tab: never open the tunnel
        ph.livelognode = currentNode;
        if (!ph.livelognode.conn) { ph.elStopLive(); ph.elRenderStatus(); return; }   // agent offline
        if (ph.livelog == null) {
            ph.livelog = CreateAgentRedirect(meshserver, ph.createRemoteEventLog(ph.fe_on_message), serverPublicNamePort, authCookie, authRelayCookie, domainUrl);
            ph.livelog.attemptWebRTC = attemptWebRTC;
            ph.livelog.onStateChanged = ph.onRemoteEventLogStateChange;
            ph.livelog.onConsoleMessageChange = function () {
                if (pluginHandler.eventlog.livelog && pluginHandler.eventlog.livelog.consoleMessage) {
                    console.log('console message available. ', pluginHandler.eventlog.livelog.consoleMessage)
                }
            }
            ph.livelog.Start(ph.livelognode._id);
        }
    };

    // Switching between plugin tabs does not go through gotoDevice(), so hook the switcher once.
    obj.elHookTabSwitch = function() {
        var ph = pluginHandler.eventlog;
        if (ph._cppWrapped === true) return;
        if ((typeof pluginHandler == 'undefined') || (typeof pluginHandler.callPluginPage != 'function')) return;
        ph._cppWrapped = true;
        var orig = pluginHandler.callPluginPage;
        pluginHandler.callPluginPage = function(id, el) {
            var r = orig.apply(this, arguments);
            try { setTimeout(function() { pluginHandler.eventlog.elEnsureLive(); }, 0); } catch (e) { }
            return r;
        };
    };

    // MeshCentral calls this hook at the top of go(), its panel switcher. The device Plugins panel
    // is opened with go(19) from the tab bar, which fires neither onDeviceRefreshEnd nor
    // callPluginPage - so without this, selecting the Event Log tab from another device tab would
    // never start the live view. It also stops the tunnel promptly when the user navigates away.
    obj.goPageStart = function(x, event) {
        // the panel has not been switched yet at this point, so decide once the stack unwinds
        setTimeout(function() { try { pluginHandler.eventlog.elEnsureLive(); } catch (e) { } }, 0);
    };

    obj.onDeviceRefreshEnd = function(nodeid, panel, refresh, event) {
      var ph = pluginHandler.eventlog;
      pluginHandler.registerPluginTab(ph.registerPluginTab());
      ph.elHookTabSwitch();
      if (typeof ph.livelog == 'undefined') { ph.livelog = null; }
      if (typeof ph.livelognode == 'undefined') { ph.livelognode = null; }
      var isSupported = ph.elIsSupported();   // Windows and Linux endpoints
      var sameNode = isSupported && (ph.livelognode != null) && (ph.livelognode._id == currentNode._id);
      // MeshCentral calls this hook on every gotoDevice() -- tab switches, node updates, connection state changes.
      // Only tear down the UI state when the node actually changed; otherwise keep the live connection
      // (stopping a still-connecting websocket logs an error) and keep the user's filters/data.
      if (!sameNode) {
          ph.elStopLive();
          ph.livelognode = null;
          ph.st = null;      // reset UI state for the new node
          ph.byKey = {};
      }
      if (!isSupported) { ph.elStopLive(); return; }
      ph.livelognode = currentNode;
      ph.elRequestAccess();   // every refresh (at most once per 5 s per device): a grant or a revoke takes effect without a page reload
      // the plugin tab DOM is rebuilt by MeshCentral on every refresh: re-create the shell (renders from state)
      ph.elEnsureShell();
      // MeshCentral restores the previously selected plugin tab right AFTER this hook returns, so the
      // "is our tab on screen?" decision has to wait for the current call stack to finish.
      setTimeout(function() { pluginHandler.eventlog.elEnsureLive(); }, 0);
    };

    // ------------------------------------------------------------------
    //  Server side
    // ------------------------------------------------------------------

    obj.hook_agentCoreIsStable = function(myparent, grandparent) {
        if (grandparent == null) { // detect old style call with single argument, backward compat, to be removed in the future.
            grandparent = myparent[1];
            myparent = myparent[0];
        }
        myparent.send(JSON.stringify({
            action: 'plugin',
            pluginaction: 'serviceCheck',
            plugin: 'eventlog',
            nodeid: myparent.dbNodeKey,
            rights: true,
            sessionid: true
        }));
        obj.db.getConfigFor(myparent.dbNodeKey, myparent.dbMeshKey)
        .then((cfgBlob) => {
            myparent.send(JSON.stringify({
                action: 'plugin',
                pluginaction: 'setConfigBlob',
                plugin: 'eventlog',
                nodeid: myparent.dbNodeKey,
                rights: true,
                sessionid: true,
                cfg: cfgBlob
            }));
        })
        .catch((e) => console.log('EVENTLOG: could not send the config to ' + myparent.dbNodeKey + ': ' + (e.message || e)));
    };

    // True when the session belongs to a MeshCentral administrator (same test as the admin page itself, admin.js)
    obj.isPluginAdmin = function(myparent) {
        try { return (myparent != null && myparent.user != null && (myparent.user.siteadmin & 0xFFFFFFFF) != 0); } catch (e) { return false; }
    };

    // data was sent to server from the client. do something with it.
    // Entry point for plugin messages. User-initiated actions are checked against the plugin permissions first;
    // agent traffic (no user) and the admin actions (own check, isPluginAdmin) pass straight through.
    obj.serveraction = function(command, myparent, grandparent) {
        if (myparent == null || myparent.user == null) return obj._serveraction(command, myparent, grandparent);
        if (command.pluginaction == 'checkAccess') { obj.sendAccess(myparent, command, grandparent); return; }
        var perm = obj.ACTION_PERMISSION[command.pluginaction];
        if (perm == null) return obj._serveraction(command, myparent, grandparent);
        obj.canUse(myparent.user, perm, { nodeid: command.nodeid, meshid: command.meshid }).then(function (ok) {
            if (ok) { try { obj._serveraction(command, myparent, grandparent); } catch (e) { console.log('PLUGIN: eventlog: serveraction error: ', e); } return; }
            obj.sendAccess(myparent, command, grandparent);   // refused: the tab learns it has no access
        });
    };
    obj._serveraction = function(command, myparent, grandparent) {
      var myobj = {};
      myobj.parent = myparent;

      if (command.uid) { // check to see if config is valid/current, if not, send update
        // This runs for every agent message carrying a uid (once per node per minute). On a SQL
        // backend these promises reject while the database is unreachable, and an unhandled
        // rejection terminates the MeshCentral process - so every path here is caught.
        obj.db.checkConfigAuth(command.uid)
        .then((cnt) => {
          if (cnt != 0) return null;
          return obj.db.getConfigFor(myparent.dbNodeKey, myparent.dbMeshKey)
          .then((cfgBlob) => {
            myparent.send(JSON.stringify({
                action: 'plugin',
                pluginaction: 'setConfigBlob',
                plugin: 'eventlog',
                nodeid: myparent.dbNodeKey,
                rights: true,
                sessionid: true,
                cfg: cfgBlob
            }));
          });
        })
        .catch((e) => console.log('EVENTLOG: could not refresh the endpoint config: ' + (e.message || e)));
      }

      switch (command.pluginaction) {
        case 'sendlog': {
          command.method = 'fe_on_message';
          if (command.sessionid != null) {
              if (typeof command.sessionid != 'string') break;
              var splitsessionid = command.sessionid.split('/');
              // Check that we are in the same domain and the user has rights over this node.
              if ((splitsessionid[0] == 'user') && (splitsessionid[1] == myobj.parent.domain.id)) {
                  // See if the session is connected. If so, go ahead and send this message to the target node
                  var ws = grandparent.wssessions2[command.sessionid];
                  if (ws != null) {
                      command.nodeid = parent.dbNodeKey; // Set the nodeid, required for responses.
                      delete command.sessionid;       // Remove the sessionid, since we are sending to that sessionid, so it's implyed.
                      try { ws.send(JSON.stringify(command)); } catch (ex) { }
                  }
              }
          }
          break;
        }
        case 'adminSaveConfig': {
            // Every outcome is reported back to the admin page, so it can show whether the save worked.
            var sendAdmin = function(o) { try { o.action = 'plugin'; o.plugin = 'eventlog'; myobj.parent.ws.send(JSON.stringify(o)); } catch (e) { } };
            if (!obj.isPluginAdmin(myparent)) { sendAdmin({ method: 'adminSaveFailed', error: 'Administrator rights are required to change the configuration.' }); break; }
            var opts = {...command.opts, ...{}};
            var isDefault = (command.id == '_default');
            var saved = isDefault
                ? obj.db.updateDefaultConfig(opts).then(function () { return ''; })
                : obj.db.updateConfig(command.id, opts).then(function (d) { return (d != null && d.insertedId) || command.id; });
            saved
            .then(function (savedId) {
                return obj.db.getAllConfigSets().then(function (sets) {
                    sendAdmin({ method: 'adminUpdateConfigSets', sets: sets, selected: savedId, saved: true, defaultSet: isDefault, name: opts.name });
                });
            })
            .catch(function (e) {
                console.log('EVENTLOG: Something went wrong saving the config: ' + ((e && e.message) || e));
                sendAdmin({ method: 'adminSaveFailed', error: String((e && e.message) || e).substring(0, 200) });
            });
            break;
        }
        case 'adminDeleteConfig': {
            if (!obj.isPluginAdmin(myparent)) break;
            obj.db.deleteConfigSet(command.id)
            .then((d) => {
              var x = { action: "plugin", plugin: "eventlog", method: "adminConfigDeleted", id: command.id };
              myobj.parent.ws.send(JSON.stringify(x));
            })
            .catch((e) => console.log('EVENTLOG: Something went wrong deleting the config'));
            break;
        }
        case 'adminAssignConfig': { // configId, nodes, meshes
            if (!obj.isPluginAdmin(myparent)) break;
            obj.db.assignConfig(command.configId, command.selection)
            .then(obj.db.getConfigAssignments)
            .then((d) => {
              var configAssignments = [];
              d.forEach((s) => {
                configAssignments.push({ asset: s.asset, configId: s.configId });
              });
              var x = { action: "plugin", plugin: "eventlog", method: "setsAssigned", data: configAssignments};
              myobj.parent.ws.send(JSON.stringify(x));
            })
            .catch((e) => console.log('EVENTLOG: Something went wrong assigning the config: ', e));
            break;
        }
        default: {
          break;
        }
      }
    }

    return obj;
};